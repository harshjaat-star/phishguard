#!/usr/bin/env python3
"""
PhishGuard — analyze URLs and email bodies for phishing indicators.

By default PhishGuard performs ONLY static analysis — it never opens a
connection to the target. Network-based redirect-chain analysis is
strictly opt-in via --allow-network, and even then PhishGuard refuses
to follow redirects to private IPs (SSRF protection).

    python3 phishguard.py https://suspicious.example.com
    python3 phishguard.py --email suspicious.eml
    python3 phishguard.py --file urls.txt
    python3 phishguard.py --json https://x.example.com
    python3 phishguard.py --demo

PhishGuard is a *defensive* tool. It helps you and your users spot
phishing. It does not attack, crawl, or brute-force anything.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import unicodedata
import urllib.parse
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Data tables
# ---------------------------------------------------------------------------

# Popular brands used for typosquatting detection. Keep names lowercase.
POPULAR_BRANDS = [
    # Tech
    "google", "gmail", "youtube", "android", "chrome",
    "apple", "icloud", "itunes", "macbook",
    "microsoft", "outlook", "hotmail", "office365", "onedrive", "azure",
    "amazon", "aws", "twitch",
    "facebook", "instagram", "whatsapp", "messenger",
    "twitter", "linkedin", "github", "gitlab", "dropbox", "adobe",
    "netflix", "spotify", "discord", "telegram", "snapchat", "tiktok",
    "steam", "epicgames", "playstation", "nintendo", "xbox",
    # Finance
    "paypal", "ebay", "stripe", "venmo", "cashapp", "wise", "revolut",
    "coinbase", "binance", "metamask", "trustwallet", "phantom",
    "chase", "wellsfargo", "citibank", "bankofamerica", "hsbc",
    "barclays", "santander", "sbi", "hdfc", "icici", "axis",
    # Common services
    "zoom", "slack", "notion", "figma", "airbnb", "uber", "doordash",
    "wikipedia", "reddit", "quora", "yahoo",
]

# Homoglyphs: visually-similar characters from other scripts that are
# commonly used to spoof Latin domain names. We map them back to Latin.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "г": "r", "п": "n",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k",
    "υ": "u", "χ": "x", "ε": "e", "τ": "t", "η": "n", "ς": "c",
    # Armenian / misc
    "օ": "o", "ս": "u", "ց": "g", "հ": "h",
}

# TLDs frequently abused in phishing campaigns. Not exhaustive — a live
# feed from Spamhaus or similar would be better, but this catches the
# obvious cases without needing network access.
SUSPICIOUS_TLDS = {
    # Freenom free TLDs — heavily abused
    "tk", "ml", "ga", "cf", "gq",
    # Cheap / high-abuse gTLDs
    "xyz", "top", "work", "click", "link", "download", "stream",
    "review", "win", "bid", "loan", "party", "racing", "science",
    "gdn", "icu", "cam", "rest", "monster", "quest", "cyou", "buzz",
    "online", "site", "website", "space", "fun", "live", "life",
    "world", "kim", "country", "zip", "mov", "cricket", "date",
    "faith", "men", "ren", "trade", "webcam",
}

# Keywords that often appear in phishing URLs, especially in the path
# or subdomain. A single one is a soft signal; several together are a
# strong signal.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "confirm",
    "confirmation", "account", "update", "secure", "security",
    "wallet", "recover", "recovery", "unlock", "suspended", "unusual",
    "activity", "billing", "payment", "invoice", "receipt", "refund",
    "support", "helpdesk", "auth", "authenticate", "session", "alert",
    "warning", "reset", "password", "credential", "authorize",
    "bank", "banking", "webscr", "cmd",
]

# Two-level public suffixes we care about for domain extraction. This is
# a small pragmatic subset, not the full Public Suffix List.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gov.in",
    "co.nz", "net.nz", "org.nz",
    "co.za", "com.br", "com.mx", "com.ar", "com.tr",
    "co.kr", "or.kr", "com.cn", "com.tw", "com.sg", "com.hk",
}

# Character substitution patterns (leet-speak, lookalike pairs) used by
# typosquatters. If a domain label contains one of these substitutions
# *and* the "canonical" form matches a brand, it's a strong signal.
LEET_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
}

Severity = namedtuple("Severity", "name weight")
SEV_INFO = Severity("info", 0)
SEV_LOW = Severity("low", 5)
SEV_MEDIUM = Severity("medium", 15)
SEV_HIGH = Severity("high", 30)
SEV_CRITICAL = Severity("critical", 50)

Finding = namedtuple("Finding", "severity category message evidence")


# ---------------------------------------------------------------------------
# URL parsing helpers
# ---------------------------------------------------------------------------

def parse_url(raw):
    """Parse a URL into a dict, with sensible handling of missing schemes."""
    raw = raw.strip()
    if not raw:
        return None

    # If it's clearly an email address (has @ but no scheme/slash), treat
    # the local part as a username and the rest as the URL. Common phishing.
    if "@" in raw and "://" not in raw and "/" not in raw:
        scheme = "http://"
        to_parse = scheme + raw
    elif "://" not in raw:
        to_parse = "http://" + raw
    else:
        to_parse = raw

    parsed = urllib.parse.urlparse(to_parse)
    if not parsed.netloc:
        return None

    host = parsed.hostname or ""
    host = host.rstrip(".")

    return {
        "raw": raw,
        "scheme": parsed.scheme.lower(),
        "netloc": parsed.netloc,
        "host": host,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "userinfo": parsed.username,
        "has_userinfo": parsed.username is not None,
    }


def split_domain(host):
    """Split a host into (subdomain, registrable, tld) as best we can."""
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""

    # Check for two-level public suffix
    if len(labels) >= 3:
        last_two = ".".join(labels[-2:])
        if last_two in TWO_LEVEL_SUFFIXES:
            return ".".join(labels[:-3]), labels[-3], last_two

    return ".".join(labels[:-2]), labels[-2], labels[-1]


def idna_decode(host):
    """Decode punycode labels to their Unicode form, safely."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host


def is_ip(host):
    """True if host looks like an IPv4 or IPv6 literal."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def is_private_ip(host):
    """True if host is an RFC1918 / loopback / link-local address."""
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return False
    octets = tuple(packed)
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------

def damerau_levenshtein(a, b):
    """Damerau-Levenshtein distance (handles transpositions)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la

    prev_prev = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            val = min(
                curr[j - 1] + 1,       # insertion
                prev[j] + 1,           # deletion
                prev[j - 1] + cost,    # substitution
            )
            if (prev_prev is not None and i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                val = min(val, prev_prev[j - 2] + cost)
            curr[j] = val
        prev_prev = prev
        prev = curr
    return prev[lb]


def unleet(label):
    """Convert 'app1e' -> 'apple', etc. Only single-pass substitution."""
    return "".join(LEET_MAP.get(ch, ch) for ch in label)


def closest_brand(label, max_distance=2):
    """Return (brand, distance) for the closest popular brand, or None."""
    label_l = label.lower()
    unleet_l = unleet(label_l)
    best = None
    for brand in POPULAR_BRANDS:
        for candidate in (label_l, unleet_l):
            if candidate == brand:
                return (brand, 0)  # exact match — legit
            d = damerau_levenshtein(candidate, brand)
            if d <= max_distance and (best is None or d < best[1]):
                best = (brand, d)
    return best


# ---------------------------------------------------------------------------
# Individual checks — each returns a list of Finding
# ---------------------------------------------------------------------------

def check_scheme(parsed):
    findings = []
    scheme = parsed["scheme"]
    if scheme in ("data", "javascript", "vbscript", "file"):
        findings.append(Finding(
            SEV_CRITICAL, "scheme",
            f"Dangerous URL scheme '{scheme}'",
            parsed["raw"][:80],
        ))
    elif scheme == "http" and not is_ip(parsed["host"]):
        findings.append(Finding(
            SEV_LOW, "scheme",
            "Uses plain HTTP (no TLS) — credentials could be intercepted",
            parsed["scheme"] + "://",
        ))
    return findings


def check_userinfo(parsed):
    findings = []
    if parsed["has_userinfo"]:
        findings.append(Finding(
            SEV_HIGH, "userinfo",
            "URL contains a 'user@host' trick — the real host is to the right of '@'",
            f"userinfo='{parsed['userinfo']}', real host='{parsed['host']}'",
        ))
    return findings


def check_ip_literal(parsed):
    findings = []
    host = parsed["host"]
    if is_ip(host):
        sev = SEV_HIGH if is_private_ip(host) else SEV_MEDIUM
        findings.append(Finding(
            sev, "ip-literal",
            "Host is an IP address, not a domain name",
            host,
        ))
    return findings


def check_port(parsed):
    findings = []
    port = parsed["port"]
    if port is not None and port not in (80, 443):
        findings.append(Finding(
            SEV_MEDIUM, "port",
            f"Non-standard port {port} — legitimate services usually use 80/443",
            f":{port}",
        ))
    return findings


def check_tld(parsed):
    findings = []
    _, _, tld = split_domain(parsed["host"])
    tld = tld.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            SEV_MEDIUM, "tld",
            f"TLD '.{tld}' is frequently abused in phishing",
            f".{tld}",
        ))
    return findings


def check_punycode(parsed):
    findings = []
    host = parsed["host"]
    if "xn--" in host.lower():
        decoded = idna_decode(host)
        findings.append(Finding(
            SEV_HIGH, "punycode",
            "Host uses punycode (encoded international characters) — a common spoofing trick",
            f"{host}  →  {decoded}",
        ))
    return findings


def check_homoglyphs(parsed):
    findings = []
    host_decoded = idna_decode(parsed["host"])
    homoglyph_hits = [ch for ch in host_decoded if ch in HOMOGLYPHS]
    if homoglyph_hits:
        # Build a visual demonstration: show which chars are suspicious
        rendered = ""
        for ch in host_decoded:
            if ch in HOMOGLYPHS:
                rendered += f"[{ch}→{HOMOGLYPHS[ch]}]"
            else:
                rendered += ch
        findings.append(Finding(
            SEV_CRITICAL, "homoglyph",
            f"Host contains {len(homoglyph_hits)} lookalike character(s) from a non-Latin script",
            rendered,
        ))
    return findings


def check_script_mixing(parsed):
    findings = []
    host_decoded = idna_decode(parsed["host"])
    scripts = set()
    for ch in host_decoded:
        if ch in "-._":
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if "CYRILLIC" in name:
            scripts.add("Cyrillic")
        elif "GREEK" in name:
            scripts.add("Greek")
        elif "LATIN" in name:
            scripts.add("Latin")
        elif "ARABIC" in name:
            scripts.add("Arabic")
        elif "HEBREW" in name:
            scripts.add("Hebrew")
    # Only flag when Latin is mixed with another script — pure Greek or
    # pure Cyrillic domains are perfectly legitimate.
    if "Latin" in scripts and len(scripts) > 1:
        findings.append(Finding(
            SEV_HIGH, "script-mixing",
            f"Host mixes scripts: {', '.join(sorted(scripts))} — very unusual for legitimate domains",
            host_decoded,
        ))
    return findings


def check_typosquatting(parsed):
    findings = []
    _, registrable, _ = split_domain(parsed["host"])
    if not registrable:
        return findings

    result = closest_brand(registrable)
    if result is None:
        return findings

    brand, distance = result
    if distance == 0:
        return findings  # exact match is the brand itself

    if distance == 1:
        findings.append(Finding(
            SEV_HIGH, "typosquatting",
            f"Domain label '{registrable}' is 1 edit away from '{brand}'",
            f"{registrable}  vs  {brand}",
        ))
    else:
        findings.append(Finding(
            SEV_MEDIUM, "typosquatting",
            f"Domain label '{registrable}' is {distance} edits away from '{brand}'",
            f"{registrable}  vs  {brand}",
        ))
    return findings


def check_brand_embedding(parsed):
    """Catch things like 'apple-login.tk' or 'secure-paypal.com'."""
    findings = []
    _, registrable, tld = split_domain(parsed["host"])
    if not registrable:
        return findings
    label = registrable.lower()

    # Only look for embedded brands when the label is NOT itself a brand
    if closest_brand(label, max_distance=0):
        return findings

    for brand in POPULAR_BRANDS:
        if len(brand) < 4:
            continue
        if brand in label:
            findings.append(Finding(
                SEV_HIGH, "brand-embedding",
                f"Domain label '{label}' embeds brand '{brand}' but is not the brand's own domain",
                f"{label}  contains  {brand}",
            ))
            break  # one finding per label is enough
    return findings


def check_suspicious_keywords(parsed):
    findings = []
    raw_lower = parsed["raw"].lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in raw_lower]
    if not hits:
        return findings
    # Deduplicate overlapping hits (e.g. "login" and "login" in path twice)
    unique = sorted(set(hits))
    severity = SEV_MEDIUM if len(unique) == 1 else SEV_HIGH
    findings.append(Finding(
        severity, "keywords",
        f"{len(unique)} suspicious keyword(s) in URL",
        ", ".join(unique),
    ))
    return findings


def check_subdomain_depth(parsed):
    findings = []
    subdomain, _, _ = split_domain(parsed["host"])
    if not subdomain:
        return findings
    depth = len(subdomain.split("."))
    if depth >= 4:
        findings.append(Finding(
            SEV_MEDIUM, "subdomain-depth",
            f"Very deep subdomain structure ({depth} levels) — often used to hide the real host",
            subdomain,
        ))
    elif depth == 3:
        findings.append(Finding(
            SEV_LOW, "subdomain-depth",
            f"Unusually deep subdomain structure ({depth} levels)",
            subdomain,
        ))
    return findings


def check_url_length(parsed):
    findings = []
    n = len(parsed["raw"])
    if n > 200:
        findings.append(Finding(
            SEV_HIGH, "length",
            f"Very long URL ({n} chars) — common hiding technique",
            f"{n} characters",
        ))
    elif n > 100:
        findings.append(Finding(
            SEV_LOW, "length",
            f"Long URL ({n} chars)",
            f"{n} characters",
        ))
    return findings


def check_encoding_tricks(parsed):
    findings = []
    raw = parsed["raw"]
    # Double URL-encoding: %25XX is '%' encoded again
    if re.search(r"%25[0-9A-Fa-f]{2}", raw):
        findings.append(Finding(
            SEV_HIGH, "encoding",
            "URL contains double-encoded sequences (%25XX)",
            re.search(r"%25[0-9A-Fa-f]{2}", raw).group(0),
        ))
    # Null byte injection
    if "%00" in raw.lower():
        findings.append(Finding(
            SEV_HIGH, "encoding",
            "URL contains a null byte (%00)",
            "%00",
        ))
    # Excessive percent-encoding in the host
    if "%" in parsed["host"]:
        findings.append(Finding(
            SEV_HIGH, "encoding",
            "Host itself contains percent-encoding",
            parsed["host"],
        ))
    return findings


def check_double_extension(parsed):
    findings = []
    path_lower = parsed["path"].lower()
    if re.search(r"\.(html?|php|asp|aspx|jsp)\.(exe|scr|bat|cmd|com|pif|js|vbs)$", path_lower):
        findings.append(Finding(
            SEV_CRITICAL, "double-extension",
            "Path has a double extension (e.g. '.pdf.exe') — classic malware delivery trick",
            parsed["path"],
        ))
    return findings


def check_redirect_params(parsed):
    findings = []
    query = parsed["query"].lower()
    if not query:
        return findings
    redirect_keys = ["url=", "redirect=", "redirect_uri=", "next=",
                     "return=", "return_to=", "continue=", "dest=",
                     "destination=", "target=", "r=", "u=", "goto="]
    for key in redirect_keys:
        if key in query + "&":
            findings.append(Finding(
                SEV_MEDIUM, "redirect-param",
                f"URL contains a redirect parameter '{key.rstrip('=')}' — may bounce to an attacker site",
                key.rstrip("="),
            ))
            break
    return findings


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def run_all_checks(raw_url):
    parsed = parse_url(raw_url)
    if parsed is None:
        return None, [
            Finding(SEV_MEDIUM, "parse", "Could not parse URL", raw_url[:80])
        ]

    findings = []
    checks = [
        check_scheme, check_userinfo, check_ip_literal, check_port,
        check_tld, check_punycode, check_homoglyphs, check_script_mixing,
        check_typosquatting, check_brand_embedding, check_suspicious_keywords,
        check_subdomain_depth, check_url_length, check_encoding_tricks,
        check_double_extension, check_redirect_params,
    ]
    for check in checks:
        try:
            findings.extend(check(parsed))
        except Exception as exc:  # never crash on a single bad check
            findings.append(Finding(
                SEV_INFO, "internal",
                f"Check '{check.__name__}' failed"
