# PhishGuard

**Static phishing analysis for URLs and email bodies — from the terminal, with zero dependencies.**

PhishGuard helps you spot phishing links **before** you click them. It runs entirely on the Python standard library, never contacts the target by default, and produces clear, colorized reports with a numeric risk score and a plain-English verdict.

> 🛡️ **Defensive tool.** PhishGuard is built to *protect* people from phishing, not to *create* it. It only analyzes URLs you give it, and only reaches the network when you explicitly pass `--allow-network`.

---

## What it detects

| Category | Examples |
|----------|----------|
| **Homoglyphs** | `аpple.com` with a Cyrillic `а` (visually identical to Latin `a`) |
| **Typosquatting** | `app1e.com`, `applle.com`, `gogle.com` (Damerau-Levenshtein distance 1–2 from a popular brand) |
| **Punycode spoofing** | `xn--80ak6aa92e.com` — decoded and shown in the report |
| **Brand embedding** | `apple-login.tk`, `secure-paypal.com` |
| **Userinfo trick** | `http://paypal.com@evil.example.com/` — the real host is to the right of `@` |
| **IP-literal hosts** | `http://192.168.1.1/admin` (with private-IP detection) |
| **Non-standard ports** | `http://example.com:8080/` |
| **Suspicious TLDs** | `.tk`, `.ml`, `.ga`, `.xyz`, `.top`, `.zip`, `.mov`, and ~40 more |
| **Script mixing** | Domains mixing Latin with Cyrillic or Greek |
| **Suspicious keywords** | `login`, `verify`, `secure`, `wallet`, `billing`, `recover`, … |
| **Deep subdomains** | `secure.apple.com.login.verify.evil.tk` |
| **Long URLs** | URLs over 100 or 200 characters |
| **Encoding tricks** | `%25XX` double-encoding, `%00` null bytes, `%` in host |
| **Double extensions** | `invoice.pdf.exe` |
| **Redirect parameters** | `?url=`, `?redirect=`, `?next=`, … |
| **Dangerous schemes** | `javascript:`, `data:`, `file:`, `vbscript:` |
| **Display-vs-actual mismatch** | `<a href="real">evil.example.com</a>` inside HTML emails |

---

## Quick start

```bash
# See every check in action with built-in examples
python phishguard.py --demo

# Analyze one URL
python phishguard.py "http://apple-login.tk/account/verify"

# JSON output (great for scripts and CI)
python phishguard.py --json "http://app1e.com/login"

# Analyze every URL in an email body
python phishguard.py --email suspicious.eml

# Analyze a list of URLs, one per line
python phishguard.py --file urls.txt

# Opt in to redirect-chain analysis (network access)
python phishguard.py --allow-network "https://bit.ly/xyz"
```

Sample output:

```
================================================================
PhishGuard — URL analysis
================================================================
URL:    http://apple-login.tk/account/verify
Host:   apple-login.tk
Scheme: http

Risk score: 90/100
Verdict:    CRITICAL — Do not visit. Almost certainly phishing.

Findings (5):

  [HIGH    ] typosquatting
           Domain label 'apple-login' embeds brand 'apple' but is not the brand's own domain
           evidence: apple-login  contains  apple

  [MEDIUM  ] tld
           TLD '.tk' is frequently abused in phishing
           evidence: .tk

  [MEDIUM  ] keywords
           3 suspicious keyword(s) in URL
           evidence: account, login, verify

  [LOW     ] scheme
           Uses plain HTTP (no TLS) — credentials could be intercepted
           evidence: http://
...
```

---

## Risk scoring

Each finding carries a severity weight:

| Severity | Weight | Meaning |
|----------|-------:|---------|
| info | 0 | informational only |
| low | 5 | soft signal, could be benign |
| medium | 15 | real concern, needs verification |
| high | 30 | very likely malicious |
| critical | 50 | almost certainly malicious |

Weights are summed and capped at 100.

| Score | Verdict |
|-------|---------|
| 75–100 | **CRITICAL** — Do not visit. Almost certainly phishing. |
| 50–74 | **HIGH** — Very likely phishing. Do not visit. |
| 25–49 | **MEDIUM** — Suspicious. Verify via another channel. |
| 10–24 | **LOW** — Minor signals. Probably safe, but double-check. |
| 0–9 | **SAFE** — No phishing indicators found. |

---

## Safety by design

- **Static by default.** PhishGuard never opens a network connection unless you pass `--allow-network`.
- **SSRF-protected.** Even in `--allow-network` mode, PhishGuard refuses to follow redirects to private IP ranges (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16).
- **No data exfiltration.** No telemetry, no external lookups, no third-party APIs.
- **Read-only.** PhishGuard never POSTs, never logs in, never downloads files.

---

## Requirements

- Python 3.7 or newer.
- No third-party packages.
- Runs on Termux, Linux, macOS, Windows — anywhere Python runs.

---

## Limitations (read this before trusting the score)

PhishGuard is a **heuristic** tool. It catches the majority of *obvious* phishing URLs, but it will:

- **Miss** sophisticated phishing hosted on legitimate-looking domains (compromised accounts, lookalike real brand domains, phishing hosted on free hosting like `sites.google.com`).
- **Flag** some legitimate sites as suspicious (e.g. a small startup called `app1e-app.com` that has nothing to do with Apple).
- **Never** confirm that a URL is safe — only the site itself can do that.

**Use PhishGuard as one signal, not the final word.** If in doubt, navigate to the service by typing its URL manually or using your bookmarks.

---

## Roadmap / contributions welcome

- [ ] Optional offline database of known-bad domains (e.g. PhishTank dump)
- [ ] Batching with summary-only mode for huge URL lists
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] Browser-extension wrapper that pipes the current tab's URL into PhishGuard
- [ ] Unit tests (the code is currently one file with no tests — a great first contribution)

---

## License

MIT. See `LICENSE`.
