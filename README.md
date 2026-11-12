<h1 align="center">🛰️ nexascan</h1>

<p align="center">
  <b>Master web recon & OWASP Top 10 scanner.</b><br>
  One target in → a consolidated, severity-ranked, OWASP-mapped report out (console · JSON · HTML).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img src="https://img.shields.io/badge/license-MIT-green">
  <img src="https://img.shields.io/badge/core-stdlib--only-brightgreen">
  <img src="https://img.shields.io/badge/scope-enforced-red">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange">
  <img src="https://img.shields.io/badge/version-1.1.0-blueviolet">
</p>

---

`nexascan` chains passive recon and active web checks into a **single pass**, enforces **scope on every host it touches**, and produces one clean report you can hand to a client or triage from. It's the orchestrator that ties the [NexaSEC Recon toolkit](https://github.com/anvarsadathk/nexasec-recon) together.

> **Detection, not exploitation.** nexascan surfaces findings and candidate issues. It never weaponizes, exploits, or persists anything.

## 🔎 What it checks

Every finding is tagged with its **OWASP Top 10 (2021)** category.

| Module | Finds | OWASP | Active? |
|--------|-------|-------|---------|
| Subdomains | hosts via Certificate Transparency logs | — | passive |
| DNS + AXFR | records; **zone-transfer** exposure (CRITICAL) | A05 | mixed |
| Takeover | dangling subdomains on unclaimed services | A05 | active |
| Ports | exposed DB/admin services (MySQL, Redis, Docker API, Kibana…) | A05 | active |
| TLS / SSL | expired/expiring certs, weak protocol, no HTTPS redirect | A02 | active |
| Security headers | missing HSTS / CSP / X-Frame-Options, tech disclosure | A05/A06 | active |
| Cookies | missing HttpOnly / Secure / SameSite flags | A05 | active |
| HTTP methods | dangerous verbs enabled (PUT, DELETE, TRACE…) | A05 | active |
| Sensitive files | exposed `.git`, `.env`, backups, dumps, swagger, actuator | A05 | active |
| CORS | origin reflection, `*`+credentials (CRITICAL) | A05 | active |
| JS secrets | AWS/GCP/Slack/GitHub/Stripe keys, private keys in scripts | A02 | active |
| Reflected params | XSS candidate points (which chars survive raw) | A03 | active |
| SQL injection | error-based detection across every parameter | A03 | active |
| Open redirect | unvalidated `url`/`next`/`redirect` params | A01 | active |

### OWASP Top 10 (2021) coverage

| | Category | Covered by |
|---|----------|-----------|
| **A01** | Broken Access Control | open redirect |
| **A02** | Cryptographic Failures | TLS/SSL audit, leaked secrets |
| **A03** | Injection | SQLi (error-based), reflected XSS |
| **A05** | Security Misconfiguration | headers, cookies, methods, CORS, sensitive files, AXFR |
| **A06** | Vulnerable Components | tech/version disclosure |

A04/A07–A10 need manual or authenticated testing and are intentionally out of scope for an unauthenticated scanner — nexascan flags the evidence a human then confirms.

## ⚡ Install

```bash
git clone https://github.com/anvarsadathk/nexascan.git
cd nexascan
pip install -r requirements.txt   # optional: DNS + AXFR
python3 nexascan.py --help
```

## 🚀 Usage

```bash
# Full scan of a domain (scope defaults to its registrable domain)
python3 nexascan.py example.com --yes-authorized

# Tighten scope, add zone-transfer attempt, feed param URLs, name the report
python3 nexascan.py https://app.example.com/ \
    --scope example.com,api.example.com \
    --axfr --urls wayback-urls.txt \
    -o acme-report --yes-authorized
```

Outputs `acme-report.json` (automation) and `acme-report.html` (shareable, dark-themed).

> nexascan runs **active** checks — it requires `--yes-authorized`. Every module validates each host against `--scope` and **hard-aborts anything out of scope**; scope safety is in the code, not a disclaimer.

## 📋 Example output

```
=== nexascan findings (14) ===
[CRITICAL] A05 cors            app.example.com/  — arbitrary origin reflected WITH credentials
[HIGH]     A05 sensitive-file  app.example.com/.env  — exposed sensitive file (.env)
[HIGH]     A02 leaked-secret   app.example.com/static/main.js — AWS Access Key: AKIA...
[HIGH]     A03 sqli            /search?id=..  — param 'id' triggers SQL error
[MEDIUM]   A01 open-redirect   /go?next=..  — param 'next' redirects to attacker-controlled URL
[MEDIUM]   A05 missing-header  app.example.com/ — CSP missing
Summary: CRITICAL=1, HIGH=3, MEDIUM=4, LOW=3, INFO=3  (9.2s)
OWASP: A01, A02, A03, A05, A06
```

## ⚠️ Responsible use

For **authorized security testing only** — assets you own or have explicit written permission to assess. Unauthorized scanning is illegal in most jurisdictions. You are responsible for staying in scope and within the law. Report findings through the proper disclosure or bug-bounty channel.

## 👤 Author

**Anvar Sadath K.** — Founder & Director, [NexaSEC Cyber Solution LLP](https://nexasec.in).
VAPT · OSINT · Red Team · API & Web3 Security.

## License
MIT — see [LICENSE](LICENSE). Use responsibly.
