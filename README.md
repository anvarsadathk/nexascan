<h1 align="center">🛰️ nexascan</h1>

<p align="center">
  <b>Master web reconnaissance & bug-finding scanner.</b><br>
  One target in → a consolidated, severity-ranked report out (console · JSON · HTML).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img src="https://img.shields.io/badge/license-MIT-green">
  <img src="https://img.shields.io/badge/core-stdlib--only-brightgreen">
  <img src="https://img.shields.io/badge/scope-enforced-red">
  <img src="https://img.shields.io/badge/version-1.0.0-blueviolet">
</p>

---

`nexascan` chains passive recon and active web checks into a **single pass**, enforces **scope on every host it touches**, and produces one clean report you can hand to a client or triage from. It's the orchestrator that ties the [NexaSEC Recon toolkit](https://github.com/anvarsadathk/nexasec-recon) together.

> **Detection, not exploitation.** nexascan surfaces findings and candidate issues. It never weaponizes, exploits, or persists anything.

## 🔎 What it checks

| Module | Finds | Active? |
|--------|-------|---------|
| Subdomains | hosts via Certificate Transparency logs | passive |
| DNS + AXFR | records; **zone-transfer** exposure (CRITICAL) | mixed |
| Takeover | dangling subdomains on unclaimed services | active |
| Ports | exposed DB/admin services (MySQL, Redis, Docker API, Kibana…) | active |
| Security headers | missing HSTS / CSP / X-Frame-Options, tech disclosure | active |
| CORS | origin reflection, `*`+credentials (CRITICAL) | active |
| JS secrets | AWS/GCP/Slack/GitHub/Stripe keys, private keys in scripts | active |
| Reflected params | XSS candidate points (which chars survive raw) | active |

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
=== nexascan findings (10) ===
[CRITICAL] cors            app.example.com/  — arbitrary origin reflected WITH credentials
[HIGH]     leaked-secret   app.example.com/static/main.js — AWS Access Key: AKIA...
[HIGH]     reflected-param /search?q=..  — param 'q' reflected; raw: "'<>
[MEDIUM]   missing-header  app.example.com/ — CSP missing
Summary: CRITICAL=1, HIGH=2, MEDIUM=2, LOW=2, INFO=3  (4.1s)
```

## ⚠️ Responsible use

For **authorized security testing only** — assets you own or have explicit written permission to assess. Unauthorized scanning is illegal in most jurisdictions. You are responsible for staying in scope and within the law. Report findings through the proper disclosure or bug-bounty channel.

## 👤 Author

**Anvar Sadath K.** — Founder & Director, [NexaSEC Cyber Solution LLP](https://nexasec.in).
VAPT · OSINT · Red Team · API & Web3 Security.

## License
MIT — see [LICENSE](LICENSE). Use responsibly.
