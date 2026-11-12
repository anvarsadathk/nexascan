#!/usr/bin/env python3
"""
nexascan - master web reconnaissance & bug-finding scanner.

One target in, a consolidated severity-ranked report out. nexascan chains
passive recon and active web checks into a single pass, enforces scope on
every host it touches, and writes console + JSON + HTML reports.

Modules: subdomains (CT logs) · DNS + AXFR · subdomain takeover ·
port scan · security headers · CORS · JS secrets/endpoints · reflected
parameters.

It is a DETECTION tool: it surfaces findings and candidate issues. It does
not exploit, weaponize, or persist anything.

Author: Anvar Sadath K. — NexaSEC  |  License: MIT
Authorized testing only. Every active module hard-aborts out of scope.
"""
import argparse
import asyncio
import concurrent.futures as cf
import html
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import dns.resolver, dns.query, dns.zone
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

VERSION = "1.0.0"
UA = f"nexascan/{VERSION}"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BANNER = r"""
  _ __   _____  ____ _ ___  ___ __ _ _ __
 | '_ \ / _ \ \/ / _` / __|/ __/ _` | '_ \
 | | | |  __/>  < (_| \__ \ (_| (_| | | | |
 |_| |_|\___/_/\_\__,_|___/\___\__,_|_| |_|
     master web recon & bug scanner  v%s
""" % VERSION


# --------------------------------------------------------------------------- #
#  Scope enforcement (non-negotiable)
# --------------------------------------------------------------------------- #
class Scope:
    def __init__(self, suffixes):
        self.suffixes = [s.strip().lstrip("*.").lower() for s in suffixes if s.strip()]

    def allows(self, host: str) -> bool:
        host = (host or "").lower().strip().rstrip(".")
        if not host:
            return False
        return any(host == s or host.endswith("." + s) for s in self.suffixes)

    def require(self, host: str):
        if not self.allows(host):
            raise OutOfScope(host)


class OutOfScope(Exception):
    pass


def registrable(host: str) -> str:
    host = host.split("//")[-1].split("/")[0].split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# --------------------------------------------------------------------------- #
#  HTTP helpers
# --------------------------------------------------------------------------- #
def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def http_get(url, timeout=12, headers=None):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return r.status, dict(r.headers), r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read(200000).decode("utf-8", "replace")
        except Exception:
            return e.code, {}, ""
    except Exception:
        return None, {}, ""


# --------------------------------------------------------------------------- #
#  Modules — each returns a list of finding dicts
# --------------------------------------------------------------------------- #
def _add_sub(name, domain, subs):
    name = name.strip().lstrip("*.").lower()
    if name.endswith(domain) and re.match(r"^[a-z0-9.\-]+$", name):
        subs.add(name)


def mod_subdomains(domain, scope, log):
    """Passive CT-log enumeration. crt.sh is flaky under load, so we retry
    with a browser-like UA and fall back to certspotter."""
    browser_ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
    subs = set()

    # --- source 1: crt.sh, with retries ---
    crt = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    for attempt in range(1, 4):
        log("subdomains", f"crt.sh attempt {attempt}/3")
        status, _, body = http_get(crt, timeout=40, headers={"User-Agent": browser_ua})
        body = (body or "").strip()
        if not body:
            time.sleep(2 * attempt)
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            # crt.sh sometimes streams newline-delimited objects or an HTML error
            if body.lstrip().startswith("<"):
                time.sleep(2 * attempt)
                continue
            data = []
            for line in body.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        data.append(json.loads(line))
                    except Exception:
                        pass
        for entry in data:
            for name in str(entry.get("name_value", "")).splitlines():
                _add_sub(name, domain, subs)
        if subs:
            break
        time.sleep(2 * attempt)

    # --- source 2: certspotter fallback ---
    if not subs:
        log("subdomains", "crt.sh empty — trying certspotter")
        cs = (f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
              "&include_subdomains=true&expand=dns_names")
        _, _, body = http_get(cs, timeout=30, headers={"User-Agent": browser_ua})
        try:
            for entry in json.loads(body or "[]"):
                for name in entry.get("dns_names", []):
                    _add_sub(name, domain, subs)
        except Exception as e:
            log("subdomains", f"certspotter error: {e}")

    subs = sorted(s for s in subs if scope.allows(s))
    if not subs:
        log("subdomains", "0 found (CT sources rate-limited or no certs) — continuing")
    else:
        log("subdomains", f"{len(subs)} in-scope subdomains")
    return subs, [{"severity": "INFO", "type": "subdomain", "target": s,
                   "detail": "discovered via CT logs"} for s in subs]


def resolve(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def mod_dns(domain, scope, do_axfr, log):
    findings = []
    if not HAVE_DNS:
        log("dns", "dnspython not installed — skipping (pip install dnspython)")
        return findings
    log("dns", "enumerating records")
    resolver = dns.resolver.Resolver()
    ns_hosts = []
    for rt in ["A", "MX", "TXT", "NS", "SOA", "CAA"]:
        try:
            for a in resolver.resolve(domain, rt, lifetime=5):
                val = a.to_text()
                if rt == "NS":
                    ns_hosts.append(val.split()[0].rstrip("."))
                findings.append({"severity": "INFO", "type": f"dns-{rt}",
                                 "target": domain, "detail": val})
        except Exception:
            pass
    if do_axfr:
        for ns in ns_hosts:
            try:
                ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, lifetime=8))
                names = [str(n) for n in zone.nodes.keys()]
                findings.append({"severity": "CRITICAL", "type": "zone-transfer",
                                 "target": ns,
                                 "detail": f"AXFR allowed — {len(names)} records exposed"})
                log("dns", f"AXFR allowed on {ns} (CRITICAL)")
            except Exception:
                pass
    return findings


TAKEOVER_FP = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "ERROR: The request could not be satisfied",
    "wpengine.com": "The site you were looking for couldn't be found",
    "surge.sh": "project not found",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "azurewebsites.net": "404 Web Site not found",
    "fastly.net": "Fastly error: unknown domain",
}


def mod_takeover(hosts, scope, log):
    findings = []
    log("takeover", f"checking {len(hosts)} hosts")

    def check(host):
        for scheme in ("https", "http"):
            status, _, body = http_get(f"{scheme}://{host}", timeout=8)
            if body:
                for svc, sig in TAKEOVER_FP.items():
                    if sig.lower() in body.lower():
                        return {"severity": "HIGH", "type": "subdomain-takeover",
                                "target": host,
                                "detail": f"unclaimed {svc} fingerprint matched"}
                break
        return None

    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for res in ex.map(check, hosts):
            if res:
                findings.append(res)
                log("takeover", f"{res['target']} — {res['detail']} (HIGH)")
    return findings


def mod_ports(host, scope, log):
    scope.require(host)
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521,
             2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 6379,
             6443, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 9300, 11211, 27017]
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return []
    log("ports", f"scanning {len(ports)} ports on {host}")
    risky = {3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB",
             9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API",
             3389: "RDP", 445: "SMB", 5601: "Kibana"}

    async def scan():
        open_ports = []
        sem = asyncio.Semaphore(200)

        async def one(p):
            async with sem:
                try:
                    fut = asyncio.open_connection(ip, p)
                    _, w = await asyncio.wait_for(fut, timeout=1.5)
                    w.close()
                    open_ports.append(p)
                except Exception:
                    pass
        await asyncio.gather(*(one(p) for p in ports))
        return sorted(open_ports)

    open_ports = asyncio.run(scan())
    findings = []
    for p in open_ports:
        if p in risky:
            findings.append({"severity": "MEDIUM", "type": "exposed-service",
                             "target": f"{host}:{p}",
                             "detail": f"{risky[p]} port reachable — review exposure"})
        else:
            findings.append({"severity": "INFO", "type": "open-port",
                             "target": f"{host}:{p}", "detail": "open"})
    log("ports", f"{len(open_ports)} open")
    return findings


SEC_HEADERS = {
    "strict-transport-security": ("HSTS missing", "MEDIUM"),
    "content-security-policy": ("CSP missing", "MEDIUM"),
    "x-frame-options": ("X-Frame-Options missing (clickjacking)", "LOW"),
    "x-content-type-options": ("X-Content-Type-Options missing", "LOW"),
    "referrer-policy": ("Referrer-Policy missing", "INFO"),
    "permissions-policy": ("Permissions-Policy missing", "INFO"),
}


def mod_headers(url, scope, log):
    host = urllib.parse.urlparse(url).hostname or ""
    scope.require(host)
    log("headers", f"auditing {url}")
    status, headers, _ = http_get(url)
    if status is None:
        return []
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    for h, (desc, sev) in SEC_HEADERS.items():
        if h not in lower:
            findings.append({"severity": sev, "type": "missing-header",
                             "target": url, "detail": desc})
    server = lower.get("server") or lower.get("x-powered-by")
    if server:
        findings.append({"severity": "INFO", "type": "tech-disclosure",
                         "target": url, "detail": f"server banner: {server}"})
    return findings


def mod_cors(url, scope, log):
    host = urllib.parse.urlparse(url).hostname or ""
    scope.require(host)
    log("cors", f"testing {url}")
    evil = "https://nexascan-evil.example"
    _, headers, _ = http_get(url, headers={"Origin": evil})
    lower = {k.lower(): v for k, v in headers.items()}
    acao = lower.get("access-control-allow-origin")
    acac = (lower.get("access-control-allow-credentials") or "").lower() == "true"
    if not acao:
        return []
    if acao == evil and acac:
        return [{"severity": "CRITICAL", "type": "cors",
                 "target": url, "detail": "arbitrary origin reflected WITH credentials"}]
    if acao == evil:
        return [{"severity": "MEDIUM", "type": "cors",
                 "target": url, "detail": "arbitrary origin reflected"}]
    if acao == "*" and acac:
        return [{"severity": "HIGH", "type": "cors",
                 "target": url, "detail": "wildcard origin with credentials"}]
    return []


SECRET_RX = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Stripe Key": re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}
JS_SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


def mod_js_secrets(base_url, scope, log):
    host = urllib.parse.urlparse(base_url).hostname or ""
    scope.require(host)
    log("js", f"scanning scripts on {base_url}")
    status, _, body = http_get(base_url)
    if not body:
        return []
    scripts = JS_SRC_RX.findall(body)
    findings = []
    seen = set()
    for src in scripts[:25]:
        js_url = urllib.parse.urljoin(base_url, src)
        jhost = urllib.parse.urlparse(js_url).hostname or ""
        if not scope.allows(jhost) or js_url in seen:
            continue
        seen.add(js_url)
        _, _, js = http_get(js_url)
        for name, rx in SECRET_RX.items():
            for m in rx.finditer(js or ""):
                findings.append({"severity": "HIGH", "type": "leaked-secret",
                                 "target": js_url,
                                 "detail": f"{name}: {m.group(0)[:40]}"})
    if findings:
        log("js", f"{len(findings)} secret hit(s) (HIGH)")
    return findings


def mod_reflected(urls, scope, log):
    findings = []
    specials = ['"', "'", "<", ">"]
    targets = [u for u in urls if "?" in u and "=" in u]
    if not targets:
        return findings
    log("reflected", f"testing {len(targets)} parameterized URL(s)")

    def test(url):
        host = urllib.parse.urlparse(url).hostname or ""
        if not scope.allows(host):
            return []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        out = []
        for i, (k, _) in enumerate(params):
            canary = f"nxq{i}" + "".join(specials) + "nxz"
            mut = list(params); mut[i] = (k, canary)
            turl = parsed._replace(query=urllib.parse.urlencode(mut)).geturl()
            _, _, body = http_get(turl)
            if body and f"nxq{i}" in body and "nxz" in body:
                seg = body[body.find(f"nxq{i}"): body.find("nxz") + 3]
                raw = [c for c in specials if c in seg]
                sev = "HIGH" if {"<", ">"} & set(raw) else (
                      "MEDIUM" if {'"', "'"} & set(raw) else "LOW")
                out.append({"severity": sev, "type": "reflected-param",
                            "target": url,
                            "detail": f"param '{k}' reflected; raw: {''.join(raw) or 'encoded'}"})
        return out

    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for res in ex.map(test, targets):
            findings.extend(res)
    return findings


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
def write_json(findings, meta, path):
    with open(path, "w") as f:
        json.dump({"meta": meta, "findings": findings}, f, indent=2)


def write_html(findings, meta, path):
    colors = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825",
              "LOW": "#1565c0", "INFO": "#607d8b"}
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    rows = ""
    for f in findings:
        c = colors.get(f["severity"], "#777")
        rows += (f'<tr><td><span class="sev" style="background:{c}">{f["severity"]}</span></td>'
                 f'<td>{html.escape(f["type"])}</td>'
                 f'<td>{html.escape(str(f["target"]))}</td>'
                 f'<td>{html.escape(str(f["detail"]))}</td></tr>')
    chips = " ".join(
        f'<span class="chip" style="background:{colors[s]}">{s}: {counts[s]}</span>'
        for s in SEVERITY_ORDER if counts[s])
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>nexascan report — {html.escape(meta['target'])}</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
header{{padding:24px 32px;background:#161922;border-bottom:1px solid #262b36}}
h1{{margin:0;font-size:20px}} .muted{{color:#8a93a6;font-size:13px;margin-top:4px}}
.wrap{{padding:24px 32px}} .chips{{margin:12px 0 20px}}
.chip,.sev{{color:#fff;padding:3px 9px;border-radius:12px;font-size:12px;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #232834;vertical-align:top}}
th{{color:#8a93a6;font-weight:600}} tr:hover td{{background:#161922}}
code{{color:#9cdcfe}}
</style></head><body>
<header><h1>🛰️ nexascan report</h1>
<div class="muted">Target: <code>{html.escape(meta['target'])}</code> ·
Scope: {html.escape(', '.join(meta['scope']))} ·
{html.escape(meta['started'])} · {len(findings)} findings</div></header>
<div class="wrap"><div class="chips">{chips or 'No findings.'}</div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Target</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="muted">Generated by nexascan v{VERSION} — authorized testing only.</p>
</div></body></html>"""
    with open(path, "w") as f:
        f.write(doc)


# --------------------------------------------------------------------------- #
#  Orchestrator
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="nexascan — master web recon & bug-finding scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="domain or URL, e.g. example.com or https://example.com/")
    p.add_argument("--scope", help="comma-separated in-scope host suffixes "
                                   "(default: the target's registrable domain)")
    p.add_argument("--axfr", action="store_true", help="attempt DNS zone transfer")
    p.add_argument("--no-ports", action="store_true", help="skip port scan")
    p.add_argument("--urls", help="file of parameterized URLs for reflected-param testing")
    p.add_argument("-o", "--output", default="nexascan-report",
                   help="output basename (writes .json and .html)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--yes-authorized", action="store_true",
                   help="confirm you are authorized to test the target + scope")
    args = p.parse_args()

    if not args.quiet:
        print(BANNER, file=sys.stderr)
    if not args.yes_authorized:
        print("[!] nexascan runs ACTIVE checks. Re-run with --yes-authorized to "
              "confirm the target and scope are authorized.", file=sys.stderr)
        sys.exit(2)

    raw = args.target
    host = urllib.parse.urlparse(raw).hostname or raw.split("/")[0].split(":")[0]
    domain = registrable(host)
    base_url = raw if raw.startswith("http") else f"https://{host}/"
    scope = Scope(args.scope.split(",") if args.scope else [domain])

    def log(mod, msg):
        if not args.quiet:
            print(f"  [{mod:10}] {msg}", file=sys.stderr)

    meta = {"target": raw, "domain": domain, "scope": scope.suffixes,
            "started": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "version": VERSION}
    print(f"[*] nexascan target={raw}  scope={scope.suffixes}", file=sys.stderr)

    findings = []
    t0 = time.time()

    subs, sub_findings = mod_subdomains(domain, scope, log)
    findings += sub_findings
    live_hosts = [host] + [s for s in subs if s != host]

    findings += mod_dns(domain, scope, args.axfr, log)
    findings += mod_takeover(live_hosts[:60], scope, log)

    if not args.no_ports:
        try:
            findings += mod_ports(host, scope, log)
        except OutOfScope as e:
            log("ports", f"out of scope, skipped: {e}")

    for fn in (mod_headers, mod_cors, mod_js_secrets):
        try:
            findings += fn(base_url, scope, log)
        except OutOfScope as e:
            log(fn.__name__, f"out of scope: {e}")
        except Exception as e:
            log(fn.__name__, f"error: {e}")

    if args.urls:
        try:
            with open(args.urls) as f:
                urls = [x.strip() for x in f if x.strip() and not x.startswith("#")]
            findings += mod_reflected(urls, scope, log)
        except Exception as e:
            log("reflected", f"error: {e}")

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    # console summary
    print(f"\n=== nexascan findings ({len(findings)}) ===")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            print(f"[{f['severity']}] {f['type']}  {f['target']}  — {f['detail']}")
    print("\nSummary: " + ", ".join(f"{k}={counts[k]}"
          for k in SEVERITY_ORDER if k in counts) + f"  ({time.time()-t0:.1f}s)")

    write_json(findings, meta, f"{args.output}.json")
    write_html(findings, meta, f"{args.output}.html")
    print(f"[+] Reports: {args.output}.json  {args.output}.html", file=sys.stderr)


if __name__ == "__main__":
    main()
