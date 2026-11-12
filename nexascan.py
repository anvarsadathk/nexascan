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

VERSION = "1.1.0"
UA = f"nexascan/{VERSION}"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# OWASP Top 10 (2021) category names
OWASP_NAMES = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components",
    "A07": "A07 Identification & Auth Failures",
    "A08": "A08 Software & Data Integrity Failures",
    "A09": "A09 Logging & Monitoring Failures",
    "A10": "A10 Server-Side Request Forgery",
    "-":   "Recon / Informational",
}

# finding type -> OWASP category
OWASP_MAP = {
    "cors": "A05", "missing-header": "A05", "insecure-cookie": "A05",
    "http-method": "A05", "dir-listing": "A05", "sensitive-file": "A05",
    "zone-transfer": "A05", "exposed-service": "A05", "takeover": "A05",
    "leaked-secret": "A02", "tls": "A02",
    "reflected-param": "A03", "sqli": "A03",
    "open-redirect": "A01",
    "tech-disclosure": "A06",
    "login-exposed": "A07",
    "missing-sri": "A08",
}


def owasp_for(ftype):
    return OWASP_MAP.get(ftype, "-")

BANNER = r"""
  _ __   _____  ____ _ ___  ___ __ _ _ __
 | '_ \ / _ \ \/ / _` / __|/ __/ _` | '_ \
 | | | |  __/>  < (_| \__ \ (_| (_| | | | |
 |_| |_|\___/_/\_\__,_|___/\___\__,_|_| |_|
   master web recon & OWASP Top 10 scanner  v%s
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # don't follow — surface the 3xx + Location to the caller


# opener carries the TLS context (OpenerDirector.open() takes no context= kwarg)
_NOREDIR_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))


def http_get(url, timeout=12, headers=None, allow_redirects=True):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        if allow_redirects:
            r = urllib.request.urlopen(req, timeout=timeout, context=_ctx())
        else:
            r = _NOREDIR_OPENER.open(req, timeout=timeout)
        with r:
            return r.status, dict(r.headers), r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # a 3xx with redirects disabled lands here — headers carry Location
        try:
            return e.code, dict(e.headers), e.read(200000).decode("utf-8", "replace")
        except Exception:
            return e.code, dict(getattr(e, "headers", {}) or {}), ""
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
#  OWASP Top 10 modules (detection-only, scope-enforced)
# --------------------------------------------------------------------------- #
def mod_tls(host, scope, log):
    """A02 Cryptographic Failures — cert validity, negotiated protocol,
    HTTP->HTTPS redirect."""
    scope.require(host)
    log("tls", f"inspecting TLS on {host}:443")
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                proto = ss.version()
                cert = ss.getpeercert()
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({"severity": "MEDIUM", "type": "tls", "target": host,
                             "detail": f"weak TLS protocol negotiated: {proto}"})
        if cert and cert.get("notAfter"):
            import calendar
            exp = calendar.timegm(time.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z"))
            days = int((exp - time.time()) / 86400)
            if days < 0:
                findings.append({"severity": "HIGH", "type": "tls", "target": host,
                                 "detail": "TLS certificate is EXPIRED"})
            elif days < 21:
                findings.append({"severity": "LOW", "type": "tls", "target": host,
                                 "detail": f"TLS certificate expires in {days} days"})
    except Exception as e:
        log("tls", f"no/failed TLS: {e}")
    # HTTP -> HTTPS redirect check (no-follow so we can read the Location)
    try:
        status, headers, _ = http_get(f"http://{host}/", timeout=8, allow_redirects=False)
        loc = {k.lower(): v for k, v in headers.items()}.get("location", "")
        redirects_https = status and 300 <= status < 400 and loc.lower().startswith("https")
        if status and not redirects_https:
            findings.append({"severity": "LOW", "type": "tls", "target": host,
                             "detail": "HTTP does not redirect to HTTPS"})
    except Exception:
        pass
    return findings


SENSITIVE_PATHS = {
    ".git/config": "[core]", ".git/HEAD": "ref:", ".env": "=",
    ".DS_Store": "Bud1", "backup.zip": "PK", "backup.sql": "",
    "db.sql": "", "dump.sql": "", ".htaccess": "", "web.config": "<?xml",
    "config.php.bak": "<?php", "phpinfo.php": "phpinfo()",
    "info.php": "phpinfo()", "server-status": "Apache Server Status",
    "actuator/health": '"status"', "actuator/env": '"propertySources"',
    "swagger.json": '"swagger"', "openapi.json": '"openapi"',
    "swagger-ui.html": "swagger", ".svn/entries": "", "wp-config.php.bak": "DB_",
    "composer.json": '"require"', "package.json": '"dependencies"',
    ".aws/credentials": "aws_access", "id_rsa": "PRIVATE KEY",
}


def mod_sensitive_files(base_url, scope, log):
    """A05 Security Misconfiguration — exposed VCS, configs, backups, dumps."""
    host = urllib.parse.urlparse(base_url).hostname or ""
    scope.require(host)
    log("files", f"probing {len(SENSITIVE_PATHS)} sensitive paths")
    base = base_url if base_url.endswith("/") else base_url + "/"
    # baseline 404 body to avoid soft-404 false positives
    _, _, baseline = http_get(urllib.parse.urljoin(base, "nexascan-404-xyz"))
    findings = []

    def probe(item):
        path, sig = item
        url = urllib.parse.urljoin(base, path)
        status, _, body = http_get(url)
        if status == 200 and body and body != baseline:
            if not sig or sig.lower() in body.lower():
                sev = "HIGH" if path in (".git/config", ".env", "id_rsa",
                                         ".aws/credentials", "actuator/env",
                                         "backup.sql", "db.sql", "dump.sql") else "MEDIUM"
                return {"severity": sev, "type": "sensitive-file", "target": url,
                        "detail": f"exposed sensitive file ({path})"}
        return None

    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        for res in ex.map(probe, SENSITIVE_PATHS.items()):
            if res:
                findings.append(res)
                log("files", f"{res['target']} ({res['severity']})")
    return findings


SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysqli",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "pg_query()", "postgresql query failed", "sqlite3.operationalerror",
    "ora-01756", "ora-00933", "microsoft ole db provider for sql server",
    "sqlstate[", "syntax error at or near", "psqlexception",
]


def mod_sqli(urls, scope, log):
    """A03 Injection — error-based SQLi detection (non-destructive probe)."""
    targets = [u for u in urls if "?" in u and "=" in u]
    if not targets:
        return []
    log("sqli", f"error-based probe on {len(targets)} URL(s)")
    findings = []

    def test(url):
        host = urllib.parse.urlparse(url).hostname or ""
        if not scope.allows(host):
            return []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        out = []
        for i, (k, v) in enumerate(params):
            for payload in ("'", "'\"", "1')--"):
                mut = list(params); mut[i] = (k, v + payload)
                turl = parsed._replace(query=urllib.parse.urlencode(mut)).geturl()
                _, _, body = http_get(turl)
                low = (body or "").lower()
                hit = next((e for e in SQL_ERRORS if e in low), None)
                if hit:
                    out.append({"severity": "HIGH", "type": "sqli", "target": url,
                                "detail": f"param '{k}' triggers SQL error ({hit[:30]}...)"})
                    break
        return out

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(test, targets):
            findings.extend(res)
    if findings:
        log("sqli", f"{len(findings)} candidate(s) (HIGH)")
    return findings


REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "return", "returnurl",
                   "return_url", "dest", "destination", "continue", "goto", "rurl", "target"}


def mod_open_redirect(urls, scope, log):
    """A01 Broken Access Control — unvalidated redirect detection."""
    targets = [u for u in urls if "?" in u and "=" in u]
    if not targets:
        return []
    log("redirect", f"testing {len(targets)} URL(s) for open redirect")
    evil = "https://nexascan-evil.example/"
    findings = []

    def test(url):
        host = urllib.parse.urlparse(url).hostname or ""
        if not scope.allows(host):
            return []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        out = []
        for i, (k, _) in enumerate(params):
            if k.lower() not in REDIRECT_PARAMS:
                continue
            mut = list(params); mut[i] = (k, evil)
            turl = parsed._replace(query=urllib.parse.urlencode(mut)).geturl()
            status, headers, _ = http_get(turl, allow_redirects=False)
            loc = {h.lower(): v for h, v in headers.items()}.get("location", "")
            if loc.startswith(evil) or loc.startswith("//nexascan-evil"):
                out.append({"severity": "MEDIUM", "type": "open-redirect", "target": url,
                            "detail": f"param '{k}' redirects to attacker-controlled URL"})
        return out

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(test, targets):
            findings.extend(res)
    return findings


def mod_cookies(base_url, scope, log):
    """A05 — Set-Cookie flag audit (HttpOnly / Secure / SameSite)."""
    host = urllib.parse.urlparse(base_url).hostname or ""
    scope.require(host)
    _, headers, _ = http_get(base_url)
    findings = []
    # http.client folds multiple Set-Cookie; inspect the combined header
    raw = headers.get("Set-Cookie") or ""
    if not raw:
        return findings
    name = raw.split("=", 1)[0]
    low = raw.lower()
    missing = [flag for flag, tok in
               (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
               if tok not in low]
    if missing:
        findings.append({"severity": "LOW", "type": "insecure-cookie", "target": base_url,
                         "detail": f"cookie '{name}' missing: {', '.join(missing)}"})
    return findings


def mod_http_methods(base_url, scope, log):
    """A05 — dangerous HTTP methods enabled."""
    host = urllib.parse.urlparse(base_url).hostname or ""
    scope.require(host)
    try:
        req = urllib.request.Request(base_url, method="OPTIONS",
                                     headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10, context=_ctx()) as r:
            allow = r.headers.get("Allow", "")
    except Exception:
        return []
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
                 if m in allow.upper()]
    if dangerous:
        return [{"severity": "MEDIUM", "type": "http-method", "target": base_url,
                 "detail": f"dangerous methods allowed: {', '.join(dangerous)}"}]
    return []


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
        owasp = OWASP_NAMES.get(f.get("owasp", "-"), "-")
        rows += (f'<tr><td><span class="sev" style="background:{c}">{f["severity"]}</span></td>'
                 f'<td>{html.escape(owasp)}</td>'
                 f'<td>{html.escape(f["type"])}</td>'
                 f'<td>{html.escape(str(f["target"]))}</td>'
                 f'<td>{html.escape(str(f["detail"]))}</td></tr>')
    chips = " ".join(
        f'<span class="chip" style="background:{colors[s]}">{s}: {counts[s]}</span>'
        for s in SEVERITY_ORDER if counts[s])
    owasp_counts = {}
    for f in findings:
        o = f.get("owasp", "-")
        if o != "-":
            owasp_counts[o] = owasp_counts.get(o, 0) + 1
    owasp_chips = " ".join(
        f'<span class="chip" style="background:#37474f">{html.escape(OWASP_NAMES[o])}: {n}</span>'
        for o, n in sorted(owasp_counts.items()))
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
<div class="chips">{owasp_chips}</div>
<table><thead><tr><th>Severity</th><th>OWASP</th><th>Type</th><th>Target</th><th>Detail</th></tr></thead>
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

    # URL-based (per-host) checks
    for fn in (mod_headers, mod_cors, mod_js_secrets, mod_sensitive_files,
               mod_cookies, mod_http_methods):
        try:
            findings += fn(base_url, scope, log)
        except OutOfScope as e:
            log(fn.__name__, f"out of scope: {e}")
        except Exception as e:
            log(fn.__name__, f"error: {e}")

    # TLS (host-based)
    try:
        findings += mod_tls(host, scope, log)
    except OutOfScope as e:
        log("tls", f"out of scope: {e}")
    except Exception as e:
        log("tls", f"error: {e}")

    # Parameter-based checks (reflected XSS, SQLi, open redirect)
    urls = []
    if "?" in raw and "=" in raw:
        urls.append(raw)
    if args.urls:
        try:
            with open(args.urls) as f:
                urls += [x.strip() for x in f if x.strip() and not x.startswith("#")]
        except Exception as e:
            log("urls", f"error reading list: {e}")
    if urls:
        for fn in (mod_reflected, mod_sqli, mod_open_redirect):
            try:
                findings += fn(urls, scope, log)
            except Exception as e:
                log(fn.__name__, f"error: {e}")

    # tag OWASP category + sort
    for f in findings:
        f["owasp"] = owasp_for(f["type"])
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    # console summary
    print(f"\n=== nexascan findings ({len(findings)}) ===")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            tag = f.get("owasp", "-")
            tag = f"{tag} " if tag != "-" else ""
            print(f"[{f['severity']}] {tag}{f['type']}  {f['target']}  — {f['detail']}")
    print("\nSummary: " + ", ".join(f"{k}={counts[k]}"
          for k in SEVERITY_ORDER if k in counts) + f"  ({time.time()-t0:.1f}s)")
    owasp_hit = sorted({f["owasp"] for f in findings if f.get("owasp", "-") != "-"})
    if owasp_hit:
        print("OWASP: " + ", ".join(owasp_hit))

    write_json(findings, meta, f"{args.output}.json")
    write_html(findings, meta, f"{args.output}.html")
    print(f"[+] Reports: {args.output}.json  {args.output}.html", file=sys.stderr)


if __name__ == "__main__":
    main()
