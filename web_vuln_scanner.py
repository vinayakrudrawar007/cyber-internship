#!/usr/bin/env python3
"""
web_vuln_scanner.py
Simple web vulnerability scanner (demo) with basic SQLi and reflected XSS checks.
Uses requests + BeautifulSoup. Safe for demo / authorized testing only.
"""
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import sys
import time

SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- "]
XSS_MARKER = "INJECT_ME_XSS_12345"

SQL_ERRORS_RE = re.compile(
    r"(sql syntax|mysql|sqlstate|native client|odbc|unterminated string|sqlite|syntax error)",
    re.I
)

def fetch(url, timeout):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None

def find_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        action = urljoin(base_url, action)
        method = (form.get("method") or "get").lower()
        inputs = {}
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value") or ""
            inputs[name] = value
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms

def discover_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme in ("http","https") and urlparse(base_url).netloc == parsed.netloc:
            links.add(full.split('#')[0])
    return list(links)

def test_sqli_get(url, timeout, verbose):
    baseline = fetch(url, timeout)
    if baseline is None:
        return []
    baseline_text = baseline.text
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings
    qs_pairs = [p.split('=') for p in parsed.query.split('&') if '=' in p]
    params = {k:v for k,v in (pair if len(pair)==2 else [pair[0], ""] for pair in qs_pairs)}
    for param in list(params.keys()):
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                r = requests.get(parsed._replace(query="").geturl(), params=test_params, timeout=timeout)
            except Exception:
                continue
            if SQL_ERRORS_RE.search(r.text):
                findings.append({"url": r.url, "param": param, "payload": payload, "evidence": "SQL error found"})
            elif abs(len(r.text) - len(baseline_text)) > 200:
                findings.append({"url": r.url, "param": param, "payload": payload, "evidence": "response length change"})
    return findings

def test_sqli_forms(forms, timeout, verbose):
    findings = []
    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        for param in list(inputs.keys()):
            for payload in SQLI_PAYLOADS:
                data = inputs.copy()
                data[param] = payload
                try:
                    if method == "post":
                        r = requests.post(action, data=data, timeout=timeout)
                    else:
                        r = requests.get(action, params=data, timeout=timeout)
                except Exception:
                    continue
                if SQL_ERRORS_RE.search(r.text):
                    findings.append({"url": action, "param": param, "payload": payload, "evidence": "SQL error in form response"})
                elif len(r.text) != 0 and "warning" in r.text.lower() and "sql" in r.text.lower():
                    findings.append({"url": action, "param": param, "payload": payload, "evidence": "possible SQL warning"})
    return findings

def test_xss_get(url, timeout, verbose):
    parsed = urlparse(url)
    if not parsed.query:
        return []
    findings = []
    qs_pairs = [p.split('=') for p in parsed.query.split('&') if '=' in p]
    params = {k:v for k,v in (pair if len(pair)==2 else [pair[0], ""] for pair in qs_pairs)}
    for param in list(params.keys()):
        test_params = params.copy()
        marker = XSS_MARKER
        test_params[param] = marker + "<script>"
        try:
            r = requests.get(parsed._replace(query="").geturl(), params=test_params, timeout=timeout)
        except Exception:
            continue
        if marker in r.text:
            findings.append({"url": r.url, "param": param, "payload": "<script>", "evidence": "marker reflected"})
    return findings

def test_xss_forms(forms, timeout, verbose):
    findings = []
    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        for param in list(inputs.keys()):
            data = inputs.copy()
            marker = XSS_MARKER
            data[param] = marker + "<svg/onload=void(0)>"
            try:
                if method == "post":
                    r = requests.post(action, data=data, timeout=timeout)
                else:
                    r = requests.get(action, params=data, timeout=timeout)
            except Exception:
                continue
            if marker in r.text:
                findings.append({"url": action, "param": param, "payload": "<svg/onload>", "evidence": "marker reflected in form response"})
    return findings

def main():
    ap = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner (demo)")
    ap.add_argument('--host', required=True, help="Base URL, e.g. http://localhost:8000")
    ap.add_argument('--sqli', action='store_true')
    ap.add_argument('--xss', action='store_true')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    base = args.host.rstrip('/')
    parsed_base = urlparse(base)
    if parsed_base.scheme not in ("http","https"):
        print("Host must include scheme, e.g. http://localhost:8000", file=sys.stderr)
        sys.exit(2)

    print(f"[+] Scanning {base} (sqli={args.sqli}, xss={args.xss})")
    r = fetch(base, args.timeout)
    if not r:
        print("[-] Failed to fetch base URL")
        sys.exit(2)

    html = r.text
    forms = find_forms(html, base)
    links = discover_links(html, base)
    if args.verbose:
        print(f"[+] Found {len(forms)} forms and {len(links)} links on base page")

    all_findings = []

    # test base page URL itself
    if args.sqli:
        if "?" in base:
            f = test_sqli_get(base, args.timeout, args.verbose)
            all_findings.extend(f)
        f = test_sqli_forms(forms, args.timeout, args.verbose)
        all_findings.extend(f)

    if args.xss:
        if "?" in base:
            f = test_xss_get(base, args.timeout, args.verbose)
            all_findings.extend(f)
        f = test_xss_forms(forms, args.timeout, args.verbose)
        all_findings.extend(f)

    # follow links (one level) and test them
    for link in links:
        if args.verbose:
            print(f"[+] Visiting {link}")
        r2 = fetch(link, args.timeout)
        if not r2:
            continue
        html2 = r2.text
        forms2 = find_forms(html2, link)
        if args.sqli:
            if "?" in link:
                all_findings.extend(test_sqli_get(link, args.timeout, args.verbose))
            all_findings.extend(test_sqli_forms(forms2, args.timeout, args.verbose))
        if args.xss:
            if "?" in link:
                all_findings.extend(test_xss_get(link, args.timeout, args.verbose))
            all_findings.extend(test_xss_forms(forms2, args.timeout, args.verbose))

    # summarize
    if all_findings:
        print("\n=== FINDINGS ===")
        for f in all_findings:
            print(f"- {f['url']} param={f.get('param')} payload={f.get('payload')} evidence={f.get('evidence')}")
    else:
        print("\nNo findings (sqli/xss) for the scanned surface.\n")

if __name__ == '__main__':
    main()
