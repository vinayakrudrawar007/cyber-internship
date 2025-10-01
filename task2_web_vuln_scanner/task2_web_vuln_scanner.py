#!/usr/bin/env python3
"""
Basic web scanner — *only for authorized targets*.
Usage:
  python web_vuln_scanner.py --url http://localhost:8000
"""
import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse

XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "' OR '1'='1"

def get_forms(url):
    r = requests.get(url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    return soup.find_all("form")

def form_details(form):
    action = form.get("action") or ""
    method = form.get("method","get").lower()
    inputs = [i.get("name") for i in form.find_all(["input","textarea"]) if i.get("name")]
    return {"action": action, "method": method, "inputs": inputs}

def scan_url_for_basic_vulns(url):
    print("Scanning", url)
    forms = get_forms(url)
    for i, form in enumerate(forms, 1):
        details = form_details(form)
        target = urllib.parse.urljoin(url, details['action'])
        print(f" Form #{i} -> {details['method'].upper()} {target} inputs={details['inputs']}")
        # Try XSS
        data = {name: XSS_PAYLOAD for name in details['inputs']}
        if details['method'] == 'post':
            r = requests.post(target, data=data, timeout=10)
        else:
            r = requests.get(target, params=data, timeout=10)
        if XSS_PAYLOAD in r.text:
            print("  [!] Possible reflected XSS at", target)
        # Try a simple SQLi payload (look for typical SQL errors or differing responses)
        data = {name: SQLI_PAYLOAD for name in details['inputs']}
        if details['method'] == 'post':
            r2 = requests.post(target, data=data, timeout=10)
        else:
            r2 = requests.get(target, params=data, timeout=10)
        # very basic heuristics
        errors = ["sql syntax", "mysql", "syntax error", "warning", "unclosed quotation mark"]
        if any(e in r2.text.lower() for e in errors) or len(r2.text) != len(r.text):
            print("  [!] Possible SQL injection (heuristic) at", target)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True)
    args = ap.parse_args()
    scan_url_for_basic_vulns(args.url)
