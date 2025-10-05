#!/usr/bin/env python3
"""
port_scanner.py - simple multithreaded TCP port scanner with optional banner grab and output options.
"""
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
import csv

def try_connect(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError):
        try:
            sock.close()
        except Exception:
            pass
        return None
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None

def grab_banner(sock, timeout=1.0):
    try:
        sock.settimeout(timeout)
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        try:
            banner = sock.recv(1024)
            return banner.decode(errors='ignore').strip()
        except Exception:
            return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass

def scan_port(task):
    host, port, timeout, do_banner = task
    sock = try_connect(host, port, timeout)
    if sock:
        banner = ""
        if do_banner:
            banner = grab_banner(sock, timeout)
        return {"port": port, "open": True, "banner": banner}
    else:
        return {"port": port, "open": False, "banner": ""}

def parse_ports(ports_arg, start, end):
    if ports_arg:
        ports = []
        for part in ports_arg.split(','):
            if '-' in part:
                a,b = part.split('-',1)
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    else:
        return list(range(start, end+1))

def main():
    ap = argparse.ArgumentParser(description="Simple TCP port scanner")
    ap.add_argument('--host', required=True)
    ap.add_argument('--start', type=int, default=1)
    ap.add_argument('--end', type=int, default=1024)
    ap.add_argument('--ports', help="Comma-separated ports or ranges, e.g. 22,80,8000-8100")
    ap.add_argument('--workers', type=int, default=200)
    ap.add_argument('--timeout', type=float, default=0.5)
    ap.add_argument('--banner', action='store_true', help="Attempt to grab banner on open ports")
    ap.add_argument('--json', help="Write results to JSON file")
    ap.add_argument('--csv', help="Write results to CSV file")
    ap.add_argument('--rate', type=float, default=0.0, help="Sleep seconds between connection attempts (rate-limit)")
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    ports = parse_ports(args.ports, args.start, args.end)
    if not ports:
        print("No ports to scan. Check --ports or --start/--end values.")
        return

    print(f"Scanning {args.host} ports: {ports[0]}-{ports[-1]} ({len(ports)} ports) with {args.workers} workers")

    tasks = [(args.host, p, args.timeout, args.banner) for p in ports]
    results = []

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_to_port = {ex.submit(scan_port, t): t[1] for t in tasks}
        completed = 0
        for fut in as_completed(future_to_port):
            port = future_to_port[fut]
            try:
                res = fut.result()
            except Exception as e:
                if args.verbose:
                    print(f"[!] error scanning {port}: {e}")
                res = {"port": port, "open": False, "banner": ""}
            results.append(res)
            completed += 1
            if args.verbose and completed % 50 == 0:
                print(f"[+] Progress: {completed}/{len(ports)} scanned")
            if args.rate:
                time.sleep(args.rate)

    results_sorted = sorted(results, key=lambda r: r["port"])
    open_ports = [r for r in results_sorted if r["open"]]

    elapsed = time.time() - start_time
    print(f"Scan finished in {elapsed:.2f}s. Open ports: {len(open_ports)}")
    for r in open_ports:
        line = f"Port {r['port']}/tcp open"
        if args.banner and r['banner']:
            line += f" — {r['banner']}"
        print(line)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(results_sorted, f, indent=2)
        print(f"Wrote JSON output to {args.json}")

    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["port","open","banner"])
            writer.writeheader()
            for r in results_sorted:
                writer.writerow(r)
        print(f"Wrote CSV output to {args.csv}")

if __name__ == "__main__":
    main()
