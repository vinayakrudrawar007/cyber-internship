#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor
import argparse

def scan_port(host, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except:
        return False

def scan_range(host, start, end, workers=100):
    open_ports = []
    def worker(p):
        if scan_port(host, p):
            open_ports.append(p)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(worker, range(start, end+1))
    return sorted(open_ports)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', required=True)
    ap.add_argument('--start', type=int, default=1)
    ap.add_argument('--end', type=int, default=1024)
    args = ap.parse_args()
    print("Scanning", args.host, args.start, "-", args.end)
    print("Open ports:", scan_range(args.host, args.start, args.end))
