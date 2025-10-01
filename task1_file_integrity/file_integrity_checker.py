#!/usr/bin/env python3
"""
Simple File Integrity Checker
Usage:
  python file_integrity_checker.py baseline ./folder baseline.json
  python file_integrity_checker.py compare ./folder baseline.json
"""
import hashlib, json, os, argparse

def compute_hash(path, algo='sha256'):
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def make_baseline(folder, outfile, algo='sha256'):
    baseline = {}
    folder = os.path.abspath(folder)
    for root, dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            baseline[rel] = compute_hash(full, algo)
    with open(outfile, 'w') as f:
        json.dump({'algo': algo, 'files': baseline}, f, indent=2)
    print(f"Baseline saved to {outfile} ({len(baseline)} files)")

def compare_baseline(folder, baseline_file):
    folder = os.path.abspath(folder)
    with open(baseline_file) as f:
        data = json.load(f)
    algo = data.get('algo', 'sha256')
    old_files = data.get('files', {})
    new_files = {}
    for root, dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            new_files[rel] = compute_hash(full, algo)

    modified = [f for f in new_files if f in old_files and new_files[f] != old_files[f]]
    added = [f for f in new_files if f not in old_files]
    removed = [f for f in old_files if f not in new_files]

    print("Modified:", len(modified))
    for f in modified: print("  M", f)
    print("Added:", len(added))
    for f in added: print("  +", f)
    print("Removed:", len(removed))
    for f in removed: print("  -", f)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['baseline','compare'])
    ap.add_argument('folder')
    ap.add_argument('file')
    ap.add_argument('--algo', default='sha256')
    args = ap.parse_args()
    if args.mode == 'baseline':
        make_baseline(args.folder, args.file, args.algo)
    else:
        compare_baseline(args.folder, args.file)
