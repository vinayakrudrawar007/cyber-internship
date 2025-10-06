#!/usr/bin/env python3
import bcrypt
import argparse

def check_wordlist(hashed_password_b64, wordlist_file):
    stored = hashed_password_b64.strip().encode()  # bcrypt hashed string e.g. b'$2b$12$...'
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f,1):
            word = line.strip().encode()
            if bcrypt.checkpw(word, stored):
                return word.decode()
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--hash', required=True, help="bcrypt hash (for demo / local only)")
    ap.add_argument('--wordlist', required=True)
    args = ap.parse_args()
    found = check_wordlist(args.hash, args.wordlist)
    if found:
        print("Password found:", found)
    else:
        print("No match in wordlist.")
