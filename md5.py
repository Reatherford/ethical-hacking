#!/usr/bin/env python3
"""
hash_cracker.py — simple educational wordlist-based hash cracker
Supports MD5 and NTLM (MD4 over UTF-16LE). Includes basic mangling.

Usage examples:
  python3 hash_cracker.py --hash 68a96446a5afb4ab69a2d15091771e39 --type md5 \
      --wordlist /usr/share/wordlists/rockyou.txt

  # Auto-try MD5 then NTLM if type is ambiguous (32 hex chars)
  python3 hash_cracker.py -H 68a96446a5afb4ab69a2d15091771e39 --type auto \
      -w rockyou.txt --mangle

  # Read the hash from a file (first non-empty line)
  python3 hash_cracker.py --hash-file hash.txt -t auto -w rockyou.txt
"""

import argparse
import hashlib
import os
import re
import sys
from typing import Iterable, Iterator, List

# ---------- Minimal pure-Python MD4 (for NTLM) ----------
# Adapted from RFC 1320 reference-style implementations (educational)
# This keeps the script dependency-free for NTLM support.

# Left rotate 32-bit integer x by n bits
def _rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def _md4_F(x, y, z): return (x & y) | (~x & z)
def _md4_G(x, y, z): return (x & y) | (x & z) | (y & z)
def _md4_H(x, y, z): return x ^ y ^ z

def md4(data: bytes) -> bytes:
    # Initialize state
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    # Pre-processing
    orig_len_bits = (len(data) * 8) & 0xffffffffffffffff
    data += b"\x80"
    while (len(data) % 64) != 56:
        data += b"\x00"
    data += orig_len_bits.to_bytes(8, "little")

    # Process 512-bit chunks
    for i in range(0, len(data), 64):
        X = list(int.from_bytes(data[i + 4*j:i + 4*j + 4], "little") for j in range(16))
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        s = [3, 7, 11, 19]
        for j in range(0, 16, 4):
            A = _rotl32((A + _md4_F(B, C, D) + X[j+0]) & 0xffffffff, s[0])
            D = _rotl32((D + _md4_F(A, B, C) + X[j+1]) & 0xffffffff, s[1])
            C = _rotl32((C + _md4_F(D, A, B) + X[j+2]) & 0xffffffff, s[2])
            B = _rotl32((B + _md4_F(C, D, A) + X[j+3]) & 0xffffffff, s[3])

        # Round 2
        s = [3, 5, 9, 13]
        for j in [0, 4, 8, 12]:
            A = _rotl32((A + _md4_G(B, C, D) + X[j+0] + 0x5a827999) & 0xffffffff, s[0])
            D = _rotl32((D + _md4_G(A, B, C) + X[j+1] + 0x5a827999) & 0xffffffff, s[1])
            C = _rotl32((C + _md4_G(D, A, B) + X[j+2] + 0x5a827999) & 0xffffffff, s[2])
            B = _rotl32((B + _md4_G(C, D, A) + X[j+3] + 0x5a827999) & 0xffffffff, s[3])

        # Round 3
        s = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(0, 16, 4):
            k0, k1, k2, k3 = order[j:j+4]
            A = _rotl32((A + _md4_H(B, C, D) + X[k0] + 0x6ed9eba1) & 0xffffffff, s[0])
            D = _rotl32((D + _md4_H(A, B, C) + X[k1] + 0x6ed9eba1) & 0xffffffff, s[1])
            C = _rotl32((C + _md4_H(D, A, B) + X[k2] + 0x6ed9eba1) & 0xffffffff, s[2])
            B = _rotl32((B + _md4_H(C, D, A) + X[k3] + 0x6ed9eba1) & 0xffffffff, s[3])

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return A.to_bytes(4, "little") + B.to_bytes(4, "little") + C.to_bytes(4, "little") + D.to_bytes(4, "little")


# ---------- Hash helpers ----------

def md5_hex(pw_bytes: bytes) -> str:
    return hashlib.md5(pw_bytes).hexdigest()

def ntlm_hex(pw_str: str) -> str:
    # NTLM = MD4(UTF-16LE(password))
    return md4(pw_str.encode("utf-16le")).hex()

def is_hex32(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", s))

# ---------- Mangling (simple, fast, built-in) ----------

LEET_MAP = {
    'a': ['a', '@', '4'],
    'e': ['e', '3'],
    'i': ['i', '1', '!'],
    'o': ['o', '0'],
    's': ['s', '5', '$'],
    't': ['t', '7'],
}

SUFFIXES = ["", "1", "123", "!", "!", "2024", "2025", "01", "07", "99"]

def basic_leetspeak(s: str, max_variants: int = 16) -> List[str]:
    """Generate a few leet variants without exploding combinatorics."""
    variants = set([s])
    # Replace at most 2 positions to keep it small
    lowers = s.lower()
    positions = [i for i, ch in enumerate(lowers) if ch in LEET_MAP]
    positions = positions[:4]  # cap scan window
    for i, pos in enumerate(positions):
        current = list(variants)
        for base in current:
            ch = base[pos]
            key = ch.lower()
            if key in LEET_MAP:
                for sub in LEET_MAP[key]:
                    cand = base[:pos] + sub + base[pos+1:]
                    variants.add(cand)
                    if len(variants) >= max_variants:
                        return list(variants)
    return list(variants)

def mangle_candidates(word: str) -> List[str]:
    cands = set()
    # base forms
    cands.add(word)
    cands.add(word.capitalize())
    cands.add(word.upper())
    # leet variants on the lowercase
    for v in basic_leetspeak(word.lower()):
        cands.add(v)
        cands.add(v.capitalize())
    # append common suffixes
    out = set()
    for w in cands:
        for suf in SUFFIXES:
            out.add(w + suf)
    return list(out)

# ---------- Core cracking ----------

def try_md5(target_hex: str, wordlist_path: str, encoding: str, mangle: bool) -> str:
    with open(wordlist_path, "rb") as f:
        for raw in f:
            pw = raw.rstrip(b"\r\n")
            if not pw:
                continue
            if not mangle:
                if md5_hex(pw) == target_hex:
                    return pw.decode(errors="ignore")
            else:
                base = pw.decode(encoding, errors="ignore")
                for cand in mangle_candidates(base):
                    if md5_hex(cand.encode(encoding)) == target_hex:
                        return cand
    return ""

def try_ntlm(target_hex: str, wordlist_path: str, encoding: str, mangle: bool) -> str:
    with open(wordlist_path, "rb") as f:
        for raw in f:
            pw = raw.rstrip(b"\r\n")
            if not pw:
                continue
            base = pw.decode(encoding, errors="ignore")
            if not mangle:
                if ntlm_hex(base) == target_hex:
                    return base
            else:
                for cand in mangle_candidates(base):
                    if ntlm_hex(cand) == target_hex:
                        return cand
    return ""

def load_hash_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            h = line.strip()
            if h:
                return h
    raise ValueError("No non-empty hash found in file")

def main():
    ap = argparse.ArgumentParser(description="Educational wordlist hash cracker (MD5 / NTLM).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--hash", help="Target hash (hex).")
    g.add_argument("--hash-file", help="Read the (first) hash from a file.")
    ap.add_argument("-t", "--type", choices=["md5", "ntlm", "auto"], default="auto",
                    help="Hash type (default: auto = try MD5 then NTLM for 32-hex).")
    ap.add_argument("-w", "--wordlist", required=True,
                    help="Path to wordlist (e.g., /usr/share/wordlists/rockyou.txt).")
    ap.add_argument("--encoding", default="utf-8", help="Wordlist decoding (default: utf-8).")
    ap.add_argument("--mangle", action="store_true", help="Apply simple built-in mangling.")
    ap.add_argument("--quiet", action="store_true", help="Reduce output verbosity.")
    args = ap.parse_args()

    if args.hash:
        target = args.hash.strip().lower()
    else:
        target = load_hash_from_file(args.hash_file).lower()

    if not is_hex32(target):
        print(f"[!] This script expects a 32-hex hash for MD5/NTLM. Got: {target}", file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        print(f"[i] Target: {target}")
        print(f"[i] Type:   {args.type}")
        print(f"[i] Wordlist: {args.wordlist}")
        print(f"[i] Mangling: {'on' if args.mangle else 'off'}")
        print("--------------------------------------------------")

    cracked = ""

    if args.type in ("md5", "auto"):
        if not args.quiet:
            print("[*] Trying MD5...")
        cracked = try_md5(target, args.wordlist, args.encoding, args.mangle)
        if cracked:
            print(f"[+] CRACKED (MD5): {cracked}")
            sys.exit(0)

    if args.type in ("ntlm", "auto"):
        if not args.quiet:
            print("[*] Trying NTLM...")
        cracked = try_ntlm(target, args.wordlist, args.encoding, args.mangle)
        if cracked:
            print(f"[+] CRACKED (NTLM): {cracked}")
            sys.exit(0)

    print("[-] Not found in the provided wordlist with current settings.")
    sys.exit(1)

if __name__ == "__main__":
    main()

