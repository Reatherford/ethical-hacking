#!/usr/bin/env python3
"""
rsa_crack_and_decode.py — NCL-friendly RSA decryptor with instructional output.

What it does (step by step):
  1) Parse inputs (n,e,c[]) OR (p,q,e,c[]).
  2) If only n is given, factor n -> p, q (trial division; small Pollard's Rho fallback).
  3) Compute phi(n) = (p-1)*(q-1) and verify gcd(e, phi) == 1.
  4) Compute private exponent d = e^{-1} mod phi(n).
  5) Decrypt each ciphertext block m_i = c_i^d mod n.
  6) Attempt several decodings to quickly reveal human-readable text:
       - ASCII (per-block bytes, and big-endian per-block join)
       - A1Z26 (1→A..26→Z), and 0→A..25→Z
       - Packed 2×2 A1Z26 (per-block: 4 digits -> two letters)
       - Base-27 (0=space, 1..26=A..Z) on each block
  7) Score candidates by "printable/alpha/space" ratio and display best first.

Usage examples:
  python3 rsa_crack_and_decode.py --n 1079 --e 43 --c "996 894 379 631 894 82 379 852 631 677 677 194 893"
  python3 rsa_crack_and_decode.py --p 13 --q 83 --e 43 --c "996,894,379,631,894,82,379,852,631,677,677,194,893"
"""

import argparse
import math
import random
from typing import List, Tuple, Optional

# -----------------------------
# Utility math: gcd, egcd, modinv
# -----------------------------
def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm: returns (g, x, y) with g=gcd(a,b) and ax+by=g."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    """Modular inverse a^{-1} mod m. Raises if gcd(a,m) != 1."""
    # Prefer Python 3.8+ built-in if available; fall back otherwise.
    try:
        return pow(a, -1, m)  # type: ignore[arg-type]
    except TypeError:
        g, x, _ = egcd(a, m)
        if g != 1:
            raise ValueError(f"No modular inverse for a={a} mod m={m} (gcd={g})")
        return x % m

# -----------------------------
# Factoring helpers
# -----------------------------
def trial_factor(n: int) -> Optional[Tuple[int, int]]:
    """Quick trial division up to sqrt(n). Good for small challenge moduli."""
    if n % 2 == 0:
        return (2, n // 2)
    r = int(math.isqrt(n))
    for f in range(3, r + 1, 2):
        if n % f == 0:
            p, q = f, n // f
            return (min(p, q), max(p, q))
    return None

def _rho_f(n: int, x: int, c: int) -> int:
    # Pollard’s Rho polynomial; (x^2 + c) mod n
    return (x * x + c) % n

def pollards_rho(n: int) -> Optional[int]:
    """Tiny Pollard’s Rho to grab a nontrivial factor for moderate n."""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    # Randomized attempts
    for _ in range(20):
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = _rho_f(n, x, c)
            y = _rho_f(n, _rho_f(n, y, c), c)
            d = math.gcd(abs(x - y), n)
            if d == n:
                break
        if d != 1 and d != n:
            return d
    return None

def factor_semiprime(n: int) -> Tuple[int, int]:
    """Factor n into two primes p<=q. Uses trial division then a tiny Pollard’s Rho."""
    # 1) Trial division (fast for small n)
    tq = trial_factor(n)
    if tq:
        p, q = tq
        return (min(p, q), max(p, q))
    # 2) Pollard's Rho fallback
    f = pollards_rho(n)
    if f:
        p, q = f, n // f
        return (min(p, q), max(p, q))
    raise ValueError("Failed to factor n with trial division and small Pollard’s Rho.")

# -----------------------------
# Parsing helpers
# -----------------------------
def parse_ciphertext(s: str) -> List[int]:
    """Accept space/comma/newline separated integers."""
    parts = [x.strip() for x in s.replace(",", " ").split()]
    return [int(x) for x in parts if x]

# -----------------------------
# Decoding helpers (heuristics)
# -----------------------------
ALPHA = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ ")
PRINTABLE = set(chr(i) for i in range(32, 127))

def score_readability(s: str) -> float:
    """Crude score: fraction of chars that are letters/spaces or printable ASCII."""
    if not s:
        return 0.0
    good = sum(1 for ch in s if ch in PRINTABLE)
    alpha = sum(1 for ch in s.upper() if ch in ALPHA)
    # Weighted: printable gets 0.4, alpha/space gets 0.6
    return 0.4 * (good / len(s)) + 0.6 * (alpha / len(s))

def a1z26_decode(nums: List[int], one_based: bool) -> str:
    """1-based: 1->A..26->Z (0 optionally space); 0-based: 0->A..25->Z."""
    out = []
    for n in nums:
        if one_based and 1 <= n <= 26:
            out.append(chr(ord('A') + n - 1))
        elif not one_based and 0 <= n <= 25:
            out.append(chr(ord('A') + n))
        elif one_based and n == 0:
            out.append(' ')
        else:
            out.append('?')
    return ''.join(out)

def ascii_per_block(nums: List[int]) -> str:
    """Interpret each m as a single byte if 32..126 (printable). Otherwise dot."""
    out = []
    for n in nums:
        out.append(chr(n) if 32 <= n <= 126 else '·')
    return ''.join(out)

def ascii_join_big_endian(nums: List[int]) -> str:
    """
    Convert each m to its minimal big-endian bytes and join, then decode as ASCII (errors -> '·').
    Useful when each block encodes multiple ASCII bytes.
    """
    by = b"".join(int(n).to_bytes((int(n).bit_length() + 7) // 8 or 1, "big") for n in nums)
    return ''.join(chr(b) if 32 <= b <= 126 else '·' for b in by)

def packed_2x2(nums: List[int]) -> str:
    """
    Per-block 'AB' packing where the block is 4 digits (e.g., '0812' -> 08->H, 12->L).
    If not 4-digit, we try zero-left-pad to 4 where safe (1..26 constraints).
    """
    out = []
    for n in nums:
        s = str(n)
        if len(s) < 4:
            s = s.zfill(4)  # pad to 4 digits
        if len(s) == 4:
            a, b = int(s[:2]), int(s[2:])
            if 1 <= a <= 26 and 1 <= b <= 26:
                out.append(chr(64 + a) + chr(64 + b))
            else:
                out.append('??')
        else:
            out.append('??')
    return ''.join(out)

def base27_block(nums: List[int]) -> str:
    """
    Base-27 decode per block: 0=space, 1..26=A..Z. If m<27, single char; if 27<=m<27*27,
    decode as two symbols: (m//27, m%27). Otherwise fallback to '?'.
    """
    def sym(v: int) -> str:
        if v == 0:
            return ' '
        if 1 <= v <= 26:
            return chr(64 + v)
        return '?'
    out = []
    for m in nums:
        if 0 <= m < 27:
            out.append(sym(m))
        elif 27 <= m < 27 * 27:
            out.append(sym(m // 27) + sym(m % 27))
        else:
            out.append('??')
    return ''.join(out)

def two_digit_stream(nums: List[int]) -> str:
    """
    Concatenate all blocks as zero-padded to even digits, then parse as 2-digit A1Z26 pairs.
    Example: [1, 23, 504] -> "01 23 504" -> "01 23 0504" -> parse 01|23|05|04.
    """
    cat = ''.join((str(n) if len(str(n)) % 2 == 0 else '0' + str(n)) for n in nums)
    letters = []
    for i in range(0, len(cat), 2):
        chunk = cat[i:i+2]
        if len(chunk) < 2:
            break
        v = int(chunk)
        if 1 <= v <= 26:
            letters.append(chr(64 + v))
        elif v == 0:
            letters.append(' ')
        else:
            letters.append('?')
    return ''.join(letters)

# -----------------------------
# Main solving routine
# -----------------------------
def decrypt_blocks(c_blocks: List[int], d: int, n: int) -> List[int]:
    """RSA core: m_i = c_i^d mod n for each ciphertext block."""
    return [pow(c, d, n) for c in c_blocks]

def attempt_decodings(m_blocks: List[int]) -> List[Tuple[str, str, float]]:
    """
    Try several decoders; return list of (name, decoded_text, score) sorted by score.
    """
    candidates = []
    def add(name: str, text: str):
        candidates.append((name, text, score_readability(text)))

    add("ASCII per-block (one byte if printable)", ascii_per_block(m_blocks))
    add("ASCII join (big-endian bytes of each block)", ascii_join_big_endian(m_blocks))
    add("A1Z26 (1→A..26→Z; 0→space)", a1z26_decode(m_blocks, one_based=True))
    add("A1Z26 (0→A..25→Z)", a1z26_decode(m_blocks, one_based=False))
    add("Packed 2×2 (each block = two letters)", packed_2x2(m_blocks))
    add("Base-27 per block (0=space,1..26=A..Z)", base27_block(m_blocks))
    add("2-digit stream across all blocks (A1Z26)", two_digit_stream(m_blocks))

    # Sort by score (desc) but keep stable ordering for ties
    candidates.sort(key=lambda t: t[2], reverse=True)
    return candidates

def main():
    # --------
    # 1) Parse arguments
    # --------
    ap = argparse.ArgumentParser(description="RSA crack & decode helper (NCL-friendly, commented).")
    ap.add_argument("--n", type=int, help="RSA modulus n (ignored if --p and --q provided)")
    ap.add_argument("--p", type=int, help="Prime p (optional)")
    ap.add_argument("--q", type=int, help="Prime q (optional)")
    ap.add_argument("--e", type=int, required=True, help="Public exponent e")
    ap.add_argument("--c", type=str, required=True,
                    help="Ciphertext blocks (space/comma/newline separated integers)")
    ap.add_argument("--no-factor", action="store_true",
                    help="If set, do NOT try to factor n (require p & q).")
    ap.add_argument("--verbose", "-v", action="store_true", help="More narrations/notes.")
    args = ap.parse_args()

    # --------
    # 2) Parse ciphertext blocks
    # --------
    c_blocks = parse_ciphertext(args.c)
    if not c_blocks:
        raise SystemExit("No ciphertext blocks parsed. Provide integers separated by spaces/commas/newlines.")

    # --------
    # 3) Determine p, q, n
    # --------
    if args.p and args.q:
        p, q = min(args.p, args.q), max(args.p, args.q)
        n = p * q
        if args.n and args.n != n:
            print("[!] Note: provided n does not match p*q; using p*q.")
    else:
        if not args.n:
            raise SystemExit("Provide either (p and q) OR n.")
        n = args.n
        if args.no-factor:
            raise SystemExit("--no-factor set but p and q not provided.")
        # Try to factor n
        if args.verbose:
            print("[*] Factoring n (trial division, then small Pollard’s Rho if needed)...")
        p, q = factor_semiprime(n)

    if p * q != n:
        raise SystemExit("Sanity check failed: p*q != n.")

    # --------
    # 4) Compute phi and private exponent d
    # --------
    phi = (p - 1) * (q - 1)
    g = math.gcd(args.e, phi)
    if g != 1:
        raise SystemExit(f"Invalid RSA parameters: gcd(e, phi(n)) = {g} != 1. Cannot invert e mod phi.")
    d = modinv(args.e, phi)

    # --------
    # 5) Decrypt blocks
    # --------
    m_blocks = decrypt_blocks(c_blocks, d, n)

    # --------
    # 6) Print educational report
    # --------
    print("=== STEP 1: RSA parameters recovered ===")
    print(f"n = {n}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"phi(n) = (p-1)(q-1) = {phi}")
    print(f"e = {args.e}")
    print(f"d = e^(-1) mod phi(n) = {d}")
    print()

    print("=== STEP 2: Ciphertext → Plain-integers (per block) ===")
    for i, (ci, mi) in enumerate(zip(c_blocks, m_blocks), 1):
        print(f"Block {i:02d}: c = {ci:>6}  →  m = c^d mod n = {mi}")
    print()

    # --------
    # 7) Decoding attempts & ranking
    # --------
    print("=== STEP 3: Decoding attempts (ranked by readability) ===")
    candidates = attempt_decodings(m_blocks)
    for name, text, score in candidates:
        print(f"[{score:0.3f}] {name}:")
        print(f"    {text}")
    print()

    # --------
    # 8) Quick tip
    # --------
    print("Tip: If none look right, consider:")
    print("  • Different packing (e.g., base-100 per letter, or per-block big-endian bytes).")
    print("  • Whether blocks should be concatenated before decoding.")
    print("  • Whether additional classical cipher steps (Caesar/Vigenère) are layered afterwards.")
    print("  • Scanning for NCL-like formats (e.g., NCL-XXXX-####).")

if __name__ == "__main__":
    main()

