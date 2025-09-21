#!/usr/bin/env python3
"""
windows_hash_crack.py  (streaming, multi-wordlist, sequential)

- Accepts multiple -w/--wordlist files OR --wordlist-dir to pick up many files.
- Streams each wordlist file one by one (no full-file load into memory).
- Uses ProcessPoolExecutor.map(..., chunksize=...) for stable multiprocessing.
- Keeps NT (MD4) cracking built-in; LM (DES) enabled if pycryptodome is installed.
"""

import argparse
import sys
import os
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from typing import Iterator, Tuple, Optional

# --- Minimal MD4 implementation (same as earlier) ---
def _leftrotate(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def md4(data: bytes) -> bytes:
    orig_len_bits = (8 * len(data)) & 0xffffffffffffffff
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += orig_len_bits.to_bytes(8, byteorder='little')
    A = 0x67452301; B = 0xEFCDAB89; C = 0x98BADCFE; D = 0x10325476
    for i in range(0, len(data), 64):
        X = [int.from_bytes(data[i + j:i + j + 4], 'little') for j in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D
        # Round 1
        for j in range(16):
            s = [3,7,11,19][j % 4]
            if j % 4 == 0:
                k = (A + ((B & C) | (~B & D)) + X[j]) & 0xFFFFFFFF
                A = _leftrotate(k, s)
            elif j % 4 == 1:
                k = (D + ((A & B) | (~A & C)) + X[j]) & 0xFFFFFFFF
                D = _leftrotate(k, s)
            elif j % 4 == 2:
                k = (C + ((D & A) | (~D & B)) + X[j]) & 0xFFFFFFFF
                C = _leftrotate(k, s)
            else:
                k = (B + ((C & D) | (~C & A)) + X[j]) & 0xFFFFFFFF
                B = _leftrotate(k, s)
        # Round 2
        idxs = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
        for j in range(16):
            s = [3,5,9,13][j % 4]
            idx = idxs[j]
            # use explicit formula (same as earlier)
            if j % 4 == 0:
                k = (A + ((B & C) | (B & D) | (C & D)) + X[idx] + 0x5A827999) & 0xFFFFFFFF
                A = _leftrotate(k, s)
            elif j % 4 == 1:
                k = (D + ((A & B) | (A & C) | (B & C)) + X[idx] + 0x5A827999) & 0xFFFFFFFF
                D = _leftrotate(k, s)
            elif j % 4 == 2:
                k = (C + ((D & A) | (D & B) | (A & B)) + X[idx] + 0x5A827999) & 0xFFFFFFFF
                C = _leftrotate(k, s)
            else:
                k = (B + ((C & D) | (C & A) | (D & A)) + X[idx] + 0x5A827999) & 0xFFFFFFFF
                B = _leftrotate(k, s)
        # Round 3
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for j in range(16):
            s = [3,9,11,15][j % 4]
            idx = order[j]
            k = (A + (B ^ C ^ D) + X[idx] + 0x6ED9EBA1) & 0xFFFFFFFF
            A = _leftrotate(k, s)
            A, B, C, D = D, A, B, C
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF
    return (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
            C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))

def nt_hash(password: str) -> str:
    return md4(password.encode('utf-16-le')).hex().upper()

# --- Optional LM (DES) if pycryptodome is available ---
try:
    from Crypto.Cipher import DES
    HAVE_DES = True
except Exception:
    HAVE_DES = False

def _odd_parity(byte):
    b = byte & 0xFE
    ones = bin(b).count('1')
    return b | (0 if ones % 2 else 1)

def _create_des_key_from_7bytes(b7: bytes) -> bytes:
    key = bytearray(8)
    key[0] = b7[0] & 0xFE
    key[1] = ((b7[0] << 7) | (b7[1] >> 1)) & 0xFE
    key[2] = ((b7[1] << 6) | (b7[2] >> 2)) & 0xFE
    key[3] = ((b7[2] << 5) | (b7[3] >> 3)) & 0xFE
    key[4] = ((b7[3] << 4) | (b7[4] >> 4)) & 0xFE
    key[5] = ((b7[4] << 3) | (b7[5] >> 5)) & 0xFE
    key[6] = ((b7[5] << 2) | (b7[6] >> 6)) & 0xFE
    key[7] = (b7[6] << 1) & 0xFE
    for i in range(8):
        key[i] = _odd_parity(key[i])
    return bytes(key)

LM_MAGIC = b"KGS!@#$%"

def lm_hash(password: str) -> str:
    if not HAVE_DES:
        raise RuntimeError("pycryptodome not installed; LM disabled")
    pw = password.upper().encode('ascii', errors='ignore')
    if len(pw) > 14: pw = pw[:14]
    else: pw = pw.ljust(14, b'\x00')
    k1 = _create_des_key_from_7bytes(pw[:7])
    k2 = _create_des_key_from_7bytes(pw[7:14])
    c1 = DES.new(k1, DES.MODE_ECB).encrypt(LM_MAGIC)
    c2 = DES.new(k2, DES.MODE_ECB).encrypt(LM_MAGIC)
    return (c1 + c2).hex().upper()

# --- Candidate generation ---
def generate_variants(base, transforms, prefixes, suffixes):
    out = set()
    for t in transforms:
        if t == 'orig': cand = base
        elif t == 'lower': cand = base.lower()
        elif t == 'upper': cand = base.upper()
        elif t == 'title': cand = base.title()
        elif t == 'capitalize': cand = base.capitalize()
        else: cand = base
        out.add(cand)
        for p in prefixes: out.add(p + cand)
        for s in suffixes: out.add(cand + s)
    return out

def try_candidate(candidate, target_lm, target_nt, want_lm, want_nt):
    found_lm = None
    found_nt = None
    if want_lm and HAVE_DES:
        try:
            if lm_hash(candidate) == target_lm:
                found_lm = candidate
        except Exception:
            pass
    if want_nt:
        if nt_hash(candidate) == target_nt:
            found_nt = candidate
    return found_lm, found_nt

# Worker receives a tuple with context + base word
def worker_task(args_tuple):
    base, want_lm, want_nt, target_lm, target_nt, transforms, prefixes, suffixes = args_tuple
    for cand in generate_variants(base, transforms, prefixes, suffixes):
        flm, fnt = try_candidate(cand, target_lm, target_nt, want_lm, want_nt)
        if flm or fnt:
            # Return the candidate and which matched
            return (base, cand, bool(flm), bool(fnt))
    return (None, None, False, False)

# --- streaming helpers ---
def words_from_file(path: Path) -> Iterator[str]:
    with path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.rstrip('\n\r')
            if s:
                yield s

def tasks_for_file(path: Path, want_lm: bool, want_nt: bool, lm_target: Optional[str], nt_target: Optional[str],
                   transforms, prefixes, suffixes) -> Iterator[Tuple]:
    # yield one task tuple per base word (for this file)
    for w in words_from_file(path):
        yield (w, want_lm, want_nt, lm_target, nt_target, transforms, prefixes, suffixes)

# --- CLI & runner ---
def parse_args():
    p = argparse.ArgumentParser(description="Crack LM:NTLM hash pairs using multiple streaming wordlists.")
    p.add_argument('-H','--hashes', help="Single hash (LM:NT) or multiple hashes separated by ';' or newlines", required=True)
    p.add_argument('-w','--wordlist', action='append', help="Path to a wordlist file. Can be used repeatedly.", default=[])
    p.add_argument('--wordlist-dir', help="Directory containing wordlist files (will glob *.txt by default)")
    p.add_argument('-p','--processes', type=int, default=max(1, (os.cpu_count() or 1) - 1))
    p.add_argument('--singleproc', action='store_true', help="Run single-threaded (no multiprocessing)")
    p.add_argument('--chunksize', type=int, default=2000, help="Chunksize for executor.map")
    p.add_argument('--suffixes', default="123,1,01", help="Comma-separated suffixes")
    p.add_argument('--prefixes', default="", help="Comma-separated prefixes")
    p.add_argument('--no-transforms', action='store_true', help="Disable transforms (only original word)")
    p.add_argument('--stop-on-first', action='store_true', help="Stop when the first match is found")
    return p.parse_args()

def normalize_pair(pair_str):
    pair_str = pair_str.strip()
    if ':' in pair_str:
        lm, nt = pair_str.split(':',1)
        return lm.strip().upper(), nt.strip().upper()
    else:
        return None, pair_str.strip().upper()

def main():
    args = parse_args()

    # Build list of wordlist files to process (in the order specified)
    files = []
    for w in args.wordlist:
        p = Path(w).expanduser()
        if p.exists() and p.is_file():
            files.append(p)
        else:
            print(f"Warning: wordlist not found/skipping: {w}", file=sys.stderr)

    if args.wordlist_dir:
        d = Path(args.wordlist_dir).expanduser()
        if d.exists() and d.is_dir():
            # default glob: *.txt (you can change if needed)
            txts = sorted(d.glob('*.txt'))
            files.extend(txts)
        else:
            print(f"Warning: wordlist-dir not found/ignored: {args.wordlist_dir}", file=sys.stderr)

    if not files:
        print("No valid wordlist files provided. Use -w or --wordlist-dir.", file=sys.stderr)
        sys.exit(1)

    # parse hashes (support multiple by ; or newline)
    pairs = []
    for pstr in args.hashes.split(';'):
        s = pstr.strip()
        if s:
            pairs.append(s)

    if not pairs:
        print("No hashes provided.", file=sys.stderr); sys.exit(1)

    suffixes = [s for s in args.suffixes.split(',') if s != ""]
    prefixes = [p for p in args.prefixes.split(',') if p != ""]

    transforms = ['orig'] if args.no_transforms else ['orig','lower','upper','title','capitalize']

    print(f"Using {len(files)} wordlist file(s). Processes: {args.processes}. Chunksize: {args.chunksize}")
    if not HAVE_DES:
        print("NOTE: pycryptodome not found; LM cracking disabled. Install: pip install pycryptodome")

    # For each target pair, run sequentially over files until found or exhausted
    for pair in pairs:
        lm_target, nt_target = normalize_pair(pair)
        want_lm = lm_target is not None
        want_nt = nt_target is not None
        if lm_target: lm_target = lm_target.upper()
        if nt_target: nt_target = nt_target.upper()
        print(f"\nTarget: LM={(lm_target or '<none>')}  NT={(nt_target or '<none>')}")
        found_any = None

        # process files sequentially
        for wf in files:
            print(f"Processing wordlist: {wf} ...")
            # build a generator of tasks for this file
            tasks_iter = tasks_for_file(wf, want_lm, want_nt, lm_target, nt_target, transforms, prefixes, suffixes)

            if args.singleproc or args.processes <= 1:
                try:
                    for t in tasks_iter:
                        res = worker_task(t)
                        base, cand, flm, fnt = res
                        if cand:
                            print(f"[FOUND] file={wf.name} base={base} cand={cand} LM={flm} NT={fnt}")
                            found_any = (wf, base, cand, flm, fnt)
                            break
                except KeyboardInterrupt:
                    print("\nInterrupted (singleproc). Exiting.")
                    sys.exit(1)
            else:
                # multiprocessing streaming map
                try:
                    with ProcessPoolExecutor(max_workers=args.processes) as exe:
                        for res in exe.map(worker_task, tasks_iter, chunksize=args.chunksize):
                            base, cand, flm, fnt = res
                            if cand:
                                print(f"[FOUND] file={wf.name} base={base} cand={cand} LM={flm} NT={fnt}")
                                found_any = (wf, base, cand, flm, fnt)
                                if args.stop_on_first:
                                    # shutdown without waiting for other workers to finish current chunks
                                    exe.shutdown(wait=False)
                                break
                except KeyboardInterrupt:
                    print("\nInterrupted (multiprocess). Exiting.")
                    exe.shutdown(wait=False)
                    sys.exit(1)
                except Exception as e:
                    print("Error during multiprocessing run:", e, file=sys.stderr)

            if found_any:
                print("Match found — stopping further files for this target.")
                break
            else:
                print(f"Finished {wf.name} — no match; moving to next file.")

        if not found_any:
            print("No matches found for this target across provided files.")
        else:
            wf, base, cand, flm, fnt = found_any
            print(f"Summary for target: matched in file {wf.name}: candidate='{cand}' LM={flm} NT={fnt}")

    print("\nAll targets processed. Exiting.")

if __name__ == "__main__":
    main()
