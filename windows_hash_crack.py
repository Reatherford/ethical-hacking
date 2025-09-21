#!/usr/bin/env python3
"""
windows_hash_crack_stream.py

Like the previous script but uses streaming ProcessPoolExecutor.map() with a chunksize
to avoid creating millions of futures at once (prevents the multiprocessing IPC/queue
saturation problem that caused your KeyboardInterrupt trace).

Usage example:
  python3 windows_hash_crack_stream.py -H "21259DD63B980471AAD3B435B51404EE:1E43E37B818AB5EDB066EB58CCDC1823" \
    -w "/path/to/pokemon_candidates.txt" -p 4 --stop-on-first

Options:
  --singleproc    : run in the main process (no concurrency)
  --chunksize N   : chunksize passed to executor.map (default 200)
"""
import argparse
import binascii
import hashlib
import sys
import os
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from itertools import islice

# --- minimal MD4 (same as previous) ---
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
            k = ( [A,D,C,B][j%4] + (([B,A,D,C][j%4] & [C,B,A,D][j%4]) | ([B,A,D,C][j%4] & [D,C,B,A][j%4]) | ([C,B,A,D][j%4] & [D,C,B,A][j%4])) + X[idx] + 0x5A827999 ) & 0xFFFFFFFF
            if j % 4 == 0:
                A = _leftrotate(k, s)
            elif j % 4 == 1:
                D = _leftrotate(k, s)
            elif j % 4 == 2:
                C = _leftrotate(k, s)
            else:
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

# (Optional) LM requires pycryptodome — we keep function but disable if not available
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

# --- candidate generation (simple) ---
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

def worker_task(args):
    base_word, want_lm, want_nt, target_lm, target_nt, transforms, prefixes, suffixes = args
    for cand in generate_variants(base_word, transforms, prefixes, suffixes):
        try:
            if want_nt and nt_hash(cand) == target_nt:
                return (cand, True, False)
            if want_lm and HAVE_DES and lm_hash(cand) == target_lm:
                return (cand, False, True)
        except Exception:
            continue
    return (None, False, False)

# --- CLI / runner ---
def load_wordlist(path):
    p = Path(path)
    if not p.exists(): raise FileNotFoundError(path)
    return [line.strip() for line in p.read_text(encoding='utf-8', errors='ignore').splitlines() if line.strip()]

def normalize_pair(pair_str):
    if ':' in pair_str:
        lm, nt = pair_str.split(':',1); return lm.strip().upper(), nt.strip().upper()
    else:
        return None, pair_str.strip().upper()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H','--hashes', help='hash line (LM:NT or NT) or multiple separated by ; or newline')
    parser.add_argument('-hf','--hashfile', help='file with hashes')
    parser.add_argument('-w','--wordlist', required=True)
    parser.add_argument('-p','--processes', type=int, default=max(1, (os.cpu_count() or 1)-1))
    parser.add_argument('--singleproc', action='store_true', help='run single threaded')
    parser.add_argument('--chunksize', type=int, default=200, help='chunksize for executor.map')
    parser.add_argument('--suffixes', default='123,1,01', help='comma list')
    parser.add_argument('--prefixes', default='', help='comma list')
    parser.add_argument('--no-transforms', action='store_true')
    parser.add_argument('--stop-on-first', action='store_true')
    args = parser.parse_args()

    # load targets
    pairs = []
    if args.hashes:
        for p in args.hashes.split(';'):
            if p.strip(): pairs.append(p.strip())
    if args.hashfile:
        for l in Path(args.hashfile).read_text(encoding='utf-8', errors='ignore').splitlines():
            if l.strip(): pairs.append(l.strip())
    if not pairs:
        print("No hashes supplied. Use -H or -hf"); sys.exit(1)

    wordlist = load_wordlist(args.wordlist)
    transforms = ['orig'] if args.no_transforms else ['orig','lower','upper','title','capitalize']
    suffixes = [s for s in args.suffixes.split(',') if s!='']
    prefixes = [p for p in args.prefixes.split(',') if p!='']

    for p in pairs:
        lm_target, nt_target = normalize_pair(p)
        want_lm = lm_target is not None
        want_nt = nt_target is not None
        if not want_lm and not want_nt:
            print("Invalid hash line:", p); continue
        print(f"Target: LM={(lm_target or '<none>')} NT={(nt_target or '<none>')}")
        if args.singleproc or args.processes <= 1:
            # single-threaded loop (safe)
            found = None
            try:
                for base in wordlist:
                    cand, flm, fnt = worker_task((base, want_lm, want_nt, lm_target, nt_target, transforms, prefixes, suffixes))
                    if cand:
                        print(f"[FOUND] {cand} (LM_match={flm} NT_match={fnt})")
                        found = (cand, flm, fnt)
                        if args.stop_on_first:
                            break
                if not found:
                    print("No matches found (singleproc).")
            except KeyboardInterrupt:
                print("\nInterrupted by user (singleproc). Exiting.")
            continue

        # streaming multiprocessing approach
        tasks_iter = ((w, want_lm, want_nt, lm_target, nt_target, transforms, prefixes, suffixes) for w in wordlist)
        found = None
        try:
            with ProcessPoolExecutor(max_workers=args.processes) as exe:
                # exe.map will feed tasks in chunksize and won't create one-future-per-item at submission time
                for res in exe.map(worker_task, tasks_iter, chunksize=args.chunksize):
                    cand, flm, fnt = res
                    if cand:
                        print(f"[FOUND] {cand} (LM_match={flm} NT_match={fnt})")
                        found = (cand, flm, fnt)
                        if args.stop_on_first:
                            # shutdown the executor and break
                            exe.shutdown(wait=False)
                            break
        except KeyboardInterrupt:
            print("\nInterrupted by user (multiprocess). Exiting gracefully.")
        except Exception as e:
            print("Error during multiprocessing run:", e)
        if not found:
            print("No matches found for this target.")

if __name__ == "__main__":
    main()

