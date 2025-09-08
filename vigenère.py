#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, unicodedata, re
from math import inf

# ---------- Language profiles ----------
EN_FREQ = [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,
           0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,
           2.758,0.978,2.360,0.150,1.974,0.074]
FR_FREQ = [7.636,0.901,3.260,3.669,14.715,1.066,0.866,0.737,7.529,0.613,
           0.049,5.456,2.968,7.095,5.796,2.521,1.362,6.553,7.948,7.244,
           6.311,1.838,0.049,0.427,0.128,0.326]
LANG_FREQ = {"en": EN_FREQ, "fr": FR_FREQ}

STOP_WORDS = {
    "en": {" THE "," AND "," OF "," TO "," IN "," IS "," IT "," YOU "," FOR "," WITH "," A "," I "},
    "fr": {" LE "," LA "," LES "," DE "," DES "," DU "," ET "," EST "," UN "," UNE "," POUR "," QUE "," QUI "}
}

# ---------- Utilities ----------
def strip_accents(s: str) -> str:
    # Remove accents for A–Z analysis, keep punctuation & case
    nfkd = unicodedata.normalize('NFD', s)
    return ''.join(ch for ch in nfkd if not unicodedata.combining(ch))

def alpha_only_upper(s: str) -> str:
    return ''.join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

def chi2_against_lang(counts, total, freq):
    exp = [total * p/100.0 for p in freq]
    chi2 = 0.0
    for i in range(26):
        diff = counts[i] - exp[i]
        chi2 += (diff*diff)/(exp[i] + 1e-9)
    return chi2

def best_shift_for_lang(col_counts, total, freq):
    best_s, best_v = 0, inf
    for s in range(26):
        rotated = [col_counts[(i + s) % 26] for i in range(26)]
        v = chi2_against_lang(rotated, total, freq)
        if v < best_v:
            best_v, best_s = v, s
    return best_s, best_v

def vig_decrypt(ct, key):
    out=[]; j=0; k=[ord(c.lower())-97 for c in key]
    for ch in ct:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch)-base - k[j%len(k)])%26 + base)); j+=1
        else:
            out.append(ch)
    return ''.join(out)

def score_plaintext(pt, lang):
    txt = " " + pt.upper() + " "
    hits = sum(1 for w in STOP_WORDS[lang] if w in txt)
    spaces = pt.count(' ')
    return hits + min(spaces/10.0, 2.0)

# ---------- Core cracker ----------
def vigenere_auto(ct, min_len=2, max_len=12, langs=("en","fr"), top=3):
    ct_noacc = strip_accents(ct)
    alpha = alpha_only_upper(ct_noacc)
    if len(alpha) < 12:
        return []

    results = []
    for lang in langs:
        freq = LANG_FREQ[lang]
        for m in range(min_len, max_len+1):
            cols = [[0]*26 for _ in range(m)]
            counts = [0]*m
            for i, ch in enumerate(alpha):
                j = i % m
                cols[j][ord(ch)-65] += 1
                counts[j] += 1
            shifts=[]; chi_sum=0.0
            for j in range(m):
                if counts[j]==0:
                    shifts.append(0); continue
                s,v = best_shift_for_lang(cols[j], counts[j], freq)
                shifts.append(s); chi_sum += v
            key = ''.join(chr(97+s) for s in shifts)
            pt = vig_decrypt(ct_noacc, key)
            quality = -chi_sum/len(alpha) + 0.5*score_plaintext(pt, lang)
            results.append((quality, lang, key, pt))
    results.sort(reverse=True)
    return results[:top]

def vigenere_with_key(ct, key):
    # Direct decrypt with known key (letters only)
    key = re.sub(r'[^A-Za-z]', '', key)
    if not key:
        raise ValueError("Key must contain at least one letter A–Z.")
    ct_noacc = strip_accents(ct)
    return vig_decrypt(ct_noacc, key.lower())

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(
        description="Vigenère cracker with English/French scoring. Use --key for direct decrypt."
    )
    ap.add_argument("ciphertext", nargs="?", help="Ciphertext (if omitted, read from stdin).")
    ap.add_argument("--key", help="Known Vigenère key (letters only). If supplied, auto-crack is skipped.")
    ap.add_argument("--lang", choices=["en","fr","auto"], default="auto",
                    help="Language model for scoring (default: auto = try en & fr).")
    ap.add_argument("--min-len", type=int, default=2, help="Min key length to try (auto mode).")
    ap.add_argument("--max-len", type=int, default=12, help="Max key length to try (auto mode).")
    ap.add_argument("--top", type=int, default=3, help="Show this many best candidates (auto mode).")
    args = ap.parse_args()

    # Get ciphertext
    if args.ciphertext is None:
        import sys
        ciphertext = sys.stdin.read().rstrip("\n")
    else:
        ciphertext = args.ciphertext

    # Direct decrypt if key is provided
    if args.key:
        pt = vigenere_with_key(ciphertext, args.key)
        print(f"[vigenere key={args.key}] {pt}")
        return

    # Auto-crack
    langs = ("en","fr") if args.lang == "auto" else (args.lang,)
    cands = vigenere_auto(ciphertext, min_len=args.min_len, max_len=args.max_len,
                          langs=langs, top=args.top)
    if not cands:
        print("[!] No plausible candidates found. Try widening key length or different language.")
        return
    for quality, lang, key, pt in cands:
        print(f"[vig lang={lang} key≈{key}] {pt}")

if __name__ == "__main__":
    main()

