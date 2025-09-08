#!/usr/bin/env python3
import sys, re, base64, urllib.parse

s = sys.argv[1].strip()

def is_printable(txt):
    return txt and sum(32 <= ord(c) <= 126 or c in "\t\r\n" for c in txt)/len(txt) > 0.9

candidates = []

# Normalize helpers
def strip_spaces_and_prefixes(x):
    x = x.strip()
    x = re.sub(r'(?i)^0x', '', x)          # drop 0x
    x = re.sub(r'[\s:_-]', '', x)          # drop spaces/underscores/colons/dashes
    return x

# 1) HEX (with or without 0x, spaces, colons)
def try_hex(x):
    t = strip_spaces_and_prefixes(x)
    if re.fullmatch(r'(?i)[0-9a-f]+', t) and len(t) % 2 == 0:
        try:
            out = bytes.fromhex(t).decode(errors='ignore')
            if is_printable(out): candidates.append(("hex", out))
        except Exception: pass

# 2) Base64
def try_base64(x):
    t = x.strip().replace("\n","")
    if re.fullmatch(r'[A-Za-z0-9+/=\s]+', t) and len(t) % 4 == 0:
        try:
            out = base64.b64decode(t, validate=True)
            txt = out.decode(errors='ignore')
            if is_printable(txt): candidates.append(("base64", txt))
        except Exception: pass

# 3) Base32
def try_base32(x):
    t = x.strip().upper().replace(" ", "")
    if re.fullmatch(r'[A-Z2-7=]+', t) and len(t) % 8 == 0:
        try:
            out = base64.b32decode(t, casefold=True)
            txt = out.decode(errors='ignore')
            if is_printable(txt): candidates.append(("base32", txt))
        except Exception: pass

# 4) Binary (8-bit groups or continuous stream)
def try_binary(x):
    # spaced groups
    if re.fullmatch(r'(?:[01]{8}\s+)*[01]{8}', x.strip()):
        bits = x.replace(" ", "")
    else:
        bits = re.sub(r'\s', '', x)
        if not re.fullmatch(r'[01]+', bits) or len(bits) % 8 != 0:
            return
    try:
        out = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        txt = out.decode(errors='ignore')
        if is_printable(txt): candidates.append(("binary(8b)", txt))
    except Exception: pass

# 5) URL percent-encoding
def try_url(x):
    if "%" in x:
        try:
            txt = urllib.parse.unquote_plus(x)
            if txt != x and is_printable(txt): candidates.append(("url-encoded", txt))
        except Exception: pass

# 6) Decimal or Octal ASCII codes (space/comma-separated)
def try_num_ascii(x):
    parts = re.split(r'[\s,]+', x.strip())
    if all(re.fullmatch(r'\d+', p or "") for p in parts) and len(parts) > 1:
        # decimal attempt
        try:
            bs = bytes(int(p) for p in parts if p != "")
            txt = bs.decode(errors='ignore')
            if is_printable(txt): candidates.append(("ascii-decimal", txt))
        except Exception: pass
        # octal attempt (e.g., 141 142 143)
        try:
            bs = bytes(int(p, 8) for p in parts if p != "")
            txt = bs.decode(errors='ignore')
            if is_printable(txt): candidates.append(("ascii-octal", txt))
        except Exception: pass

# 7) Quick ROT/Shift (common Caesar shifts)
def try_rot(x):
    # Only try if input looks like letters/spaces
    if not re.fullmatch(r'[A-Za-z\s\.\,\!\?\-\_\'"]{3,}', x.strip()):
        return
    def shift(t, k):
        out=[]
        for ch in t:
            if 'a' <= ch <= 'z':
                out.append(chr((ord(ch)-97+k)%26 + 97))
            elif 'A' <= ch <= 'Z':
                out.append(chr((ord(ch)-65+k)%26 + 65))
            else:
                out.append(ch)
        return ''.join(out)
    for k in (13, 1, 2, 3, 5, 7, 13, 19, 21, 25):  # include ROT13 and a few common shifts
        txt = shift(x, k)
        if is_printable(txt) and re.search(r'[aeiouAEIOU]', txt):
            candidates.append((f"caesar+{k}", txt))
# 8) Atbash
def try_atbash(x):
    def ab(ch):
        if 'a'<=ch<='z': return chr(ord('z')-(ord(ch)-97))
        if 'A'<=ch<='Z': return chr(ord('Z')-(ord(ch)-65))
        return ch
    txt = ''.join(ab(c) for c in x)
    if txt != x and is_printable(txt):
        candidates.append(("atbash", txt))

# 9) Morse code (.- style)
MORSE_TABLE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.' :'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
    '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'
}
def try_morse(x):
    if not re.fullmatch(r'[\.\-/\s]+', x.strip()):
        return
    words = x.strip().replace('/', ' / ').split()
    out=[]
    for w in words:
        if w == '/':
            out.append(' ')
        else:
            out.append(MORSE_TABLE.get(w, '?'))
    txt = ''.join(out)
    if is_printable(txt):
        candidates.append(("morse", txt))
# Pre-transform variants to try before decoding
def variants(x):
    wrev = ' '.join(w[::-1] for w in x.split())
    return [
        ("raw", x),
        ("rev", x[::-1]),
        ("word-rev", wrev),
        ("swap", x.swapcase()),
        ("rot47", rot47(x)),  # defined just below
    ]

def rot47(t):
    out=[]
    for ch in t:
        o=ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o-33+47)%94)))
        else:
            out.append(ch)
    return ''.join(out)

# 10) Base58 (Bitcoin-style alphabet, no checksum required)
_B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c:i for i,c in enumerate(_B58_ALPH)}

def b58decode_to_bytes(t: str):
    t = t.strip().replace(" ", "")
    if not t or any(ch not in _B58_IDX for ch in t):
        return None
    # Count leading '1' (zero bytes)
    n_zeros = len(t) - len(t.lstrip('1'))
    num = 0
    for ch in t:
        num = num * 58 + _B58_IDX[ch]
    # Convert integer to bytes
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 256)
        out.append(rem)
    out = bytes([0])*n_zeros + bytes(reversed(out))
    return out

def try_base58(x):
    t = x.strip()
    if not t or any(ch not in _B58_IDX and not ch.isspace() for ch in t):
        return
    try:
        raw = b58decode_to_bytes(t)
        if raw is None:
            return
        # try text
        txt = raw.decode(errors='ignore')
        if is_printable(txt):
            candidates.append(("base58", txt))
        # also surface hex if looks byte-ish but not very printable
        elif raw and len(raw) <= 64:
            candidates.append(("base58->hex", raw.hex()))
    except Exception:
        pass

# 11) A1Z26 (1->A ... 26->Z). 0 or 27 -> space
def try_a1z26(x):
    s = x.strip()
    # Quick gate: must have mostly digits/separators
    if not re.fullmatch(r'[0-9\s,/\-]+', s):
        return
    out = []
    num = ""
    def flush():
        nonlocal num
        if not num:
            return
        try:
            v = int(num)
        except ValueError:
            v = -1
        if v == 0 or v == 27:
            out.append(' ')
        elif 1 <= v <= 26:
            out.append(chr(ord('A') + v - 1))
        else:
            out.append('?')
        num = ""

    for ch in s:
        if ch.isdigit():
            num += ch
        else:
            flush()
            # treat slash or whitespace as word break
            if ch in '/ ':
                out.append(' ')
            # commas/dashes are just separators (no extra space needed)

    flush()
    txt = ''.join(out)
    # Normalize spaces
    txt = re.sub(r'\s+', ' ', txt).strip()
    if txt and is_printable(txt):
        candidates.append(("a1z26", txt))

# Run detectors over variants
for vname, vx in variants(s):
    before = len(candidates)
    try_hex(vx)
    try_base64(vx)
    try_base32(vx)
    try_binary(vx)
    try_url(vx)
    try_num_ascii(vx)
    try_rot(vx)
    try_atbash(vx)
    try_morse(vx)
    try_base58(vx)   # <-- add
    try_a1z26(vx)   # <-- add
    if len(candidates) > before:
        for i in range(before, len(candidates)):
            kind, txt = candidates[i]
            candidates[i] = (f"{kind} via {vname}", txt)

# De-duplicate & print
seen=set()
if not candidates:
    print("[!] No obvious decode. Try other avenues (e.g., base58, z85, Morse, gzip+base64).")
else:
    for kind, txt in candidates:
        key = (kind, txt)
        if key in seen: continue
        seen.add(key)
        print(f"[{kind}] {txt}")

