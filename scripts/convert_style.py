#!/usr/bin/env python3
"""Minimal convert: indent + cleanup, NO namespace restructuring."""
import os, re, math
from collections import Counter

SRC_ROOT = "/root/tun_engine"
BOM = b'\xef\xbb\xbf'

def discover_files(root):
    result = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ('build', 'build-mingw')]
        for fn in sorted(fns):
            if fn.endswith(('.cpp', '.hpp')):
                result.append(os.path.join(dp, fn))
    return sorted(result)

def _detect_indent_unit(lengths, counts):
    total = sum(counts.values())
    filtered = [l for l, c in counts.items() if l >= 2 and c >= 2 and c / total >= 0.005]
    if len(filtered) < 2:
        sa = sorted(set(lengths))
        if len(sa) >= 2: return max(1, sa[1])
        elif sa: return max(1, min(sa, default=4))
        return 4
    try:
        g = math.gcd(*filtered)
        if g >= 2: return g
    except ValueError: pass
    return max(1, min(filtered, default=4))

def normalize_indent(text):
    lengths = []
    for line in text.split('\n'):
        m = re.match(r'^(\s+)', line)
        if m: lengths.append(len(m.group()))
    if not lengths: return text
    counts = Counter(lengths)
    base = _detect_indent_unit(lengths, counts)
    if base == 0: return text
    ul = sorted(set(lengths))
    known = {}
    for ln in ul:
        r = ln / base
        if abs(r - round(r)) <= 0.5: known[ln] = max(1, round(r))
    for ln in ul:
        if ln not in known:
            snap = round(ln / base) * base
            known[ln] = known[snap] if snap in known else max(1, round(ln / base))
    out = []
    for line in text.split('\n'):
        m = re.match(r'^(\s*)(.*)', line, re.DOTALL)
        if m and m.group(1):
            wl = len(m.group(1))
            out.append(' ' * known.get(wl, max(1, round(wl / base))) + m.group(2))
        else: out.append(line)
    return '\n'.join(out)

def clean_namespace_comments(text):
    """Replace '} // namespace ...' with bare '}' """
    return re.sub(
        r'^(\s*)\S{0,1}[^}\n]*\}\s*//\s*namespace\b.*$',
        r'\1}',
        text, flags=re.MULTILINE
    )

def _remove_triple_blanks(t):
    while '\n\n\n' in t: t = t.replace('\n\n\n', '\n\n')
    return t

def fix_blank_lines(t):
    t = _remove_triple_blanks(t)
    lines = t.split('\n')
    result = []
    for line in lines:
        s = line.strip()
        if s in ('public:', 'private:', 'protected:'):
            k = len(result) - 1
            while k >= 0 and result[k].strip() == '': k -= 1
            if k < 0 or result[k].strip():
                if result and result[-1].strip() != '': result.append('')
        result.append(line)
    return _remove_triple_blanks('\n'.join(result))

def ensure_bom(d): return d if d[:3] == BOM else BOM + d
def ensure_lf(raw):
    h = False
    if b'\r\n' in raw: raw = raw.replace(b'\r\n', b'\n'); h = True
    if b'\r' in raw: raw = raw.replace(b'\r', b'\n'); h = True
    return raw, h

def add_missing_bom(path):
    with open(path, 'rb') as f: raw = f.read()
    if raw[:3] != BOM:
        with open(path, 'wb') as f: f.write(BOM + raw)
        return True
    return False

def transform(text):
    text = normalize_indent(text)
    text = clean_namespace_comments(text)
    text = fix_blank_lines(text)
    text = _remove_triple_blanks(text)
    return text

def process_file(path):
    with open(path, 'rb') as f: raw = f.read()
    raw, _ = ensure_lf(raw); raw = ensure_bom(raw)
    text = raw[3:].decode('utf-8')
    transformed = transform(text)
    new_raw = BOM + transformed.encode('utf-8')
    if new_raw != raw:
        with open(path, 'wb') as f: f.write(new_raw)
        return True
    return False

def main():
    files = discover_files(SRC_ROOT)
    print(f"Found {len(files)} source files")
    bc, sc = 0, 0
    for path in files:
        rel = os.path.relpath(path, SRC_ROOT); ch = False
        if add_missing_bom(path): bc += 1; ch = True
        if process_file(path):
            sc += 1
            print(f"  {'[style+]' if ch else '[style]'} {rel}")
    print(f"\nDone: {sc} style-transformed, {bc} BOM-added")

if __name__ == '__main__':
    main()
