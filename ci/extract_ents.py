#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Mach-O 的 LC_CODE_SIGNATURE 里抽出 entitlements，写成 plist 给 ldid -S 用。
用法: python3 extract_ents.py <主二进制> <输出.plist>
"""
import struct, sys, plistlib

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    path, out = sys.argv[1], sys.argv[2]
    d = open(path, 'rb').read()
    ncmds, = struct.unpack_from('<I', d, 16)
    off = 32; cs = None
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == 0x1D:                                  # LC_CODE_SIGNATURE
            cs = struct.unpack_from('<II', d, off + 8)
        off += sz
    if not cs:
        print('[!] 没有 LC_CODE_SIGNATURE'); return 3
    dataoff, datasize = cs
    blob = d[dataoff:dataoff + datasize]
    if struct.unpack_from('>I', blob, 0)[0] != 0xFADE0CC0:
        print('[!] 不是 SuperBlob'); return 4
    n, = struct.unpack_from('>I', blob, 8)
    slots = {}
    for i in range(n):
        t, o = struct.unpack_from('>II', blob, 12 + 8 * i)
        slots[t] = o
    if 5 not in slots:
        print('[!] 没有 entitlements slot'); return 5
    o = slots[5]
    m, l = struct.unpack_from('>II', blob[o:o + 8])
    ent = blob[o + 8:o + l].rstrip(b'\0')
    pl = plistlib.loads(ent)
    with open(out, 'wb') as f:
        f.write(plistlib.dumps(pl, fmt=plistlib.FMT_XML))
    print('[+] 已导出 %d 个 entitlement 键 -> %s' % (len(pl), out))
    return 0

if __name__ == '__main__':
    sys.exit(main())
