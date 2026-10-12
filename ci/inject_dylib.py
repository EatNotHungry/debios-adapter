#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把一条 LC_LOAD_DYLIB 加进 Mach-O 主程序（不动任何段数据）。

适用条件：加载命令区后面还有空位 —— 本项目的 Diss 打完 T3Gate 补丁后，命令区
占用到 0x1AC0，而 __TEXT 段第一个 section 的数据从 0x4000 才开始，所以还有
~6.6KB 空位。这样不需要搬移段、不需要重算 chained fixups，改完 ldid -S 重签即可。

用法:
    python3 inject_dylib.py <主二进制> @executable_path/T3Adapter.dylib
"""
import struct, sys, os

LC_SEGMENT_64     = 0x19
LC_LOAD_DYLIB     = 0xC
LC_CODE_SIGNATURE = 0x1D

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    path, dylib_path = sys.argv[1], sys.argv[2]

    d = bytearray(open(path, 'rb').read())
    magic, cputype, cpusubtype, ftype, ncmds, sizeofcmds, flags, res = \
        struct.unpack_from('<IiiIIIII', d, 0)
    if magic != 0xFEEDFACF:
        print('[!] 不是 64 位小端 Mach-O (magic=0x%X)' % magic); return 3

    print('[*] 文件 %s (%d 字节)' % (path, len(d)))
    print('[*] ncmds=%d sizeofcmds=%d flags=0x%X' % (ncmds, sizeofcmds, flags))

    off = 32
    have = False
    sect_starts = []          # 每个段里第一个 section 的文件偏移 -> 头部真实可用上限
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == LC_LOAD_DYLIB:
            no, = struct.unpack_from('<I', d, off + 8)
            e = d.index(b'\0', off + no)
            name = d[off + no:e].decode('utf-8', 'replace')
            if name == dylib_path:
                have = True
        if cmd == LC_SEGMENT_64:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, off + 24)
            nsects, = struct.unpack_from('<I', d, off + 64)
            seg_name = d[off + 8:off + 24].rstrip(b'\0').decode('utf-8', 'replace')
            so = off + 72
            for _j in range(nsects):
                sec_fileoff, = struct.unpack_from('<I', d, so + 48)
                if sec_fileoff > 0:
                    sect_starts.append((sec_fileoff, seg_name,
                                        d[so:so + 16].rstrip(b'\0').decode('utf-8', 'replace')))
                so += 80
        off += sz

    if have:
        print('[=] 已经注入过 %s，无需重复' % dylib_path); return 0

    sect_starts.sort()
    limit = sect_starts[0][0] if sect_starts else None
    if limit is None:
        print('[!] 找不到 section 起点，无法确定头部空位'); return 4
    print('[*] 加载命令区结束于 0x%X，第一个 section 数据从 0x%X 开始（%s,%s）'
          % (32 + sizeofcmds, limit, sect_starts[0][1], sect_starts[0][2]))

    raw = dylib_path.encode('utf-8') + b'\0'
    raw += b'\0' * ((8 - len(raw) % 8) % 8)
    cmdsize = 24 + len(raw)
    if cmdsize % 8:
        pad = 8 - cmdsize % 8
        raw += b'\0' * pad
        cmdsize += pad

    end = 32 + sizeofcmds
    if end + cmdsize > limit:
        print('[!] 头部空位不够：需要 %d 字节，只有 %d 字节' % (cmdsize, limit - end))
        return 5

    lc = struct.pack('<IIIIII', LC_LOAD_DYLIB, cmdsize, 24, 2, 0, 0) + raw
    assert len(lc) == cmdsize

    d[end:end + cmdsize] = lc
    struct.pack_into('<I', d, 16, ncmds + 1)
    struct.pack_into('<I', d, 20, sizeofcmds + cmdsize)
    open(path, 'wb').write(bytes(d))

    print('[+] 已注入 %s' % dylib_path)
    print('    新 ncmds=%d sizeofcmds=%d，命令区到 0x%X' % (ncmds + 1, sizeofcmds + cmdsize, end + cmdsize))
    print('[!] 页哈希已失效，记得 ldid -S 重签')
    return 0

if __name__ == '__main__':
    sys.exit(main())
