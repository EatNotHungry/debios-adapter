#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地自检：确认仓库文件齐全 + 注入器能在你的基础上跑通（不需要网络）"""
import os, sys, shutil, struct, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

need = [
    '.github/workflows/build.yml',
    'src/T3Adapter.m',
    'src/T3Verify.h',
    'ci/inject_dylib.py',
    'ci/extract_ents.py',
    'README.md',
]
print('=== 1) 仓库文件检查 ===')
ok = True
for f in need:
    p = os.path.join(ROOT, f)
    e = os.path.isfile(p)
    print('  %-32s %s%s' % (f, 'OK' if e else '缺失',
                            ('  %d 字节' % os.path.getsize(p)) if e else ''))
    ok &= e

print()
print('=== 2) 注入器干跑（用你打过补丁的 Diss 副本）===')
base = os.path.join(ROOT, '..',
                    '工作室雷达_T3卡密_v7_最终版_待真机验证', 'Payload', 'Diss.app', 'Diss')
base = os.path.abspath(base)
if not os.path.isfile(base):
    print('  [skip] 找不到 %s' % base)
else:
    tmp = os.path.join(HERE, '_selftest.bin')
    shutil.copy2(base, tmp)
    r = subprocess.run([sys.executable, os.path.join(HERE, 'inject_dylib.py'),
                        tmp, '@executable_path/T3Adapter.dylib'],
                       capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    for line in r.stdout.strip().splitlines():
        print('  ' + line)
    if r.returncode == 0:
        d = open(tmp, 'rb').read(0x2000)
        ncmds, scmds = struct.unpack_from('<II', d, 16)
        print('  [OK] 注入后 ncmds=%d sizeofcmds=%d' % (ncmds, scmds))
    os.remove(tmp)

print()
print('=== 3) entitlements 抽取干跑 ===')
if os.path.isfile(base):
    out = os.path.join(HERE, '_selftest_ents.plist')
    r = subprocess.run([sys.executable, os.path.join(HERE, 'extract_ents.py'), base, out],
                       capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    for line in (r.stdout + r.stderr).strip().splitlines():
        print('  ' + line)
    if os.path.isfile(out):
        print('  产物 %d 字节' % os.path.getsize(out))
        os.remove(out)

print()
print('结论:', '仓库完整，可以直接 push' if ok else '有文件缺失，先补齐')
sys.exit(0 if ok else 1)
