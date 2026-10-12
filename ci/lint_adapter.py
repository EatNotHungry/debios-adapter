# -*- coding: utf-8 -*-
"""对 T3Adapter.m 做静态粗检（不编译，只查括号配平 / 关键结构 / objc_msgSend 转换）"""
import re, sys, os

P = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'T3Adapter.m')
P = os.path.abspath(P)
s = open(P, encoding='utf-8').read()

depth = {'{': 0, '(': 0, '[': 0}
pairs = {'}': '{', ')': '(', ']': '['}
i, n, state, line = 0, len(s), None, 1
errs = []
while i < n:
    c = s[i]
    if c == '\n':
        line += 1
    if state == '//':
        if c == '\n': state = None
    elif state == '/*':
        if s[i:i+2] == '*/': state = None; i += 1
    elif state == 'str':
        if c == '\\': i += 1
        elif c == '"': state = None
    elif state == 'chr':
        if c == '\\': i += 1
        elif c == "'": state = None
    else:
        two = s[i:i+2]
        if two == '//': state = '//'; i += 1
        elif two == '/*': state = '/*'; i += 1
        elif c == '"': state = 'str'
        elif c == "'": state = 'chr'
        elif c in '{([': depth[c] += 1
        elif c in '})]':
            depth[pairs[c]] -= 1
            if depth[pairs[c]] < 0:
                errs.append('line %d: 多余的 %s' % (line, c)); depth[pairs[c]] = 0
    i += 1

print('文件:', P)
print('行数: %d   字节: %d' % (s.count('\n') + 1, len(s.encode())))
print('括号配平: {}=%d ()=%d []=%d' % (depth['{'], depth['('], depth['[']))
print('错误:', errs if errs else '无')

print()
print('关键结构:')
for k in ['@interface T3ALockVC', '@implementation T3ALockVC', '@end',
          '__attribute__((constructor))', '#import "T3Verify.h"',
          'UIWindowLevelAlert', 'dispatch_source_create', 'NSDictionaryOfVariableBindings']:
    print('  %-34s %s' % (k, '有' if k in s else '❌ 缺'))

calls = re.findall(r'\)\s*objc_msgSend', s)
casts = re.findall(r'\(void \*\)\s*objc_msgSend', s)
print()
print('objc_msgSend 出现次数: %d   (void *) 转换次数: %d  -> %s'
      % (len(re.findall(r'objc_msgSend', s)), len(casts),
         '全部转换 OK' if len(calls) == len(casts) else '有不齐，需检查'))
for m in re.finditer(r'\(id \(\*\)[^;]*?\)\(void \*\)objc_msgSend', s):
    pass
print()
print('函数签名个数:')
for name in re.findall(r'^\s*(?:static\s+)?[\w\*\s]+?(t3a_\w+)\s*\(', s, re.M):
    pass
print('  t3a_* 函数:', len(set(re.findall(r'\bt3a_\w+', s))), '个不同名字')

sys.exit(1 if (errs or any(depth[k] != 0 for k in depth)) else 0)
