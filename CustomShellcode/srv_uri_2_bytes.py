"""
's' is the uri extracted from msfvenom stager.

Replace the existing string, and run:

    python3 srv_uri_2_bytes.py

then paste the generated code to your source, and feel free to

modify anything as needed.
"""

import math
import sys

if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <URI String>')
    sys.exit(-1)

def reverse(string):
    string = string[::-1]
    return string

s = sys.argv[1]

if len(s) == 0:
    sys.exit(-1)

r = len(s) % 8

print(f'\n[*]Original URI string:\n\n{s}\n'.expandtabs(4))

print(f'[*]Reversed URI string:\n\n{reverse(s)}\n'.expandtabs(4))

print(f'[*]Remainder is: {r}\n')

print('[*]Generated instructions:\n'.expandtabs(4))

rs = reverse(s)
l = '0x'
i = 0
n = 0

if r:
    rs_1 = rs[:r]
    for c in rs_1:
        i += 1
        l += hex(ord(c))[2:]
    print(f'"\tmov rax, {l}\t\t;"'.expandtabs(4))
    print('"\tpush rax\t\t\t\t\t\t;"'.expandtabs(4))
    l = '0x'
    i = 0
    rs = rs[r:]

if len(rs) > 0:
    for c in rs:
        i += 1
        l += hex(ord(c))[2:]
        if i % 8 == 0:
            print(f'"\tmov rax, {l}\t\t;"'.expandtabs(4))
            print('"\tpush rax\t\t\t\t\t\t;"'.expandtabs(4))
            l = '0x'

    n = math.ceil(i / 8) if i >= 8 else 1

n += 1 if r else 0

print(f"\n[*]Done! Total byte lines: {n}\n[*]Need to clean up extra {hex(n * 8)} bytes of stack space\n")

