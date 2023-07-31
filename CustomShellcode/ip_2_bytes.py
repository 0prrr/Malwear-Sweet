import sys

if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <IPv4>')
    sys.exit(-1)

def reverse(string):
    string = string[::-1]
    return string

ip = sys.argv[1]

print(f'\n[*]IP address: {ip}')

s_1 = ip[0:8]
s_2 = ip[8:]
print(f'\n[*]First part: {s_1}')
print(f'[*]Second part: {s_2}')

s_1 = reverse(s_1)
s_2 = reverse(s_2)

print(f'\n[*]First reversed part: {s_1}')
print(f'[*]Second reversed part: {s_2}')

print("\n[*]Generated instructions:")

l = '0x'
for c in s_2:
    l += hex(ord(c))[2:]

print()
print(f'"\tmov rax, {l}\t;"')
print('"\tpush rax\t\t\t;"')

l = '0x'
for c in s_1:
    l += hex(ord(c))[2:]

print(f'"\tmov rax, {l}\t;"')
print('"\tpush rax\t\t\t;"')
print()

