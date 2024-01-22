import os
import sys
from ctypes import c_int32, c_int64

def _djb2(msg):
    _hash = c_int64(0xcafebabedeadbeef).value;
    for b in msg:
        if not b:
            continue
        _hash = (((_hash << 0x5) + _hash) + b) & 0xFFFFFFFF
    return f"0x{_hash:02X}"

def _crc32h(msg):
    SEED = c_int32(0xEDBEA93F).value & 0xFFFFFFFF
    i = 0
    crc = c_int32(0xFFFFFFFF).value & 0xFFFFFFFF
    g0, g1, g2, g3, g4, g5, g6, g7 = SEED, SEED >> 1, SEED >> 2, SEED >> 3, SEED >> 4, SEED >> 5, (SEED >> 6) ^ SEED, ((SEED >> 6) ^ SEED) >> 1

    for b in msg:
        if not b:
            continue
        else:
            crc ^= b
            c = (c_int32(~((c_int32(crc << 31).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g7 ^ \
                (c_int32(~((c_int32(crc << 30).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g6 ^ \
                (c_int32(~((c_int32(crc << 29).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g5 ^ \
                (c_int32(~((c_int32(crc << 28).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g4 ^ \
                (c_int32(~((c_int32(crc << 27).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g3 ^ \
                (c_int32(~((c_int32(crc << 26).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g2 ^ \
                (c_int32(~((c_int32(crc << 25).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g1 ^ \
                (c_int32(~((c_int32(crc << 24).value & 0xFFFFFFFF) >> 31) + 1).value & 0xFFFFFFFF) & g0
            crc = (crc >> 8) ^ c

    _hash = ~crc & 0xFFFFFFFF

    return f"0x{_hash:02X}"

JOAA_INIT_SEED = 8

def _joaa(msg):
    _hash = 0x0

    for b in msg:
        if not b:
            continue 
        _hash += b
        _hash = c_int32(_hash).value & 0xFFFFFFFF
        _hash += _hash << JOAA_INIT_SEED
        _hash = c_int32(_hash).value & 0xFFFFFFFF
        _hash ^= _hash >> 6
        _hash = c_int32(_hash).value & 0xFFFFFFFF

    _hash += _hash << 3
    _hash = c_int32(_hash).value & 0xFFFFFFFF
    _hash ^= _hash >> 11
    _hash = c_int32(_hash).value & 0xFFFFFFFF
    _hash += _hash << 15
    _hash = c_int32(_hash).value & 0xFFFFFFFF

    return f"0x{_hash:02X}"

if __name__ == "__main__":
    if (len(sys.argv) < 3):
        print(f"[-]Usage: python {sys.argv[0]} <hash_type> <comma_sep_str>")
        print(f"[-]Usage: For <hash_type>, choose from: d (djb2), c (crc32h), j (joaa)")
        print(f"[-]Usage: The script hashes the string as is")
        sys.exit(-1)

    hash_type = sys.argv[1]
    raw_input = sys.argv[2]

    if raw_input.endswith(','):
        raw_input = raw_input[:-1]
    item_list = raw_input.split(',')

    # due to implementation, unicode string yields the same output ...
    if hash_type == 'd':    # djb2
        for i in item_list:
            print(_djb2(i.encode()))
    elif hash_type == 'c':  # crc32h
        for i in item_list:
            print(_crc32h(i.encode()))
    elif hash_type == 'j':  # joaa
        for i in item_list:
            print(_joaa(i.encode()))
    else:
        print(f"[-]Unsupported hash type, choose from: d (djb2), c (crc32h), j (joaa) ...")
        sys.exit(-1)

