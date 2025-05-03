import struct

def to_le_bytes(val, length):
    return val.to_bytes(length, byteorder='little')

# Encrypted buffer (25 bytes)
encrypted = (
    to_le_bytes(0x7b67737c51525045, 8) +
    to_le_bytes(0x7569, 2) +
    to_le_bytes(0x68716a626675, 6) +
    to_le_bytes(0x756f, 2) +
    to_le_bytes(0x7e686d68766768, 7)
)

# Key buffer (25 bytes)
key = (
    to_le_bytes(0x0502010103020302, 8) +
    to_le_bytes(0x0304, 2) +
    to_le_bytes(0x010305030102, 6) +
    to_le_bytes(0x0706, 2) +
    to_le_bytes(0x0101ffff040203, 7)
)

# Sanity check
assert len(encrypted) == 25
assert len(key) == 25

def is_printable(b):
    return 32 <= b <= 126

ops_results = {}

# XOR
ops_results['XOR'] = bytes([(e ^ k) for e, k in zip(encrypted, key)])

# AND
ops_results['AND'] = bytes([(e & k) for e, k in zip(encrypted, key)])

# OR
ops_results['OR'] = bytes([(e | k) for e, k in zip(encrypted, key)])

# ADD (mod 256)
ops_results['ADD'] = bytes([(e + k) % 256 for e, k in zip(encrypted, key)])

# SUB (mod 256)
ops_results['SUB'] = bytes([(e - k) % 256 for e, k in zip(encrypted, key)])

# filter for printable strings
printable_variants = {
    op: ''.join(chr(b) for b in val if is_printable(b))
    for op, val in ops_results.items()
}

# Print the results
for op, result in printable_variants.items():
    print(f"{op}: {result}")
