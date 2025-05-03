## **Problem Context**

The note presented the following challenge:

> **[mechanical puppet voice, slow and deliberate] Hello. I want to play a game. Before you lies a simple test of your skills. A program that guards its secret behind a wall of code. It asks for a password - one that is hidden within its very structure. You may use whatever tools you possess, but know this: only those who choose to reveal the program's inner workings through Ghidra will discover the truth. First, you must locate the main function - the heart of this twisted creation. Then, follow the digital breadcrumbs to the check_pw function where truth awaits. Keep the ASCII table as your guide through this labyrinth of bytes and characters. The choice is yours. Will you take the easy path and fail? Or will you peel back the layers to expose what lies beneath? Live or die. Decompile... or be denied. Let the game begin.**

## **Challenge Interpretation**

From the puppet's haunting words, I understood the following:

- The binary hides its secrets within its structure — not via input/output patterns.
- **Ghidra** was explicitly mentioned as the key to unlocking the program’s logic.
- The **main() function** is the entry point, but the real treasure lies deeper, in a function named `check_pw`.
- A strong hint to **use the ASCII table** to interpret transformations suggested low-level operations like byte math.

---

## Reversing Strategy

1. **Passed the binary to Ghidra** for analysis and decompilation.
2. **Analyzed `main()` function**:
   - It loads two memory regions (`local_28` and `local_48`) each of 25 bytes.
   - Calls `check_pw(input, &local_28, &local_48)` only if the input length is `0x19` (25 bytes).
   - Indicates a transformation (possibly XOR or similar) to verify the password.

3. **Extracted Hardcoded Buffers** from Ghidra:

   - **Encrypted Buffer (25 bytes)**:
     ```
     local_28 = 0x7b67737c51525045
     local_20 = 0x7569
     uStack_1e = 0x68716a626675
     uStack_18 = 0x756f
     local_16 = 0x7e686d68766768
     ```

   - **Key Buffer (25 bytes)**:
     ```
     local_48 = 0x502010103020302
     local_40 = 0x0304
     uStack_3e = 0x010305030102
     uStack_38 = 0x0706
     local_36 = 0x0101ffff040203
     ```

---

## Solution Attempts

Several operations were tested through this python script:

```python
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
```

### Results

| Operation | Result |
|----------|--------|
| XOR      | `GSPR}re~mvwgaoriirkeri` (Garbage) |
| AND      | Garbage |
| OR       | Garbled |
| ADD      | Garbled |
| ✅ SUB   | `CMPN{reverse_engineering}` ✅ |

---

## Solution

```
CMPN{reverse_engineering}
```