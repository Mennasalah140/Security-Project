# 🔐 CTF Challenge: Reverse Engineering Password Check

## 📄 Challenge Description

The binary prompts for a single argument and checks if it matches a hidden password. If correct, it prints a success message. The goal is to reverse engineer the binary and extract the correct password.

---

## 🧠 Reversing Strategy

1. **Passed the binary to Ghidra** for analysis.
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

## 🧪 Solution Attempts

Several operations were tested:

| Operation | Result |
|----------|--------|
| XOR      | `GSPR}re~mvwgaoriirkeri` (incomplete) |
| AND      | Garbage |
| OR       | Garbled |
| ADD      | Garbled |
| ✅ SUB   | `CMPN{reverse_engineering}` ✅ |

---

## ✅ Final Flag

```
CMPN{reverse_engineering}
```

---

## 🛠 Script

Python script used to extract the flag:

```python
def to_le_bytes(val, length):
    return val.to_bytes(length, byteorder='little')

# Encrypted buffer
encrypted = (
    to_le_bytes(0x7b67737c51525045, 8) +
    to_le_bytes(0x7569, 2) +
    to_le_bytes(0x68716a626675, 6) +
    to_le_bytes(0x756f, 2) +
    to_le_bytes(0x7e686d68766768, 7)
)

# Key buffer
key = (
    to_le_bytes(0x502010103020302, 8) +
    to_le_bytes(0x0304, 2) +
    to_le_bytes(0x010305030102, 6) +
    to_le_bytes(0x0706, 2) +
    to_le_bytes(0x0101ffff040203, 7)
)

# Correct operation (SUB)
password_bytes = bytes([(e - k) % 256 for e, k in zip(encrypted, key)])
print("Flag:", password_bytes.decode())
```

---

## 📎 Notes

- This challenge was a twist on the usual XOR obfuscation — the real operation was **subtraction**.
- Byte padding and ordering (little-endian) were crucial.
- Helpful tools: **Ghidra**, **Python**, and **a hex editor**.

---
