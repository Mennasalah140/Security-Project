
# Chest 3 – Bit Scramble Decryption VaultDoor8

## Challenge Summary

This part of the CTF was themed around unlocking a vault using a scrambled password. The hint came in the form of Java source code, where the password was passed through a series of bit-level transformations and then compared to a hardcoded scrambled expected result.

Your goal:  
Reverse the scrambling logic to retrieve the original password that unlocks the vault.

---

## Thought Process

1. Read the Source Code Carefully  
   The Java class VaultDoor8 contains:
   - A main function that reads a password
   - A checkPassword function that compares a scrambled version of the password to a hardcoded array
   - A scramble method that calls a switchBits function on each character

2. Understand the Scramble Logic  
   The scramble method applies 8 bit-level swaps per character:

   ```
   c = switchBits(c, 1, 2)
   c = switchBits(c, 0, 3)
   c = switchBits(c, 5, 6)
   c = switchBits(c, 4, 7)
   c = switchBits(c, 0, 1)
   c = switchBits(c, 3, 4)
   c = switchBits(c, 2, 5)
   c = switchBits(c, 6, 7)
   ```

   This scrambles each byte non-trivially.

3. Reverse the Bit Swapping  
   To reverse it, I rewrote the scramble logic in reverse order. This step is critical because bit-swapping is not self-reversing unless applied in reverse sequence.

4. Implement a Java Decoder  
   I re-implemented the switchBits function and wrote an unscramble method that reverses the scrambling sequence.

5. Map Back to Characters  
   I applied unscramble to each byte in the expected array and printed the original character. This revealed the correct password.

---

## Java Code Snippet Core Reverse Logic

```
public static char unscramble(char c) {
    c = switchBits(c, 6, 7)
    c = switchBits(c, 2, 5)
    c = switchBits(c, 3, 4)
    c = switchBits(c, 0, 1)
    c = switchBits(c, 4, 7)
    c = switchBits(c, 5, 6)
    c = switchBits(c, 0, 3)
    c = switchBits(c, 1, 2)
    return c
}
```

---

## Final Output

Running the full program printed the final key:

CMPN fl1p y0ur b1ts and r3v3rs3 3ng1neer m3