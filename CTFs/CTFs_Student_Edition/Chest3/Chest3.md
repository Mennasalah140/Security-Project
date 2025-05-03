
## **Problem Context**

The challenge introduced a digital vault locked behind a distorted cipher:

A Java source file was provided. It contained a method named `scramble` that operated at the **bit level**, transforming each character of the input string in a highly specific sequence. The vault would only unlock if the transformed input matched a hardcoded scrambled array.

---

## **Challenge Interpretation**

Key insights from the prompt and source:

- The challenge centers on **bitwise transformations**.
- The `scramble` method in the Java code performs multiple **bit position swaps** on each character.
- To find the flag, one must reverse-engineer this logic by **undoing the bit scrambling**.
- The presence of **switchBits** functions hinted at isolated pairwise bit swaps, not overall shifts or masks.
- Correct solution required **reversal** of the transformation order.

---

## **Investigation**

### Step 1: Analyzing the Source

From the Java source, I extracted the transformation logic:

```java
public static char scramble(char c) {
    c = switchBits(c, 1, 2);
    c = switchBits(c, 0, 3);
    c = switchBits(c, 5, 6);
    c = switchBits(c, 4, 7);
    c = switchBits(c, 0, 1);
    c = switchBits(c, 3, 4);
    c = switchBits(c, 2, 5);
    c = switchBits(c, 6, 7);
    return c;
}
```

This function scrambles each character by **swapping bit positions** multiple times.

---

### Step 2: Reversing the Scramble

Since bit swaps are not inherently reversible unless undone in reverse order, I implemented an `unscramble()` function by applying the swaps in **reverse sequence**:

```java
public static char unscramble(char c) {
    c = switchBits(c, 6, 7);
    c = switchBits(c, 2, 5);
    c = switchBits(c, 3, 4);
    c = switchBits(c, 0, 1);
    c = switchBits(c, 4, 7);
    c = switchBits(c, 5, 6);
    c = switchBits(c, 0, 3);
    c = switchBits(c, 1, 2);
    return c;
}
```

I applied this to each byte of the scrambled password array found in the Java class.

---

### Step 3: Reconstructing the Original Password

Once the unscramble logic was applied to all scrambled characters, the output produced ASCII-readable characters — revealing the original password.

---

## Solution

```
s0m3_m0r3_b1t_sh1fTiNg_91c642112
```