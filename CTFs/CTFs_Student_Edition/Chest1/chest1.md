# **Atbash Cipher Solution**

## **Problem Context**

The note presented the following challenge:

> **"Dissect the very essence of the letters within the given legendary fight between Dio and Jotaro! Count them, unravel their lengths, uncover the patterns hidden in plain sight! Use every ounce of your knowledge, every fragment of your intellect but cast aside the meaningless—ignore the special characters and the empty spaces!…but know this—what you face is no modern enigma. No, it is something far older, something timeless… it is CLASSICAL!"**

## **Initial Assumptions: Caesar Cipher**

At first glimpse, I thought the cipher was a **Caesar cipher**. Here's why:

### **"Dissect the very essence of the letters"**:
This part suggests that we need to focus on the letters themselves and possibly analyze their structure or order. This could hint toward a letter-based cipher.

### **"Count them, unravel their lengths, uncover the patterns hidden in plain sight!"**:
The phrase **"patterns hidden in plain sight"** implies that the solution lies in understanding the structure of the letters themselves, and perhaps rearranging or substituting them based on a known pattern.

### **"Use every ounce of your knowledge, every fragment of your intellect"**:
This suggests using established, classic ciphers or methods that rely on letter manipulation.

### **"It is something far older, something timeless… it is CLASSICAL!"**:
The word **"CLASSICAL"** directly points to **classical ciphers**, which are a family of ciphers used for centuries. The mention of "older" and "timeless" strongly hints at a cipher that has been around for a long time, such as the **Caesar cipher**.

## **Why Caesar Cipher Didn't Work**

Upon analyzing the conversation in the `enc.txt` and attempting a **Bash script** to try all **Caesar cipher** shifts, it became clear that **Caesar cipher** didn’t work.

### Also, by analogy from the note and the encrypted file length:
- **WRL** corresponds to **Dio**:
  - `W -> D`
  - `R -> I`
  - `L -> O`
- **QLGZIL** corresponds to **Jotaro**:
  - `Q -> J`
  - `L -> O`
  - `G -> T`
  - `Z -> A`
  - `I -> R`
  - `L -> O`

> NO CAESAR CIPHER WILL SOLVE THIS.

## **Discovery of the Atbash Cipher**

After further analysis and testing, I discovered that the **Atbash cipher** fits the clues much better.

The **Atbash cipher** is one of the oldest known substitution ciphers, dating back to the Hebrew script in ancient times. In **Atbash**, each letter is mapped to its reverse counterpart (A ↔ Z, B ↔ Y, etc.), which fits the "timeless" clue. The idea of reversing the alphabet aligns well with the concept of a **"classical" cipher**.

### **"Ignore the special characters and the empty spaces!"**
This part advises us to focus purely on the alphabetic characters, which is exactly what the **Atbash cipher** does—it only deals with the alphabet, ignoring spaces and punctuation.

### **"It is no modern enigma"**
This reinforces the idea that the solution is based on **old, classical techniques** rather than more modern cryptographic methods.


# Solution
- key: cmpn {i_luv_jojo}