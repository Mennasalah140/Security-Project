# 🔍 **Static Analysis nOTES**

## 🧩 DLL Usage

**Weight: Low**
DLL presence is not a strong discriminator since both benign and malicious files import similar libraries.

* **Filesystem DLLs**: Very common in *both* safe and unsafe files.
* **Networking DLLs**: Rare overall, but slightly more common in ransomware.
* **Crypto DLLs**: Appears in \~60% of ransomware files but also found in some safe files.

## ⚙️ API Usage

**Weight: Low**
API patterns are not strongly distinctive between benign and malicious samples. APIs like crypto functions appear across both sets.

## 📦 Packer Detection

**Initial Method (Section Names):** Not reliable — packers like UPX, Aspack, and Themida do not leave clear section name indicators.
**Alternative Method:** Use external UPX tool via `subprocess` for more accurate detection.

### NOP Sleds (Potential Obfuscation)

* **Ransomware Avg:** 8,689 (Max: 58,929)
* **Safe Files Avg:** 847.87 (Max: 5,984)
  **Heuristic:** If NOP count > 7,500 → assign *high weight*.

### 🧠 Entropy Analysis (Packers)

| Threshold | Ransomware Triggered | Safe Files Falsely Flagged |
| --------- | -------------------- | -------------------------- |
| **6.75**  | 8                    | 20 *(Optimal threshold)*   |

### 🧠 Entropy Analysis (obfuscation)
* Threshold of 6.5 provides a good tradeoff for flagging suspicious obfuscation with minimal false positives.

## 🔐 YARA Rule Matching

### ✅ High-Signal Indicators (High Weight)

* Ransom note phrases
* Ransom-related file names
* Suspicious commands (e.g., shadow deletion, PowerShell abuse)
* Weird extensions (`.fun`, `.locky`, `.enc`, etc.)

### ⚠️ Low-Signal Indicators (Low Weight)

* IP addresses and URLs (common in many files)
* Known good extensions (trigger only when **≥ 7** found)
* DLL/API matches alone

## 🚩 Verdict Scoring Heuristics

| Feature                              | Weight |
| ------------------------------------ | ------ |
| DLLs / APIs                          | Low    |
| Matched IP / URL YARA rules          | Low    |
| Packers (esp. via UPX detection)     | High   |
| Obfuscated strings (entropy > 6.5)   | High   |
| NOP count > 7500                     | High   |
| YARA matches (ransom note, commands) | High   |

---