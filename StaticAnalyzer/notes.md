# Analysis Summary

## DLLs

**Weight: Low**, since DLLs appear in both safe and unsafe files, and the range distribution isn’t clearly distinct.

1. **Filesystem** — Very common in both safe and unsafe files.
2. **Networking** — Uncommon in both, but more prevalent in ransomware.
3. **Crypto** — Present in some safe files, but found in ~60% of ransomware files.

## APIs

**Weight: Also low**, in my opinion, as APIs are present in both safe and unsafe files, and the value range doesn’t provide clear differentiation.

## Packers

Using section names to detect packers doesn’t work well in either safe or unsafe files — most packers don’t show clear identifiers in section names.

Could check for upx using upx tool -> subprocess 

### Entropy Threshold Testing:

| Threshold | Non-Ransomware Flagged | Safe Files Incorrectly Flagged |
|-----------|------------------------|-------------------------------|
| 6.00      | 4                      | 75                            |
| 6.25      | 7                      | 43                            |
| 6.40      | 8                      | 28                            |
| 6.50      | 8                      | 20 *(Optimal)*                |
| 6.75      | 14                     | 6                             |
| 7.00      | 16                     | 1                             |

---

## Detailed Stats

### Safe Files

**DLL Categories:**
- **Crypto**  
  - Max: 5, Min: 0, Average: 1.71
- **Filesystem**  
  - Max: 0.5, Min: 0, Average: 0.41
- **Networking**  
  - Max: 2, Min: 0, Average: 0.18

**API Categories:**
- **Crypto**  
  - Max: 5, Min: 0, Average: 0.44

**Packer Categories:**
- **UPX**  
  - Max: 0, Min: 0, Average: 0.00
- **Aspack**  
  - Max: 0, Min: 0, Average: 0.00
- **Themida**  
  - Max: 0, Min: 0, Average: 0.00

---

### Unsafe Files

**DLL Categories:**
- **Crypto**  
  - Max: 5, Min: 0, Average: 2.05
- **Filesystem**  
  - Max: 0.5, Min: 0, Average: 0.34
- **Networking**  
  - Max: 2, Min: 0, Average: 0.45

**API Categories:**
- **Crypto**  
  - Max: 5, Min: 0, Average: 0.91

**Packer Categories:**
- **UPX**  
  - Max: 0, Min: 0, Average: 0.00
- **Aspack**  
  - Max: 0, Min: 0, Average: 0.00
- **Themida**  
  - Max: 0, Min: 0, Average: 0.00
