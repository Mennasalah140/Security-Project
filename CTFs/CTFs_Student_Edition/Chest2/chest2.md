## **Problem Context**

The note presented the following challenge:

> **Hear ye, hear ye, brave soul of the Lands Between, the tarnished wanderer of the cryptic realms... "One Cipher to rule them all, forged in the sacred flames of the wisdom of the Erdtree. Heed well this ancient covenant: the Runic Key must be wielded but once, then cast into the Abyss of Forgotten Lore, never to be reclaimed by mortal hands.Should thy folly lead thee to brandish the same Key twice, mark these words, bearer of the curse - thou shalt summon forth the wrath of the Greater Will. The perfect guardians of secrecy shall rise to smite thy transgression, and thy secrets shall be laid bare before all who seek them. Three vessels of sound now rest in thy possession - sacred audio scrolls imbued with arcane power. Thou must harness the power of a twin of the artifacts with wisdom and care. Each scroll may be used but once, for their essence is fragile. Should thou attempt to wield either scroll for multiple enchantments, their mystical patterns shall fade and wither, rendering them forever broken and silent.Remember this warning, oh seeker of hidden knowledge: These twin sounds are thy key and thy burden. Use them for a single sacred joining, then seek new vessels for thy future workings."The parchment crumbles to dust as the final words fade into whispers on the wind...**

## Challenge Interpretation

The prompt spoke in riddles, evoking a sacred rule of **one-time usage** of audio artifacts – a concept that instantly echoed the **One-Time Pad (OTP)** encryption model. From this, I understood:

- Only one use of a **Runic Key** is permitted.
- Reuse leads to destruction — or in crypto terms, **key reuse leads to XOR leakage**.
- **Three audio scrolls** are given; two of them are **identical** — indicating redundancy or tampering.
- The phrase “use them for a single sacred joining” pointed directly to **XOR operations** between the scrolls.
- The GIF ("You shall not pass") further hinted at something being **blocked**, perhaps unless decryption was done correctly.

---

## Investigation

Reading a bit about audio CTFs, mainly from this soure: `https://ctf-wiki.mahaloz.re/misc/audio/introduction/`, I undertook the following steps:

### Step 1: Auditory and Visual Inspection

- **Listened** to the files. Nothing obvious stood out.
- Used **Sonic Visualizer** to check spectrograms — no visible spectrograph text or unusual patterns.
- Attempted **Least Significant Bit (LSB)** extraction using steganalysis tools — no meaningful output.
  
### Step 2: File Analysis

- Calculated file hashes and used bit-by-bit comparison.
- **output3.wav** and **output5.wav** were **identical** (binary diff and output analysis).

This reinforced the idea of **key reuse**, meaning **output3** and **output5** represented ciphertexts **encoded with the same key**.

---

## Step 3: XOR

Using XOR (and some Python):

```python
import numpy as np
from scipy.io import wavfile

def xor_wav(file1, file2, output_file):
    rate1, data1 = wavfile.read(file1)
    rate2, data2 = wavfile.read(file2)
    
    if rate1 != rate2 or len(data1) != len(data2):
        min_len = min(len(data1), len(data2))
        data1, data2 = data1[:min_len], data2[:min_len]
    
    xor_data = np.bitwise_xor(data1, data2)
    wavfile.write(output_file, rate1, xor_data)

xor_wav("output3.wav", "output4.wav", "xor_result.wav")
```

- **output3 XOR output4** revealed an interpretable audio **xor_result.wav**.
- The interpreted words: **"cyber", "secur", "braces", "underscore", "P", "N", "C"**, and curly braces.

---

## Unscrambling the Clue

By reassembling the leaked fragments and aligning them logically, I constructed the final flag:

```
cmpn{cyber_security}
```