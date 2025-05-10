
# Security Testing and Training Toolkit

This repository contains educational tools for **cybersecurity training, demonstration, and awareness** purposes. It is intended for use in **controlled environments only**, such as classrooms, labs, or authorized simulations.

---

## IMPORTANT: EDUCATIONAL USE ONLY

This code is provided strictly for **educational purposes**. These tools simulate security threats and **must not** be used against real systems or individuals without **explicit authorization**. Misuse is both **illegal and unethical**.

---

## Project Structure

The toolkit consists of three primary modules and a CTFs section:

### 1. File Encryption/Decryption Simulation (`Module1/`)
Demonstrates how ransomware-like behavior works, including:
- **AES encryption of files**
- **Simulated ransom interface**
- **Decryption functionality with authentication**

**Key Files:**
- `RegisterationApp.py` – Main encryption/decryption interface
- `hash.py` – Hash utility for integrity checks

---

### 2. Phishing Simulation (`Phishing/`)
Demonstrates common phishing tactics for awareness training:
- **Phishing email template generation**
- **Batch sending with configurable parameters**
- **Realistic educational scenarios**

**Key Files:**
- `phishingScript.py` – Main script for sending simulated phishing emails
- `student_emails.txt` – Sample recipient list for demo use

---

### 3. Static Analyzer Module (`StaticAnalyzer/`)
Introduces basic concepts of static code analysis and malware detection:
- **Scans files for common malware signatures or suspicious patterns**
- **Supports rules-based detection and extensibility**
- **Useful for demonstrating defensive coding and secure development practices**

**Key Files:**
- `analyzer.py` – Signature-based analysis engine
- `rules.json` – Customizable detection ruleset

---

### 4. Capture The Flag Challenges (`CTFs/`)
Includes beginner-friendly CTF-style exercises:
- **Mini challenges for reverse engineering, web security, cryptography, etc.**
- **Designed to complement hands-on learning during training workshops**
- **Hints and solutions available for instructors**

---

## Setup and Configuration

### Prerequisites
- Python 3.8+
- Required Libraries:
  - `ttkbootstrap`
  - `pycryptodomex` (or `pycryptodome`)
  - `keyring`
  - `python-dotenv`
  - `fpdf`

### Installation

```bash
git clone https://github.com/your-username/security-testing-toolkit.git
cd security-testing-toolkit
pip install -r requirements.txt
```

### Environment Variables (for Phishing module)
Create a `.env` file with the following:

```env
EMAIL_ADDRESS=your-sender-email@example.com
EMAIL_PASSWORD=your-email-password
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_DOMAIN=example.com
```

---

## Usage Guidelines

### File Encryption Simulation

Only run this on **test files in isolated environments**.

```bash
python Module1/RegisterationApp.py
```

- Encrypts files and simulates a ransomware attack interface.
- Files are reversible if proper key is retained.

### Phishing Simulation

Use only in **authorized security awareness programs**.

```bash
python Phishing/phishingScript.py
```

- Sends educational phishing emails to addresses in `student_emails.txt`.

### Static Analyzer

```bash
python StaticAnalyzer/analyzer.py path/to/target/files
```

- Scans files for known patterns, alerts on suspicious code.

---

## Best Practices for Security Training

- Always conduct training in **controlled and authorized environments**
- Avoid simulating attacks on live systems or real users
- Document all exercises and provide **educational debriefs**
- Use this toolkit as a **starting point** for discussion and exploration

---

## 🧾 Disclaimer

The authors of this toolkit are **not responsible for any misuse** of the provided code. Use responsibly and ethically.
