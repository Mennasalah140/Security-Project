# 🛡️ Static Analyzer GUI

A desktop-based GUI tool using PyQt5 for analyzing Windows binaries to detect **potential ransomware** using static analysis techniques like PE inspection, YARA rule matching, and string analysis.

You give it a file or folder path — and it tells you if it's **ransomware** or not.

---

## 📦 Requirements

- Python 3.6+
- PyQt5
- yara-python
- pefile

Install required packages:

```bash
pip install -r requirements.txt
````

---

## ⚙️ Setup Instructions

### 1. Download Sysinternals `strings.exe`

* Download from Microsoft:
  [https://learn.microsoft.com/en-us/sysinternals/downloads/strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)

* Extract the downloaded archive and note the full path to `strings.exe`.

### 2. Configure Paths in `constants.py`

Open the file `constants.py` and edit the following variables to point to your environment:

```python
Strings_PATH = "C:\\Path\\To\\strings.exe"
YARA_RULES_PATH = "C:\\Path\\To\\YaraRules"
```

Ensure the path strings are valid and correctly formatted.


### 3. (Optional) Activate Virtual Environment

You can manually set up your virtual environment by running:

```bash
.\venv\Scripts\Activate  # On PowerShell (Windows)
```

But you can also use the **Makefile** to automate the setup process!

---

## 🚀 Automated Setup & Running the App

You can automatically create a virtual environment, install the required libraries, and run the application with the following command:

```bash
make run
```

This will:

1. Create a virtual environment (if it doesn't exist)
2. Install all necessary dependencies from `requirements.txt`
3. Launch the PyQt5 GUI app

Once the application is running:

* Paste or select a directory containing Windows executables
* Click **Analyze**
* The app will:

  * Scan each file
  * Categorize them into:

    * **Malicious (Potential Ransomware)**
    * **Safe**
    * **Error during scan**
  * Show total stats

---


## 🗂️ Project Structure

```
/StaticAnalyzer
│
├── analyzer.py           # Core analysis logic
├── analyzer_ui.py        # PyQt5 GUI interface
├── constants.py          # Config paths for strings.exe and rules
├── helpers.py            # Utility functions
├── indicators.py         # Ransomware detection heuristics
├── rules.yara            # YARA rules file
├── requirements.txt      # Dependencies
├── README.md             # This file
├── notes.md              # Project notes
├── Makefile              # Optional make commands


❗ Notes
Verdicts are based on heuristics — not always 100% accurate

Use this for research or educational purposes

This does not replace antivirus or EDR tools