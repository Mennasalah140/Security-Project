import sys
import os
from indicators import run_indicators

def analyze_file(file_path):
    print(f"\n[+] Analyzing file: {file_path}")
    result = run_indicators(file_path)

    if not result["is_pe"]:
        print("[-] Not a PE (Portable Executable) file. Skipping analysis.")
        return

    print(f"Malicious Score: {result['malicious_score'] * 100}%")
    if result["is_malicious"]:
        print("[!] Verdict: POTENTIALLY MALICIOUS")
    else:
        print("[✓] Verdict: Likely benign")

    print("\nReasons / Findings:")
    for reason in result["reasons"]:
        print(f"  - {reason}")
    print("-" * 40)

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_or_directory_path>")
        sys.exit(1)

    path = sys.argv[1]

    if os.path.isfile(path):
        analyze_file(path)
    elif os.path.isdir(path):
        print(f"[+] Analyzing directory: {path}")
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                analyze_file(full_path)
    else:
        print(f"[-] Invalid path: {path}")

if __name__ == "__main__":
    main()
