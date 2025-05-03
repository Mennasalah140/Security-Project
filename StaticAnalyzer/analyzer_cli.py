import sys
import os
from indicators import run_indicators

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_or_directory_path>")
        sys.exit(1)

    path = sys.argv[1]
    scanned_files = 0
    malicious_count = 0
    safe_count = 0
    total_pe_files = 0

    def analyze_wrapper(file_path):
        nonlocal scanned_files, malicious_count, safe_count, total_pe_files
        scanned_files += 1
        print(f"\n[+] Analyzing file: {file_path}")
        result = run_indicators(file_path)

        if not result["is_pe"]:
            print(f"[-] Skipped (Not PE): {file_path}")
            return

        total_pe_files += 1 

        print(f"Malicious Score: {result['malicious_score']}")
        if result["is_malicious"]:
            print("[!] Verdict: POTENTIALLY MALICIOUS")
            malicious_count += 1
        else:
            print("Verdict: Likely benign")
            safe_count += 1

        print("\nReasons / Findings:")
        for reason in result["reasons"]:
            print(f"  - {reason}")
        print("-" * 40)

    if os.path.isfile(path):
        analyze_wrapper(path)
    elif os.path.isdir(path):
        print(f"[+] Analyzing directory: {path}")
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                analyze_wrapper(full_path)
    else:
        print(f"[-] Invalid path: {path}")
        return

    print("\n" + "=" * 40)
    print(f"Total files scanned: {scanned_files}")
    print(f"Total valid PE files analyzed: {total_pe_files}")
    print(f"Malicious files: {malicious_count}")
    print(f"Safe files: {safe_count}")
    print("=" * 40)

if __name__ == "__main__":
    main()
