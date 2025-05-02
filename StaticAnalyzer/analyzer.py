import indicators
import helpers as helpers


def main():
    directory_path = input("Enter the directory path to analyze: ")
    
    benign_file_count = 0
    total_file_count = 0

    for file_path in indicators.recursive_file_search(directory_path):
        print(f"\nAnalyzing: {file_path}")
        total_file_count += 1
        is_malicious = indicators.run_indicators(file_path)
        if is_malicious:
            print(f"[+] {file_path} is potentially malicious.")
        else:
            benign_file_count += 1
            print(f"[-] {file_path} is benign.")
    
    print(f"\nTotal files analyzed: {total_file_count}")
    print(f"Total potentially malicious files: {total_file_count - benign_file_count}")

if __name__ == "__main__":
    main()