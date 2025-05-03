import os
from indicators import run_indicators

def analyze_path(path):
    scanned_files = 0
    malicious_count = 0
    safe_count = 0
    error_count = 0 
    error_files = []  
    malicious_files = []  # List to hold malicious files
    safe_files = []  # List to hold safe files

    def analyze_wrapper(file_path):
        nonlocal scanned_files, malicious_count, safe_count , error_count
        scanned_files += 1
        result = run_indicators(file_path)

        if not result["is_pe"]:
            error_count += 1
            error_files.append(file_path)
            return

        if result["is_malicious"]:
            malicious_count += 1
            malicious_files.append(file_path)  # Add to malicious list
        else:
            safe_files.append(file_path)  # Add to safe list
            safe_count += 1

    if os.path.isfile(path):
        analyze_wrapper(path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                analyze_wrapper(full_path)
    else:
        return "Invalid path"
    

    return malicious_files, safe_files, error_files, scanned_files, scanned_files, malicious_count, safe_count , error_count
