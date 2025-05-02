import os
import helpers as helpers
import pefile
"""
This module contains the indicators for the static analysis of the code.

1. It includes functions to check for specific patterns or characteristics in the code.
2. These indicators are used to identify potentially malicious code or behavior.
3. The indicators are used in the main static analysis function to determine if the code is malicious or not.
4. Weights are assigned to each indicator based on its importance in identifying malicious code. (To be decided later)
"""

# To be decided later

def run_indicators():
    '''
    This function runs all the indicators and returns if it's malicious or not.
    '''
    return

'''
1. Imports DDl -> windows registry api w keda
2. Byte Entropy for the whole file -> check for packers 
3. DOS mode 
4. Static strings + Ransomware notes (Yara Rules)
5. Byte entropy for strings lw ynf3 
'''
INDICATOR_WEIGHTS = {
    "dlls": {
        'filesystem': 0.5, # Very common, but not always malicious
        'crypto': 5, # % in safe files
        'networking': 2 # very low in safe files
    },
    "apis": {
        'crypto': 5,
    }
}

DANGEROUS_DLLS = {
    "crypto": {
        "rundll32.exe", "advapi32.dll", "bcrypt.dll", "ncrypt.dll", "crypt32.dll", "wincrypt.h" 
    },
    "filesystem": {
        "kernel32.dll", "shell32.dll", "shlwapi.dll", "ntdll.dll", "ole32.dll"
    },
    "networking": {
        "wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll", "httpapi.dll", "dnsapi.dll"
    }
}

Dangerous_API = {
    "crypto": {
        "cryptgenrandom", "cryptacquirecontextw", "cryptreleasecontext", "cryptprotectdata", "cryptsetkeyparam" , "cryptdecrypt", "cryptencrypt",
        "cryptcreatehash", "crypthashdata", "cryptverifysignature", "cryptsignhashw", "cryptimportkey", "cryptexportkey" , 
         "cryptdestroyhash"
    },
}

def check_dangerous_dlls(file_path):
    try:
        extracted_dlls =  helpers.extract_imported_items(file_path, item_type='dlls')
        total_score , matched_hits , matched_categories = helpers.check_matches(extracted_dlls, DANGEROUS_DLLS, INDICATOR_WEIGHTS["dlls"])
        return total_score, matched_hits , matched_categories

    except Exception as e:
        print(f"[!] Error processing file: {e}")
        return 0, {} , set()  
    
def check_registry_apis(file_path):
    try:
        extracted_imports =  helpers.extract_imported_items(file_path, item_type='apis')
        total_score , matched_hits , matched_categories= helpers.check_matches(extracted_imports, Dangerous_API, INDICATOR_WEIGHTS["apis"])
        return total_score, matched_hits , matched_categories

    except Exception as e:
        print(f"[!] Error processing file hena: {e}")
        return 0, {} , set()
    
def recursive_file_search(directory):
    """
    Recursively search for all files in a given directory and its subdirectories.
    :param directory: Path to the directory to search.
    :return: A list of file paths.
    """
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_paths.append(os.path.join(root, file))
    
    return file_paths