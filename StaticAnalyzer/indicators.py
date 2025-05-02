import math
import os
import helpers as helpers
import pefile
import constants
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
1. Imports DDl -> windows registry api w keda (Done)
2. Byte Entropy for the whole file -> check for packers 
3. DOS mode 
4. Static strings + Ransomware notes (Yara Rules)
5. Byte entropy for strings lw ynf3 
'''

def check_dangerous_dlls(file_path):
    try:
        extracted_dlls =  helpers.extract_imported_items(file_path, item_type='dlls')
        total_score , matched_hits , matched_categories = helpers.check_matches(extracted_dlls, constants.DANGEROUS_DLLS, constants.INDICATOR_WEIGHTS["dlls"])
        return total_score, matched_hits , matched_categories

    except Exception as e:
        print(f"[!] Error processing dll: {e}")
        return 0, {} , set()  
    
def check_registry_apis(file_path):
    try:
        extracted_imports =  helpers.extract_imported_items(file_path, item_type='apis')
        total_score , matched_hits , matched_categories= helpers.check_matches(extracted_imports, constants.Dangerous_API, constants.INDICATOR_WEIGHTS["apis"])
        return total_score, matched_hits , matched_categories

    except Exception as e:
        print(f"[!] Error processing apis: {e}")
        return 0, {} , set()

def check_for_known_packers(file_path):
    packers_found = {}
    packer_matches = set()
    total_score = 0
    try:
        # Check aganist known packers 
        sections = helpers.extract_pe_sections(file_path)
        total_score , matched_hits , matched_categories = helpers.check_matches(sections, constants.Dangerous_packers, None, weight=constants.INDICATOR_WEIGHTS["packers"])
        # check for entropy of sections
        pe = pefile.PE(file_path)
        analyze_pe_entropy(pe.__data__)

        return total_score, packers_found, list(packer_matches)
    except Exception as e:
        print(f"[!] Error processing packers: {e}")
        return 0, {} , set()

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurences = [0] * 256

    for byte in data:
        occurences[byte] += 1

    for count in occurences:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy

def analyze_pe_entropy(pe_data):
    pe = pefile.PE(data=pe_data)
    suspicious_sections = []

    for section in pe.sections:
        raw_data = section.get_data()
        entropy = calculate_entropy(raw_data)
        name = section.Name.rstrip(b'\x00').decode(errors='ignore')

        print(f"Section: {name:8s} | Entropy: {entropy:.2f}")

        if entropy > 6.45:
            suspicious_sections.append((name, entropy))

    if suspicious_sections:
        print("\n Suspicious Sections Detected (High Entropy):")
        for name, ent in suspicious_sections:
            print(f" - {name}: {ent:.2f}")
    else:
        print("\n No suspicious high-entropy sections detected.")

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