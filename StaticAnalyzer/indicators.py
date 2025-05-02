import os
import helpers as helpers
import constants
"""
This module contains the indicators for the static analysis of the code.

1. It includes functions to check for specific patterns or characteristics in the code.
2. These indicators are used to identify potentially malicious code or behavior.
3. The indicators are used in the main static analysis function to determine if the code is malicious or not.
4. Weights are assigned to each indicator based on its importance in identifying malicious code. (To be decided later)
"""

# To be decided later
def run_indicators(file_path , scores_details , nop_count_scores):
    '''
    This function runs all the indicators and returns if it's malicious or not.
    '''
    category_scores = {
        'crypto': [],
        'filesystem': [],
        'networking': [],
    }

    category_scores_api = {
        'crypto': [],
    }

    category_scores_packer = {
        "upx": [],
        "aspack": [],
        "themida": [],
    }

    # dll and apis
    total_score_dlls, matched_dlls, dll_categories = check_dangerous_dlls(file_path)
    total_score_apis, matched_apis, matched_categories_apis = check_registry_apis(file_path)

    # check for known packers
    is_malicious , nop_count = check_for_known_packers(file_path)
    nop_count_scores.append(nop_count)
    
    # check for entropy of sections
    suspicious_strings = extract_strings_and_entropy_from_pe(file_path, entropy_threshold=6)
    if suspicious_strings:
        print(f"[+] Extracted suspicious strings with high entropy: {suspicious_strings}")

    #Track matches and category scores for DLLs
    matched_cats_this_file = set(dll_categories)
    helpers.update_category_scores(matched_cats_this_file, category_scores, 'dlls')

    # Track matches and category scores for APIs
    matched_cats_api_this_file = set(matched_categories_apis)
    helpers.update_category_scores(matched_cats_api_this_file, category_scores_api, 'apis')

    check_for_dangerous_strings(file_path)
    # Collect file analysis details
    scores_details.append({
        'file': file_path,
        'dll_matches': matched_dlls,
        'dll_score': total_score_dlls,
        'apis_matches': matched_apis,
        'apis_score': total_score_apis,
        'packer_found': is_malicious,
        'nop_count': nop_count,
        'obuscated_strings_found': suspicious_strings,
    })

    return total_score_dlls + total_score_apis, category_scores, category_scores_api, category_scores_packer

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
    try:
        is_malicious = False
        # Check aganist known packers 
        sections = helpers.extract_pe_sections(file_path)
        _ , matched_hits , _ = helpers.check_matches(sections, constants.Dangerous_packers, None, weight=constants.INDICATOR_WEIGHTS["packers"])
        # Check for entropy of sections
        is_malicious = analyze_pe_entropy_per_section_data(file_path)
        # Check for NOPs in the file
        nop_count = check_nop_in_pe(file_path)
        if nop_count > 0:
            print(f"[+] Found {nop_count} NOP instructions in {file_path}.")
        
        if matched_hits:
            is_malicious = True

        return is_malicious , nop_count
    except Exception as e:
        print(f"[!] Error processing packers: {e}")
        return False

def extract_strings_and_entropy_from_pe(file_path, entropy_threshold=4.5):
    suspicious_strings = []
    names_and_data = helpers.extract_sections_data(file_path)

    combined_data = b"".join( names_and_data.values())
    
    extracted_strings = helpers.get_strings(combined_data)
    
    for s in extracted_strings:
        entropy = helpers.calculate_entropy(s.encode())  
        if entropy > entropy_threshold:
            suspicious_strings.append((s, entropy))
    
    return suspicious_strings

def analyze_pe_entropy_per_section_data(file_path):
    suspicious_sections = []
    names_and_data = helpers.extract_sections_data(file_path)
    
    for name , raw_data  in names_and_data.items():
        entropy = helpers.calculate_entropy(raw_data)
        print(f"Section: {name:8s} | Entropy: {entropy:.2f}")

        if entropy > 6.5:
            suspicious_sections.append((name, entropy))

    if suspicious_sections:
        return True
    else:
        return False

def check_nop_in_pe(file_path):
    nop_count = 0

    names_and_data = helpers.extract_sections_data(file_path)
    
    for _ , raw_data  in names_and_data.items():
        nop_count += raw_data.count(b'\x90')
        
    return nop_count

def check_for_dangerous_strings(file_path):
    try:
        matched ,result = helpers.scan_file_with_yara(file_path, constants.YARA_RULES_PATH)
        if matched:
            print(f"[+] YARA rules matched for {file_path}: {result.stdout}")
            return True
        else:
            print(f"[!] No YARA rules matched for {file_path}.")
            return False
    except Exception as e:
        print(f"[!] Error running YARA: {e}")
        return False


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