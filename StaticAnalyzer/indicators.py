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
def run_indicators(file_path):
    '''
    This function runs all the indicators and returns if it's malicious or not.
    '''
    try:
        # Check for dangerous DLLs
        dll_score, dll_matches, dll_categories = check_dangerous_dlls(file_path)
        print(f"[+] DLL Score: {dll_score}, Matches: {dll_matches}, Categories: {dll_categories}")

        # Check for dangerous APIs
        api_score, api_matches, api_categories = check_registry_apis(file_path)
        print(f"[+] API Score: {api_score}, Matches: {api_matches}, Categories: {api_categories}")

        # Check for known packers
        is_malicious, nop_count , max_entropy = check_for_known_packers(file_path)
        print(f"[+] NOP Count: {nop_count} , max_entropy {max_entropy}" )

        # Check for dangerous strings using YARA rules
        yara_result , ip_and_url = check_for_dangerous_strings(file_path)

        # Extract strings and calculate entropy
        suspicious_strings = extract_strings_and_entropy_from_pe(file_path , entropy_threshold=6.0)
        print(f"[+] Suspicious Strings: {suspicious_strings}")

        return is_malicious or yara_result or len(suspicious_strings) > 1 or nop_count > 5000 or (dll_score > 5 and api_score > 5 and (ip_and_url or max_entropy >=6))

    except Exception as e:
        print(f"[!] Error running indicators: {e}")
        return 0, False, False
    

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
        is_malicious , max_entropy= analyze_pe_entropy_per_section_data(file_path)
        # Check for NOPs in the file
        nop_count = check_nop_in_pe(file_path)
        if nop_count > 4000:
            print(f"[+] Found {nop_count} NOP instructions in {file_path}.")
            is_malicious = True
        
        if matched_hits:
            is_malicious = True

        return is_malicious , nop_count , max_entropy
    except Exception as e:
        print(f"[!] Error processing packers: {e}")
        return False , 0 , 0

def extract_strings_and_entropy_from_pe(file_path, entropy_threshold=4.5):
    extracted_strings = helpers.get_strings(file_path)
    suspicious_strings = []
    
    for s in extracted_strings:
        entropy = helpers.calculate_entropy(s.encode())  
        if entropy > entropy_threshold:
            suspicious_strings.append((s, entropy))
    
    return suspicious_strings

def analyze_pe_entropy_per_section_data(file_path):
    suspicious_sections = []
    names_and_data = helpers.extract_sections_data(file_path)
    max_entropy = 0

    for name , raw_data  in names_and_data.items():
        entropy = helpers.calculate_entropy(raw_data)
        print(f"Section: {name:8s} | Entropy: {entropy:.2f}")
        if entropy > max_entropy:
            max_entropy = entropy

        if entropy > 6.75:
            suspicious_sections.append((name, entropy))

    if suspicious_sections:
        return True , max_entropy
    else:
        return False , 0 

def check_nop_in_pe(file_path):
    nop_count = 0

    names_and_data = helpers.extract_sections_data(file_path)
    
    for _ , raw_data  in names_and_data.items():
        nop_count += raw_data.count(b'\x90')
        
    return nop_count

def check_for_dangerous_strings(file_path):
    '''
    returns 2 arguments :
    1. if any rule matched other than ip and urls 
    2. if any ip and urls matched
    '''
    try:
        matched , result ,result_length , ip_and_url = helpers.scan_file_with_yara(file_path, constants.YARA_RULES_PATH)
        if matched:
            print(f"[+] YARA rules matched for {file_path}: {result}")
            if  (result_length >= 2 and not ip_and_url) or (result_length >= 3 and ip_and_url):
                return True , ip_and_url
            else:
                return False , ip_and_url
        else:
            print(f"[!] No YARA rules matched for {file_path}.")
            return False , False
    except Exception as e:
        print(f"[!] Error running YARA: {e}")
        return False , False

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