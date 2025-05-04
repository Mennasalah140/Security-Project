import sys
import os
import pefile
import helpers
import constants

# Function to run all indicators on a given file
def run_indicators(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return {
            "is_pe": False,
            "malicious_score": 0,
            "reasons": ["Not a PE file. Skipping analysis."]
        }

    total_score = 0
    reasons = []

    sus_score, sus_funcs = check_suspicious_functions(pe)
    total_score += sus_score
    if sus_funcs:
        reasons.append(f"Suspicious functions found: {', '.join(sus_funcs)}")

    weird_score, weird_secs = check_weird_sections(pe)
    total_score += weird_score
    if weird_secs:
        reasons.append(f"Weird sections: {', '.join(weird_secs)}")

    url_score, urls = check_url_requests(file_path)
    total_score += url_score
    if urls:
        reasons.append(f"Internet usage detected: {', '.join(urls[:3])}...")

    dll_score, _ , _ = check_dangerous_dlls(file_path)
    if dll_score > 15:
        reasons.append(f"High DLL risk score {dll_score}" )

    api_score, _ , _ = check_registry_apis(file_path)
    if api_score > 10:
        reasons.append(f"High API risk score {api_score}")

    packer_flag, nop_count, max_entropy = check_for_known_packers(file_path)
    if packer_flag:
        reasons.append("Detected known packer or suspicious entropy")

    yara_result, ip_and_url = check_for_dangerous_strings(file_path)
    if yara_result:
        reasons.append("YARA rule matched")

    suspicious_strings = extract_strings_and_entropy_from_pe(file_path, entropy_threshold=6.5)
    if suspicious_strings:
        reasons.append("High entropy suspicious strings found")

    is_malicious = (total_score >= 3) or packer_flag or yara_result or len(suspicious_strings) > 2 or (dll_score > 15 and api_score > 10 and (ip_and_url)) or (max_entropy > 6.5 and len(suspicious_strings) > 2)

    return {
        "is_pe": True,
        "malicious_score": total_score,
        "is_malicious": is_malicious,
        "reasons": reasons if reasons else ["No strong indicators found."]
    }

# Function to check for suspicious functions in the exe
def check_suspicious_functions(pe):
    suspicious_found = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 0.0, suspicious_found
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode('utf-8', errors='ignore')
                if name in constants.SUSPICIOUS_FUNCTIONS:
                    suspicious_found.append(name)
    score = (len(suspicious_found)/10)
    return score, suspicious_found

# Function to check for weird sections in the exe
def check_weird_sections(pe):
    found = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if name in constants.WEIRD_SECTION_NAMES:
            found.append(name)
    score = len(found)*3
    return score, found

# Function to check for URLs in the file content
def check_url_requests(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    try:
        decoded = content.decode('utf-8', errors='ignore')
    except:
        return 0.0, []
    urls = constants.URL_PATTERN.findall(decoded)
    score = (len(urls)/10)
    return score, urls

# Function to check for dangerous DLLs
def check_dangerous_dlls(file_path):
    try:
        extracted_dlls = helpers.extract_imported_items(file_path, item_type='dlls')
        total_score, matched_hits, matched_categories = helpers.check_matches(extracted_dlls, constants.DANGEROUS_DLLS, constants.INDICATOR_WEIGHTS["dlls"])
        return total_score, matched_hits, matched_categories
    except Exception as e:
        print(f"[!] Error processing dlls: {e}")
        return 0, {}, set()

# Function to check for dangerous APIs
def check_registry_apis(file_path):
    try:
        extracted_imports = helpers.extract_imported_items(file_path, item_type='apis')
        total_score, matched_hits, matched_categories = helpers.check_matches(extracted_imports, constants.Dangerous_API, constants.INDICATOR_WEIGHTS["apis"])
        return total_score, matched_hits, matched_categories
    except Exception as e:
        print(f"[!] Error processing apis: {e}")
        return 0, {}, set()

# Function to check for known packers
def check_for_known_packers(file_path):
    try:
        is_malicious = False
        sections = helpers.extract_pe_sections(file_path)
        _, matched_hits, _ = helpers.check_matches(sections, constants.DANGEROUS_PACKERS, None, weight=constants.INDICATOR_WEIGHTS["packers"])
        is_malicious, max_entropy = analyze_pe_entropy_per_section_data(file_path)
        nop_count = check_nop_in_pe(file_path)
        if nop_count > 10000:
            print("number of Nop is " , nop_count)
            is_malicious = True
        if matched_hits:
            is_malicious = True
        return is_malicious, nop_count, max_entropy
    except Exception as e:
        print(f"[!] Error processing packers: {e}")
        return False, 0, 0

# Function to extract strings and calculate their entropy
def extract_strings_and_entropy_from_pe(file_path, entropy_threshold=4.5):
    extracted_strings = helpers.get_strings(file_path)
    suspicious_strings = []
    for s in extracted_strings:
        entropy = helpers.calculate_entropy(s.encode())
        if entropy > entropy_threshold:
            suspicious_strings.append((s, entropy))
            print(f"[!] High entropy string detected: {s} with entropy {entropy}")
    return suspicious_strings

# Function to analyze entropy per section data
def analyze_pe_entropy_per_section_data(file_path):
    suspicious_sections = []
    names_and_data = helpers.extract_sections_data(file_path)
    max_entropy = 0
    for name, raw_data in names_and_data.items():
        entropy = helpers.calculate_entropy(raw_data)
        if entropy > max_entropy:
            max_entropy = entropy
        if entropy > 6.75:
            print(f"[!] High entropy detected in section {name}: {entropy}")
            suspicious_sections.append((name, entropy))
    return (True, max_entropy) if suspicious_sections else (False, max_entropy)

# Function to check for number of NOP instructions in PE sections
def check_nop_in_pe(file_path):
    nop_count = 0
    names_and_data = helpers.extract_sections_data(file_path)
    for _, raw_data in names_and_data.items():
        nop_count += raw_data.count(b'\x90')
    return nop_count

# Function to check for dangerous strings using YARA rules 
def check_for_dangerous_strings(file_path):
    try:
        matched, _ , result_length, ip_and_url = helpers.scan_file_with_yara(file_path, constants.YARA_RULES_PATH)
        if matched:
            if (result_length >= 2 and not ip_and_url) or (result_length >= 3 and ip_and_url):
                return True, ip_and_url
            else:
                return False, ip_and_url
        else:
            return False, False
    except Exception as e:
        print(f"[!] Error running YARA: {e}")
        return False, False

