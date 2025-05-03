import sys
import os
import pefile
import helpers
import constants

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

    score1, sus_funcs = check_suspicious_functions(pe)
    total_score += score1
    # total_score += score1 * constants.FINAL_INDICATOR_WEIGHTS["suspicious_functions"]
    # print(f"[+] Suspicious Function Score: {score1:.2f} | Found: {', '.join(sus_funcs) if sus_funcs else 'None'}")
    if sus_funcs:
        reasons.append(f"Suspicious functions found: {', '.join(sus_funcs)}")

    score2, weird_secs = check_weird_sections(pe)
    total_score += score2 
    # * constants.FINAL_INDICATOR_WEIGHTS["weird_sections"]
    # print(f"[+] Weird Section Score: {score2:.2f} | Found: {', '.join(weird_secs) if weird_secs else 'None'}")
    if weird_secs:
        reasons.append(f"Weird sections: {', '.join(weird_secs)}")

    score3, urls = check_url_requests(file_path)
    total_score += score3 
    # * constants.FINAL_INDICATOR_WEIGHTS["url_usage"]
    # print(f"[+] URL Usage Score: {score3:.2f} | Found: {', '.join(urls[:3]) + '...' if urls else 'None'}")
    if urls:
        reasons.append(f"Internet usage detected: {', '.join(urls[:3])}...")

    dll_score, dll_matches, dll_categories = check_dangerous_dlls(file_path)
    # total_score += min(1.0, dll_score / 10.0) * constants.FINAL_INDICATOR_WEIGHTS["dlls"] 
    # print(f"[+] DLL Score: {dll_score} | Matches: {dll_matches} | Categories: {dll_categories}")
    if dll_score > 5:
        reasons.append("High DLL risk score")

    api_score, api_matches, api_categories = check_registry_apis(file_path)
    # total_score += min(1.0, api_score / 10.0) * constants.FINAL_INDICATOR_WEIGHTS["apis"]
    # print(f"[+] API Score: {api_score} | Matches: {api_matches} | Categories: {api_categories}")
    if api_score > 5:
        reasons.append("High API risk score")

    packer_flag, nop_count, max_entropy = check_for_known_packers(file_path)
    # packer_score = 1.0 if packer_flag else 0.0
    # total_score += packer_score * constants.FINAL_INDICATOR_WEIGHTS["packers"]
    # print(f"[+] Packer/Entropy/NOP Check: Malicious={packer_flag} | NOPs={nop_count} | Max Entropy={max_entropy:.2f}")
    if packer_flag:
        reasons.append("Detected known packer or suspicious entropy")

    yara_result, ip_and_url = check_for_dangerous_strings(file_path)
    # yara_score = 1.0 if yara_result else 0.0
    # total_score += yara_score * constants.FINAL_INDICATOR_WEIGHTS["yara"]
    # print(f"[+] YARA Match: {yara_result} | IP/URL detected: {ip_and_url}")
    if yara_result:
        reasons.append("YARA rule matched")

    suspicious_strings = extract_strings_and_entropy_from_pe(file_path, entropy_threshold=6.0)
    # entropy_score = min(1.0, len(suspicious_strings) / 5.0)
    # total_score += entropy_score * constants.FINAL_INDICATOR_WEIGHTS["entropy_strings"]
    # print(f"[+] Suspicious High-Entropy Strings (>{6.0}): {len(suspicious_strings)} found")
    if suspicious_strings:
        reasons.append("High entropy suspicious strings found")

    is_malicious = (total_score >= 3) or (packer_flag or yara_result or len(suspicious_strings) > 1 or nop_count > 5000 or (dll_score > 10 and api_score > 10 and (ip_and_url or max_entropy >=6)))

    return {
        "is_pe": True,
        "malicious_score": total_score,
        "is_malicious": is_malicious,
        "reasons": reasons if reasons else ["No strong indicators found."]
    }

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
    score = len(suspicious_found)
    return score, suspicious_found

def check_weird_sections(pe):
    found = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if name in constants.WEIRD_SECTION_NAMES:
            found.append(name)
    score = len(constants.WEIRD_SECTION_NAMES)
    return score, found

def check_url_requests(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    try:
        decoded = content.decode('utf-8', errors='ignore')
    except:
        return 0.0, []
    urls = constants.URL_PATTERN.findall(decoded)
    score = len(urls)
    return score, urls

def check_dangerous_dlls(file_path):
    try:
        extracted_dlls = helpers.extract_imported_items(file_path, item_type='dlls')
        total_score, matched_hits, matched_categories = helpers.check_matches(extracted_dlls, constants.DANGEROUS_DLLS, constants.INDICATOR_WEIGHTS["dlls"])
        return total_score, matched_hits, matched_categories
    except Exception as e:
        print(f"[!] Error processing dlls: {e}")
        return 0, {}, set()

def check_registry_apis(file_path):
    try:
        extracted_imports = helpers.extract_imported_items(file_path, item_type='apis')
        total_score, matched_hits, matched_categories = helpers.check_matches(extracted_imports, constants.Dangerous_API, constants.INDICATOR_WEIGHTS["apis"])
        return total_score, matched_hits, matched_categories
    except Exception as e:
        print(f"[!] Error processing apis: {e}")
        return 0, {}, set()

def check_for_known_packers(file_path):
    try:
        is_malicious = False
        sections = helpers.extract_pe_sections(file_path)
        _, matched_hits, _ = helpers.check_matches(sections, constants.Dangerous_packers, None, weight=constants.INDICATOR_WEIGHTS["packers"])
        is_malicious, max_entropy = analyze_pe_entropy_per_section_data(file_path)
        nop_count = check_nop_in_pe(file_path)
        if nop_count > 4000:
            # print(f"[+] Found {nop_count} NOP instructions in {file_path}.")
            is_malicious = True
        if matched_hits:
            is_malicious = True
        return is_malicious, nop_count, max_entropy
    except Exception as e:
        print(f"[!] Error processing packers: {e}")
        return False, 0, 0

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
    for name, raw_data in names_and_data.items():
        entropy = helpers.calculate_entropy(raw_data)
        # print(f"Section: {name:8s} | Entropy: {entropy:.2f}")
        if entropy > max_entropy:
            max_entropy = entropy
        if entropy > 6.75:
            suspicious_sections.append((name, entropy))
    return (True, max_entropy) if suspicious_sections else (False, max_entropy)

def check_nop_in_pe(file_path):
    nop_count = 0
    names_and_data = helpers.extract_sections_data(file_path)
    for _, raw_data in names_and_data.items():
        nop_count += raw_data.count(b'\x90')
    return nop_count

def check_for_dangerous_strings(file_path):
    try:
        matched, result, result_length, ip_and_url = helpers.scan_file_with_yara(file_path, constants.YARA_RULES_PATH)
        if matched:
            # print(f"[+] YARA rules matched for {file_path}: {result}")
            if (result_length >= 2 and not ip_and_url) or (result_length >= 3 and ip_and_url):
                return True, ip_and_url
            else:
                return False, ip_and_url
        else:
            # print(f"[!] No YARA rules matched for {file_path}.")
            return False, False
    except Exception as e:
        print(f"[!] Error running YARA: {e}")
        return False, False

def recursive_file_search(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths
