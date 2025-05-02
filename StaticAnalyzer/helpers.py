'''
This module contains the helpers for the static analysis of the code.
Any functions that are used multiple times in the code should be placed here.
'''
import math
import statistics
import subprocess
import constants
import pefile
import yara 

def extract_sections_data(file_path):
    try:
        pe = pefile.PE(file_path)
        dict = {} 
        for section in pe.sections:
            dict[section.Name.decode().lower().split("\x00")[0]] = section.get_data()
        return dict
    except Exception as e:
        print(f"[!] Error extracting sections data for {file_path}: {e}")
        return {}
    
def extract_pe_sections(file_path):
    sections = []
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            sections.append(section.Name.decode().lower().split("\x00")[0])
        print(f"[+] Extracted sections from {file_path}: {sections}")
    except Exception as e:
        print(f"[!] Error extracting PE sections for {file_path}: {e}")
    
    return sections

def extract_imported_items(file_path, item_type='dlls'):
    imported_items = set()
    try:
        pe = pefile.PE(file_path)

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if item_type == 'dlls':
                    dll_name = entry.dll.decode().lower()
                    imported_items.add(dll_name)
                elif item_type == 'apis':
                    for imp in entry.imports:
                        if imp.name:
                            imported_items.add(imp.name.decode().lower())
        
    except Exception as e:
        print(f"[!] Error processing file: {e}")
    
    return imported_items 

def check_matches(imported_items, items_to_check, category_weights = None , weight=1.0):
    total_score = 0
    matched_items = {}
    matched_categories = set()

    for category, items in items_to_check.items():
        for item in imported_items:
            if item in items:  
                matched_categories.add(category)
                if category_weights:
                    total_score += category_weights.get(category, 1.0)
                else:
                    total_score += weight

    return total_score, matched_items , matched_categories

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

def get_strings(file_path):
    try:
        result = subprocess.run(
            [constants.Strings_PATH, file_path],
            capture_output=True,
            text=True,
            check=True
        )
        strings_output = result.stdout.splitlines()
        return strings_output
    except Exception as e:
        print(f"[!] Error extracting strings: {e}")
        return []

def scan_file_with_yara(file_path, yara_file_path):
    rules = yara.compile(filepath=yara_file_path)  
    matches = rules.match(file_path)
    ip_and_url = False
    length = 0
    if matches:
        for match in matches:
            length +=1
            print(f"Rule matched: {match.rule}")
            if match.rule == "Suspicious_IPs_And_URLs":
                ip_and_url = True
        return True, matches , length  , ip_and_url
    else:
        return False, None , 0, False

