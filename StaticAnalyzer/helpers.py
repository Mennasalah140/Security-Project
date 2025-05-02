'''
This module contains the helpers for the static analysis of the code.
Any functions that are used multiple times in the code should be placed here.
'''
import math
import statistics
import constants
import pefile
import yara 
import re

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

def get_strings(data, min_length=4):
    """
    Extract printable strings from binary data.
    :param data: Binary data to extract strings from.
    :param min_length: Minimum length of strings to extract.
    :return: List of extracted printable strings.
    """
    pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
    value = [match.decode('utf-8', errors='ignore') for match in re.findall(pattern, data)]    
    filtered_value = [s for s in value if len(s) >= min_length]
    return filtered_value

def scan_file_with_yara(file_path, yara_file_path):
    rules = yara.compile(filepath=yara_file_path)  # not filepaths=...
    matches = rules.match(file_path)
    
    if matches:
        return True, matches
    else:
        return False, None


def calculate_statistics(scores):
    return {
        'max': max(scores) if scores else 0,
        'min': min(scores) if scores else 0,
        'average': statistics.mean(scores) if scores else 0
    }

def update_category_scores(matched_categories, category_scores, category_name, category_type='dlls'):
    """
    Updates the category scores for a given category (DLLs, APIs, Packets).
    
    :param matched_categories: Set of matched categories for this file
    :param category_scores: Dictionary to hold category scores for the corresponding category type
    :param category_name: Name of the category (e.g., 'dlls', 'apis', 'packers')
    :param category_type: Type of indicator ('dlls', 'apis', 'packers') to check weights from the respective INDICATOR_WEIGHTS
    """
    for category in category_scores.keys():
        weight = constants.INDICATOR_WEIGHTS[category_type].get(category, 0) if category in matched_categories else 0
        category_scores[category].append(weight)

def calculate_and_print_statistics(category_scores, category_name):
    stats = calculate_statistics(category_scores)
    print(f"\n{category_name} Category Stats:")
    print(f"Max: {stats['max']}, Min: {stats['min']}, Average: {stats['average']:.2f}")

def print_final_results(total_matches, total_score, total_scores_list, benign_file_count, total_file_count, category_scores, category_scores_api, category_scores_packer, scores_details):
    print("\nTotal Matches:", total_matches)
    print("Total Score:", total_score)
    print("Average Score:", total_score / len(scores_details) if scores_details else 0)

    # Total score statistics
    print("\nTotal Score Statistics:")
    print(f"Max Total Score: {max(total_scores_list)}")
    print(f"Min Total Score: {min(total_scores_list)}")
    print(f"Average Total Score: {sum(total_scores_list) / len(total_scores_list):.2f}")

    # Benign / unsafe classification
    unsafe_file_count = total_file_count - benign_file_count
    unsafe_percentage = (unsafe_file_count / total_file_count * 100) if total_file_count > 0 else 0
    print(f"Unsafe Files: {unsafe_file_count} ({unsafe_percentage:.2f}%)")

    # Category stats for DLLs
    for category, scores in category_scores.items():
        calculate_and_print_statistics(scores, f"{category.capitalize()} Category (DLL)")

    # Category stats for APIs
    for category, scores in category_scores_api.items():
        calculate_and_print_statistics(scores, f"{category.capitalize()} Category (API)")

    # Category stats for Packers
    for packer, scores in category_scores_packer.items():
        calculate_and_print_statistics(scores, f"{packer.capitalize()} Category (Packer)")

    print("\nScores Details (for tuning):")
    for detail in scores_details:
        print(f"File: {detail['file']}")
        print(f"  DLL Matches: {detail['dll_matches']} | DLL Score: {detail['dll_score']}")
        print(f"  API Matches: {detail['apis_matches']} | API Score: {detail['apis_score']}")
        print(f"  Packer found: {detail['packer_found']}")
        print(f"  Obuscated strings: {detail['obuscated_strings_found']}")
        print("------")