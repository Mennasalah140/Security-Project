'''
This module contains the helpers for the static analysis of the code.
Any functions that are used multiple times in the code should be placed here.
'''
import statistics
import pefile

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


def check_matches(imported_items, items_to_check, category_weights):
    total_score = 0
    matched_items = {}
    matched_categories = set()

    for category, items in items_to_check.items():
        for item in imported_items:
            if item in items:  
                matched_categories.add(category)
                total_score += category_weights.get(category, 1.0)

    return total_score, matched_items , matched_categories


def calculate_statistics(scores):
    return {
        'max': max(scores) if scores else 0,
        'min': min(scores) if scores else 0,
        'average': statistics.mean(scores) if scores else 0
    }