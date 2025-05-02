import indicators
import helpers as helpers

def analyze_file(file_path, category_scores, category_scores_api, category_scores_packer, scores_details):
    score_dlls, matched_dlls, dll_categories = indicators.check_dangerous_dlls(file_path)
    score_apis, matched_apis, matched_categories_apis = indicators.check_registry_apis(file_path)
    
    total_file_score = score_dlls + score_apis

    # Track matches and category scores for DLLs
    matched_cats_this_file = set(dll_categories)
    helpers.update_category_scores(matched_cats_this_file, category_scores, 'dlls')

    # Track matches and category scores for APIs
    matched_cats_api_this_file = set(matched_categories_apis)
    helpers.update_category_scores(matched_cats_api_this_file, category_scores_api, 'apis')

    # Track packer scores and add to the respective packer categories
    score_packers, matched_packers, packer_categories = indicators.check_for_known_packers(file_path)
    for packer in matched_packers:
        category_scores_packer[packer].append(indicators.INDICATOR_WEIGHTS['packers'].get(packer, 1))

    # Collect file analysis details
    scores_details.append({
        'file': file_path,
        'dll_matches': matched_dlls,
        'dll_score': score_dlls,
        'apis_matches': matched_apis,
        'apis_score': score_apis,
        'packer_matches': matched_packers,
        'packer_score': score_packers,
        'total_score': total_file_score
    })

    return total_file_score

def main():
    directory_path = input("Enter the directory path to analyze: ")

    total_matches = set()
    total_score = 0
    total_indicators = 0
    scores_details = []

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

    total_scores_list = []
    benign_file_count = 0
    total_file_count = 0

    for file_path in indicators.recursive_file_search(directory_path):
        print(f"\nAnalyzing: {file_path}")
        total_file_count += 1

        total_file_score = analyze_file(file_path, category_scores, category_scores_api, category_scores_packer, scores_details)
        total_scores_list.append(total_file_score)

        if total_file_score <= 6:
            benign_file_count += 1

        total_score += total_file_score
        total_indicators += 1

    # Print the final results
    helpers.print_final_results(total_matches, total_score, total_scores_list, benign_file_count, total_file_count, category_scores, category_scores_api, category_scores_packer, scores_details)

if __name__ == "__main__":
    main()