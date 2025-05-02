import indicators
import helpers as helpers


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

    total_scores_list = []
    benign_file_count = 0
    total_file_count = 0

    for file_path in indicators.recursive_file_search(directory_path):
        print(f"\nAnalyzing: {file_path}")
        total_file_count += 1

        # DLL analysis
        score_dlls, matched_dlls, dll_categories = indicators.check_dangerous_dlls(file_path)
        total_matches.update([item for sublist in matched_dlls.values() for item in sublist])
        total_score += score_dlls
        total_indicators += 1

        # Track which categories were matched for this file
        matched_cats_this_file = set(dll_categories)

        for category in category_scores.keys():
            if category in matched_cats_this_file:
                weight = indicators.INDICATOR_WEIGHTS['dlls'].get(category, 0)
                category_scores[category].append(weight)
            else:
                category_scores[category].append(0)

        # API analysis
        score_apis, matched_apis , matched_categories_apis = indicators.check_registry_apis(file_path)
        total_matches.update([item for sublist in matched_apis.values() for item in sublist])
        total_score += score_apis
        total_indicators += 1

        total_file_score = score_dlls + score_apis
        total_scores_list.append(total_file_score)

        if total_file_score <= 6:
            benign_file_count += 1

        # Track API category scores
        matched_cats_api_this_file = set(matched_categories_apis)

        for category in category_scores_api.keys():
            if category in matched_cats_api_this_file:
                weight = indicators.INDICATOR_WEIGHTS['apis'].get(category, 0)
                category_scores_api[category].append(weight)
            else:
                category_scores_api[category].append(0)

        scores_details.append({
            'file': file_path,
            'dll_matches': matched_dlls,
            'dll_score': score_dlls,
            'apis_matches': matched_apis,
            'apis_score': score_apis,
            'total_score': total_file_score
        })

    average_score = total_score / total_indicators if total_indicators > 0 else 0

    print("\nTotal Matches:", total_matches)
    print("Total Score:", total_score)
    print("Average Score:", average_score)

    # Total score statistics
    print("\nTotal Score Statistics:")
    print(f"Max Total Score: {max(total_scores_list)}")
    print(f"Min Total Score: {min(total_scores_list)}")
    print(f"Average Total Score: {sum(total_scores_list)/len(total_scores_list):.2f}")

    # Benign / unsafe classification
    #print(f"Benign Files (Score ≤ 3): {benign_file_count}")
    unsafe_file_count = total_file_count - benign_file_count
    unsafe_percentage = (unsafe_file_count / total_file_count * 100) if total_file_count > 0 else 0
    print(f"Unsafe Files: {unsafe_file_count} ({unsafe_percentage:.2f}%)")

    # Category stats for DLLs
    for category, scores in category_scores.items():
        stats = helpers.calculate_statistics(scores)
        print(f"\n{category.capitalize()} Category Stats (DLL):")
        print(f"Max: {stats['max']}, Min: {stats['min']}, Average: {stats['average']:.2f}")

    # Category stats for APIs
    for category, scores in category_scores_api.items():
        stats = helpers.calculate_statistics(scores)
        print(f"\n{category.capitalize()} Category Stats (API):")
        print(f"Max: {stats['max']}, Min: {stats['min']}, Average: {stats['average']:.2f}")

    print("\nScores Details (for tuning):")
    for detail in scores_details:
        print(f"File: {detail['file']}")
        print(f"  DLL Matches: {detail['dll_matches']} | DLL Score: {detail['dll_score']}")
        print(f"  API Matches: {detail['apis_matches']} | API Score: {detail['apis_score']}")
        print(f"  Total Score: {detail['total_score']}")
        print("------")

if __name__ == "__main__":
    main()
