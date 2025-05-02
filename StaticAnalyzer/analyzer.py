import indicators
import helpers as helpers


def main():
    directory_path = input("Enter the directory path to analyze: ")
    total_matches = set()
    scores_details = []
    total_score = 0
    
    total_scores_list = []
    benign_file_count = 0
    total_file_count = 0
    nop_count_scores = []

    for file_path in indicators.recursive_file_search(directory_path):
        print(f"\nAnalyzing: {file_path}")
        total_file_count += 1

        total_file_score , category_scores , category_scores_api , category_scores_packer = indicators.run_indicators(file_path , scores_details , nop_count_scores)
        total_scores_list.append(total_file_score)

        if total_file_score <= 6:
            benign_file_count += 1

        total_score += total_file_score

    # Print the final results

    helpers.print_final_results(total_matches, total_score, total_scores_list, benign_file_count, total_file_count, category_scores, category_scores_api, category_scores_packer, scores_details)
    helpers.calculate_and_print_statistics(nop_count_scores, "NOP Count")
if __name__ == "__main__":
    main()