import pefile
import re

# Suspicious API functions commonly used in malware
SUSPICIOUS_FUNCTIONS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "LoadLibrary", "WinExec", "ShellExecute", "URLDownloadToFile", 
    "InternetOpen", "InternetConnect", "HttpSendRequest", "GetProcAddress"
]

# Sections with strange or suspicious names
WEIRD_SECTION_NAMES = [
    ".textbss", "UPX0", "UPX1", ".packed", ".rsrcbss", ".fake", ".adata"
]

# Regular expressions for URL patterns
URL_PATTERN = re.compile(
    r"(http[s]?://|www\.)[a-zA-Z0-9.\-_/]+"
)

# Weights (customize these based on importance)
INDICATOR_WEIGHTS = {
    "suspicious_functions": 0.5,
    "weird_sections": 0.2,
    "url_usage": 0.3,
}


def check_suspicious_functions(pe):
    suspicious_found = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 0.0, suspicious_found

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode('utf-8', errors='ignore')
                if name in SUSPICIOUS_FUNCTIONS:
                    suspicious_found.append(name)

    score = len(suspicious_found)
    return score, suspicious_found


def check_weird_sections(pe):
    found = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if name in WEIRD_SECTION_NAMES:
            found.append(name)

    score = len(found)
    return score, found


def check_url_requests(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()

    try:
        decoded = content.decode('utf-8', errors='ignore')
    except:
        return 0.0, []

    urls = URL_PATTERN.findall(decoded)
    score = len(urls)  # Cap the effect
    return score, urls


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

    # Check suspicious functions
    score1, sus_funcs = check_suspicious_functions(pe)
    total_score += score1 
    # total_score += score1 * INDICATOR_WEIGHTS["suspicious_functions"]
    if sus_funcs:
        reasons.append(f"Suspicious functions found: {', '.join(sus_funcs)}")

    # Check weird sections
    score2, weird_secs = check_weird_sections(pe)
    total_score += score2
    # total_score += score2 * INDICATOR_WEIGHTS["weird_sections"]
    if weird_secs:
        reasons.append(f"Weird sections: {', '.join(weird_secs)}")

    # Check for URL or Internet usage
    score3, urls = check_url_requests(file_path)
    total_score += score3 
    # total_score += score3 * INDICATOR_WEIGHTS["url_usage"]
    if urls:
        reasons.append(f"Internet usage detected: {', '.join(urls[:3])}...")

    # Decision threshold
    threshold = 3
    is_malicious = total_score >= threshold

    return {
        "is_pe": True,
        "malicious_score": total_score ,
        "is_malicious": is_malicious,
        "reasons": reasons if reasons else ["No strong indicators found."]
    }
