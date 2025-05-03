import re

# Suspicious API functions commonly used in malware
SUSPICIOUS_FUNCTIONS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "GetProcAddress", "LoadLibrary", "WinExec", "ShellExecute",
    "URLDownloadToFile", "InternetOpen", "InternetConnect", "HttpSendRequest",
]

# Sections with strange or suspicious names
WEIRD_SECTION_NAMES = [
    ".textbss", "UPX0", "UPX1", ".packed", ".rsrcbss", ".fake", ".adata"
]

# Regular expressions for URL patterns
URL_PATTERN = re.compile(r"(http[s]?://|www\.)[a-zA-Z0-9.\-_/]+")

# Weights (customize these based on importance)
FINAL_INDICATOR_WEIGHTS = {
    "suspicious_functions": 0.15,
    "weird_sections": 0.1,
    "url_usage": 0.1,
    "dlls": 0.15,
    "apis": 0.15,
    "packers": 0.15,
    "yara": 0.1,
    "entropy_strings": 0.1,
}

INDICATOR_WEIGHTS = {
    "dlls": {
        'filesystem': 0.5, 
        'crypto': 5, 
        'networking': 2 
    },
    "apis": {
        'crypto': 5,
    },
    "packers": 1, 
}

DANGEROUS_DLLS = {
    "crypto": {
        "rundll32.exe", "advapi32.dll", "bcrypt.dll", "ncrypt.dll", "crypt32.dll", "wincrypt.h" 
    },
    "filesystem": {
        "kernel32.dll", "shell32.dll", "shlwapi.dll", "ntdll.dll", "ole32.dll"
    },
    "networking": {
        "wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll", "httpapi.dll", "dnsapi.dll"
    }
}

Dangerous_API = {
    "crypto": {
        "cryptgenrandom", "cryptacquirecontextw", "cryptreleasecontext", "cryptprotectdata", "cryptsetkeyparam" , "cryptdecrypt", "cryptencrypt",
        "cryptcreatehash", "crypthashdata", "cryptverifysignature", "cryptsignhashw", "cryptimportkey", "cryptexportkey" , 
         "cryptdestroyhash"
    },
}

Dangerous_packers = {
    'UPX': [b'\x55\x8B\xEC\x83\xEC\x10\x53\x56'],  
    'Themida': [b'\x4D\x5A\x90\x00\x00\x00\x00'],  
    'ASPack': [b'\x43\x52\x59\x50'],  
}

YARA_RULES_PATH = "C:/Users/maria/OneDrive/Desktop/projects/Security-Project/StaticAnalyzer/rules.yara" 
Strings_PATH = "C:/Users/maria/Downloads/Strings/strings.exe"