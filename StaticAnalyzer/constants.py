import re

# Suspicious API functions commonly used in malware
SUSPICIOUS_FUNCTIONS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "LoadLibrary", "WinExec", "ShellExecute","URLDownloadToFile", 
    "InternetOpen", "InternetConnect", "HttpSendRequest", "GetProcAddress",
]

# Sections with strange or suspicious names
WEIRD_SECTION_NAMES = [
    ".textbss", "UPX0", "UPX1", ".packed", ".rsrcbss", ".fake", ".adata"
]

# Regular expressions for URL patterns
URL_PATTERN = re.compile(r"(http[s]?://|www\.)[a-zA-Z0-9.\-_/]+")

# Weights for different indicators and their sub categories
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

# Dangerous DLLs that are commonly used in malware
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

# Dangerous APIS that are commonly used in malware
Dangerous_API = {
    "crypto": {
        "cryptgenrandom", "cryptacquirecontextw", "cryptreleasecontext", "cryptprotectdata", "cryptsetkeyparam" , "cryptdecrypt", "cryptencrypt",
        "cryptcreatehash", "crypthashdata", "cryptverifysignature", "cryptsignhashw", "cryptimportkey", "cryptexportkey" , 
         "cryptdestroyhash"
    },
}

# Dangerous packers siginatures
DANGEROUS_PACKERS = {
    'UPX': [b'\x55\x8B\xEC\x83\xEC\x10\x53\x56'],  
    'Themida': [b'\x4D\x5A\x90\x00\x00\x00\x00'],  
    'ASPack': [b'\x43\x52\x59\x50'],  
}

# Path to YARA rules file and strings executable 
# TODO: Change this to the correct path for your system
YARA_RULES_PATH = "D:/Handasa/Security/Shared_VM/Security-Project/StaticAnalyzer/rules.yara" 
STRINGS_PATH = "D:/Handasa/Security/Shared_VM/Strings/strings.exe"