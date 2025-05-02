INDICATOR_WEIGHTS = {
    "dlls": {
        'filesystem': 0.5, # Very common, but not always malicious
        'crypto': 5, # % in safe files
        'networking': 2 # very low in safe files
    },
    "apis": {
        'crypto': 5,
    },
    "packers": 1, # To be decided later
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
    'UPX': [b'\x55\x8B\xEC\x83\xEC\x10\x53\x56'],  # UPX decompression stub signature (example)
    'Themida': [b'\x4D\x5A\x90\x00\x00\x00\x00'],  # Themida unpacking stub (example pattern)
    'ASPack': [b'\x43\x52\x59\x50'],  # ASPack signature example (could vary based on version) 
}


YARA_RULES_PATH = "C:/Users/maria/OneDrive/Desktop/projects/Security-Project/StaticAnalyzer/rules.yara" 
