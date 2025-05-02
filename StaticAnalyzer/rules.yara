rule Suspicious_RansomNotes
{
    meta:
        description = "Detects common ransomnote phrases"
        author = "StaticAnalyzer"
    strings:
        $ransom_note1 = "Your files are encrypted" ascii nocase
        $ransom_note2 = "Pay X BTC to decrypt your files" ascii nocase
        $ransom_note3 = "send email to" ascii nocase
        $ransom_note4 = "decrypt your files" ascii nocase
        $ransom_note5 = "recover your files" ascii nocase
        $ransom_note6 = "bitcoins" ascii nocase
        $ransom_note7 = "cryptography" ascii nocase
        $ransom_note8 = "victim" ascii nocase
        $ransom_note9 = "bitcoins wallet" ascii nocase
        $ransom_note10 = "instructions to decrypt" ascii nocase
        $ransom_note11 = "All your files have been encrypted" ascii nocase
        $ransom_note13 = "don't pay" ascii nocase
        $ransom_note14 = "To get the decryption key" ascii nocase
        $ransom_note15 = "your files will be destroyed" ascii nocase
        $ransom_note16 = "Follow the instructions in the attached file to restore your files" ascii nocase
        $ransom_note17 = "Do not try to remove the encryption" ascii nocase
        $ransom_note18 = "If you do not pay, we will publish your files" ascii nocase
        $ransom_note19 = "Your personal data is at risk, pay to restore" ascii nocase
        $ransom_note20 = "Do not try to contact us, we will track you" ascii nocase
    condition:
        any of them
}

rule Suspicious_RansomFilenames
{
    meta:
        description = "Detects ransomnote filenames"
        author = "StaticAnalyzer"
    strings:
        $ransom_file1 = "!!README!!.txt" ascii nocase
        $ransom_file2 = "WannaDecryptor.txt" ascii nocase
        $ransom_file3 = "WannaCryDecrypt.txt" ascii nocase
        $ransom_file4 = "cerber-ransom.html" ascii nocase
        $ransom_file5 = "README.txt" ascii nocase
        $ransom_file6 = "decrypt.html" ascii nocase
        $ransom_file7 = "how_to_decrypt.txt" ascii nocase
        $ransom_file8 = "your_files_are_encrypted.txt" ascii nocase
        $ransom_file9 = "HELP_DECRYPT_YOUR_FILES.txt" ascii nocase
        $ransom_file10 = "DECRYPT_INSTRUCTIONS.txt" ascii nocase
        $ransom_file11 = "readme.txt" ascii nocase
        $ransom_file12 = "YOUR_FILES_ARE_ENCRYPTED.txt" ascii nocase
        $ransom_file13 = "read_me.txt" ascii nocase
        $ransom_file14 = "ransom_note.html" ascii nocase
        $ransom_file15 = "decrypt_instructions.txt" ascii nocase
        $ransom_file16 = "read_me" ascii nocase
        $ransom_file17 = "ransom_note" ascii nocase
        $ransom_file18 = "decrypt_instructions" ascii nocase
    condition:
        any of them
}

rule Suspicious_IPs_And_URLs
{
    meta:
        description = "Detects IPv4, IPv6 addresses and URLs"
        author = "StaticAnalyzer"
    strings:
        $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/
        $ipv6 = /([a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}/
        $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(\/\S*)?/
    condition:
        any of them
}

rule Suspicious_Paths
{
    meta:
        description = "Detects suspicious file paths"
        author = "StaticAnalyzer"
    strings:
        $path1 = /[a-zA-Z]:\\\\[^\s"']{3,}/
        $path2 = /\\\\Users\\\\[^\\\\]+\\\\/
    condition:
        any of them
}

rule Suspicious_Extensions
{
    meta:
        description = "Detects weird or encrypted extensions"
        author = "StaticAnalyzer"
    strings:
        $weird_ext1 = ".fun"
        $weird_ext2 = ".crypt"
        $weird_ext3 = ".bro"
        $weird_ext4 = ".locky"
        $weird_ext5 = ".enc"

        $encrypted_ext1 = ".locked"
        $encrypted_ext2 = ".encrypted"
        $encrypted_ext4 = ".xtbl"
        $encrypted_ext5 = ".wallet"
        $encrypted_ext6 = ".cerber"
        $encrypted_ext7 = ".cesar"
        $encrypted_ext8 = ".odin"
        $encrypted_ext9 = ".aaa"
        $encrypted_ext10 = ".zepto"
        $encrypted_ext11 = ".virus"
        $encrypted_ext12 = ".ryuk"
        $encrypted_ext13 = ".aesir"
        $encrypted_ext14 = ".escl"
        $encrypted_ext15 = ".fucked"
        $encrypted_ext3 = ".blackmail"
    condition:
        any of them
}

rule Suspicious_KnownGoodExtensionsOverused
{
    meta:
        description = "Triggers if 7 or more common extensions are present"
        author = "StaticAnalyzer"
    strings:
        $ext1 = ".txt"
        $ext2 = ".jpg"
        $ext3 = ".png"
        $ext4 = ".html"
        $ext5 = ".mp4"
        $ext6 = ".doc"
        $ext7 = ".xls"
        $ext8 = ".pdf"
        $ext9 = ".exe"
        $ext10 = ".zip"
    condition:
        7 of them
}

rule Suspicious_Commands
{
    meta:
        description = "Detects suspicious command-line usage"
        author = "StaticAnalyzer"
    strings:
        $cmd1 = "vssadmin delete shadows /all /quiet" ascii nocase
        $cmd2 = "wmic shadowcopy delete" ascii nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled No" ascii nocase
        $cmd4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
        $cmd5 = "powershell -nop -w hidden" ascii nocase
        $cmd6 = "certutil -urlcache -split -f" ascii nocase
        $cmd7 = "bitsadmin /transfer" ascii nocase
        $cmd8 = "cmd.exe /c" ascii nocase
        $cmd9 = "taskkill /F /IM" ascii nocase
        $cmd10 = "sc stop" ascii nocase
        $cmd11 = "netsh interface set interface" ascii nocase
        $cmd12 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $cmd13 = "mshta" ascii nocase
        $cmd14 = "curl -O" ascii nocase
        $cmd15 = "schtasks /create" ascii nocase
        $cmd16 = "del /f /s /q" ascii nocase
        $cmd17 = "echo Y|cacls" ascii nocase
    condition:
        any of them
}

rule Suspicious_AllInOne
{
    meta:
        description = "Triggers if any suspicious group is detected"
        author = "StaticAnalyzer"
    condition:
        any of (Suspicious_*)
}
