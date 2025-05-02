rule RansomNoteDetection
{
    meta:
        description = "Detects ransom note strings commonly found in ransomware"
        author = "StaticAnalyzer"
        last_modified = "2025-05-02"
        tags = "ransomware , ransom_note"

    strings:
        $ransom_note1 = "Your files are encrypted" ascii
        $ransom_note2 = "Pay X BTC to decrypt your files" ascii
        $ransom_note3 = "send email to" ascii
        $ransom_note4 = "decrypt your files" ascii
        $ransom_note5 = "recover your files" ascii
        $ransom_note6 = "bitcoins" ascii
        $ransom_note7 = "cryptography" ascii
        $ransom_note8 = "victim" ascii
        $ransom_note9 = "bitcoins wallet" ascii
        $ransom_note10 = "instructions to decrypt" ascii
        $ransom_note11 = "All your files have been encrypted" ascii
        $ransom_note13 = "don't pay" ascii
        $ransom_note14 = "To get the decryption key" ascii
        $ransom_note15 = "your files will be destroyed" ascii
        $ransom_note16 = "Follow the instructions in the attached file to restore your files" ascii
        $ransom_note17 = "Do not try to remove the encryption" ascii
        $ransom_note18 = "If you do not pay, we will publish your files" ascii
        $ransom_note19 = "Your personal data is at risk, pay to restore" ascii
        $ransom_note20 = "Do not try to contact us, we will track you" ascii

        // WannaCry
        $ransom_file1 = "!!README!!.txt" ascii
        $ransom_file2 = "WannaDecryptor.txt" ascii
        $ransom_file3 = "WannaCryDecrypt.txt" ascii

        // Cerber Ransomware
        $ransom_file4 = "cerber-ransom.html" ascii
        $ransom_file5 = "README.txt" ascii
        $ransom_file6 = "decrypt.html" ascii

        // TeslaCrypt
        $ransom_file7 = "how_to_decrypt.txt" ascii
        $ransom_file8 = "your_files_are_encrypted.txt" ascii
        $ransom_file9 = "HELP_DECRYPT_YOUR_FILES.txt" ascii

        // CryptoLocker
        $ransom_file10 = "DECRYPT_INSTRUCTIONS.txt" ascii
        $ransom_file11 = "readme.txt" ascii
        $ransom_file12 = "YOUR_FILES_ARE_ENCRYPTED.txt" ascii

        // Common ransom-related file names
        $ransom_file13 = "read_me.txt" ascii
        $ransom_file14 = "ransom_note.html" ascii
        $ransom_file15 = "decrypt_instructions.txt" ascii
        $ransom_file16 = "read_me" ascii
        $ransom_file17 = "ransom_note" ascii
        $ransom_file18 = "decrypt_instructions" ascii

    condition:
        any of ($ransom_note*) or
        any of ($ransom_file*)
}

rule EncryptedFileExtensions
{
    meta:
        description = "Detects common file extensions used by ransomware for encrypted files"
        author = "StaticAnalyzer"
        last_modified = "2025-05-02"
        tags = "ransomware, file_extension"

    strings:
        // Common ransomware-encrypted file extensions
        $encrypted_ext1 = ".locked" ascii
        $encrypted_ext2 = ".crypt" ascii
        $encrypted_ext3 = ".encrypted" ascii
        $encrypted_ext4 = ".rtf" ascii  // Some ransomware encrypts RTF files
        $encrypted_ext5 = ".xtbl" ascii  // Locky ransomware extension
        $encrypted_ext6 = ".wallet" ascii  // Crysis or CryptoTor ransomware extension
        $encrypted_ext7 = ".cerber" ascii  // Cerber ransomware extension
        $encrypted_ext8 = ".cesar" ascii  // Cesar ransomware extension
        $encrypted_ext9 = ".odin" ascii  // Odin ransomware extension
        $encrypted_ext10 = ".aaa" ascii  // TeslaCrypt or other variants
        $encrypted_ext11 = ".zepto" ascii  // Zepto ransomware extension
        $encrypted_ext12 = ".virus" ascii  // Often used by file-encrypting malware
        $encrypted_ext13 = ".locky" ascii  // Locky ransomware variant extension
        $encrypted_ext14 = ".ryuk" ascii  // Ryuk ransomware extension
        $encrypted_ext15 = ".aesir" ascii  // Aesir ransomware extension
        $encrypted_ext16 = ".escl" ascii  // Some variants of ransomware (e.g., ExoticRansomware)
        $encrypted_ext17 = ".fucked" ascii  // Used by certain ransomware variants to mark encrypted files
        $encrypted_ext18 = ".blackmail" ascii  // Used by certain blackmail-based ransomware

    condition:
        any of ($encrypted_ext*)
}
