
## 📄 `documentation.md`


## `Indicator.py`

### How do we define a malicious file?

Using a set of **Metrics**

1. **YARA Rules**
2. **Suspicious Functions**
3. **Weird Section Names**
4. **Use of URLs (Internet Connections)**
5. **Dangerous dll**
6. **Dangerous api**
7. **Packers Detection**
8. **High entropy string**



---

**"Suspicious Functions", "Weird Section Names", and "Use of URLs"** are combined into a **total score**,
where:

* **Suspicious functions** and **URLs** have **low weights** since they are present in most safe files
* **Weird section names** is a **cutoff criteria**, since we have only seen it in malicious files (and not all of them 7atta)

---

### Functions Logic 
#### **1. check_suspicious_functions(pe)**

```
    Takes a pe and checks if it has an import table (file that lists external functions (from DLLs)), 
    if it does, python script goes through each imported function from DLLs 
    Decodes the byte string to a regular string using UTF-8. Errors are ignored
    and compares them to a predefined list (SUSPICIOUS_FUNCTIONS)
    then returns the count of these functions and their names 
    
```

---

#### **2. check_weird_sections(pe)**

```
    same as sus_fns but for section names
```

---

#### **3.check_url_requests(file_path)**

```
    checks a file for embedded URLs, which can indicate suspicious behavior (like calling a malicious server)
    Opens the file in binary mode:
    Reads the file’s raw binary content.
    Tries to decode the content into a UTF-8 string:
    Uses a regex pattern to extract URLs:
```

---

#### **4.check_dangerous_dlls(file_path)**

```
Extracts all DLLs imported by the PE file.  
Matches DLLs against a known list of dangerous DLLs.  
Uses weighted scoring per match category.  
Returns a score, matched DLLs, and matched categories.
```

---

#### **5.check_registry_apis(file_path)**

```
Extracts all APIs imported by the PE file.  
Compares them to a list of registry/process-related APIs.  
Uses weighted scoring to determine API severity.  
Returns a score, matched APIs, and matched categories.
```

---

#### **6.check_for_known_packers**

```
Extracts section names and scans for known packer signatures.  
Checks each section’s entropy to detect compression/encryption normally packers make the section have high entropy.  
Counts number of NOP (0x90) instructions in binary as packers have high number of Nop operations.  
Flags if known packer is found, entropy is high, or NOPs exceed 4000.  
Returns boolean flag, NOP count, and max entropy (used in sub criteria).
```

---

#### **7.extract_strings_and_entropy_from_pe**

```
Extracts readable strings from the PE file.  
Calculates entropy for each string.  
Flags strings with entropy above a set threshold (e.g., 6.0).  
Returns list of suspicious (high-entropy) strings.
```

---

#### **8.check_for_dangerous_strings**

```
Uses String libary to extract the strings in the exe
Scans the strings using predefined YARA rules.  
Detects keywords, obfuscation, or shellcode-like patterns.  
Flags based on result length and presence of IPs/URLs (low weight as commonly present).  
Returns boolean match result and whether any IPs/URLs were involved.
```

---


