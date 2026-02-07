# Fuzzing Portfolio Project: Heap Overflow Discovery

**Author:** Fuad  
**Date:** February 2026  
**Duration:** 4 days  
**Tools:** Python, GCC, ASan, GDB

## 🎯 Project Overview

Custom mutation-based fuzzer that discovered a heap buffer overflow vulnerability in a JSON parser through automated testing. Includes full vulnerability analysis, proof-of-concept exploit, and remediation recommendations.

## 🔍 Key Achievements

- ✅ Built custom mutation-based fuzzer from scratch
- ✅ Discovered heap buffer overflow (CWE-122) in < 1 second
- ✅ Generated 6+ unique crash samples
- ✅ Achieved 27,000 executions/second fuzzing speed
- ✅ Performed root cause analysis with GDB + ASan
- ✅ Developed working proof-of-concept exploit
- ✅ Documented findings in professional security advisory format

## 📁 Repository Structure
```
fuzzing-project/
├── README.md                    # This file
├── CRASH_TRIAGE_REPORT.md      # Detailed vulnerability analysis
├── poc_heap_overflow.py        # Proof-of-concept exploit
├── fuzzer/
│   ├── fuzzer.py               # Original fuzzer
│   └── simple_fuzz.py          # Simplified working fuzzer
├── target/
│   └── vuln_json/
│       └── vuln_parser.c       # Vulnerable target
├── corpus/                      # Initial seed files (15 files)
└── crashes/                     # Discovered crashes (6+ files)
```

## 🚀 Quick Start

### 1. Compile Target
```bash
cd target/vuln_json
gcc vuln_parser.c -o vuln_parser -g -fsanitize=address -fno-omit-frame-pointer -O1
```

### 2. Run Fuzzer
```bash
cd ~/fuzzing-project
python3 simple_fuzz.py
```

### 3. Test PoC
```bash
python3 poc_heap_overflow.py
```

## 🐛 Vulnerability Details

**Type:** Heap Buffer Overflow (CWE-122)  
**Severity:** HIGH (CVSS 8.6)  
**Location:** `extract_string()` at vuln_parser.c:61  
**Trigger:** JSON value > 64 characters

### Root Cause
```c
32  char* result = malloc(64);  // Fixed allocation
...
61  memcpy(result, start, len);  // No bounds check! 💥
```

### Impact
- Denial of Service (guaranteed crash)
- Memory corruption (heap metadata overwrite)
- Potential RCE (with additional primitives)

## 📊 Test Results

| Test Case | Input Size | Result |
|-----------|-----------|--------|
| Control | 50 bytes | ✅ No crash |
| Edge | 63 bytes | ✅ No crash |
| Minimal Overflow | 65 bytes | ❌ **CRASH** |
| Large Overflow | 100 bytes | ❌ **CRASH** |
| Massive Overflow | 500 bytes | ❌ **CRASH** |

**Crash Boundary:** 64 bytes (exact)  
**Reproducibility:** 100%

## 🔧 Technical Skills Demonstrated

### Fuzzing
- Custom mutation strategies (8 techniques)
- Coverage-guided feedback loop
- Crash deduplication (MD5 hashing)
- High-speed execution (27k/sec)

### Vulnerability Analysis
- Root cause identification
- Memory forensics with GDB
- ASan report interpretation
- CVSS scoring

### Exploit Development
- Controlled overflow demonstration
- Boundary testing
- Automated PoC framework

### Security Engineering
- Compiler hardening (ASan, FORTIFY_SOURCE)
- Secure coding recommendations
- Defense-in-depth strategies

## 📚 Documentation

- **[CRASH_TRIAGE_REPORT.md](CRASH_TRIAGE_REPORT.md)** - Full vulnerability analysis
- **[poc_heap_overflow.py](poc_heap_overflow.py)** - Exploit proof-of-concept

## 🎓 Learning Outcomes

1. **Fuzzing Fundamentals** - Built fuzzer from scratch, understand mutation strategies
2. **Vulnerability Discovery** - Found real bugs in < 1 second of fuzzing
3. **Memory Safety** - Deep understanding of heap overflows
4. **Debugging Tools** - Proficient with GDB, ASan, compiler instrumentation
5. **Security Writing** - Professional CVE-style documentation

## 🔐 Remediation

**Recommended Fix:**
```c
// Use dynamic allocation
int len = end - start;
char* result = malloc(len + 1);  // Exact size needed
```

**Alternative:**
```c
// Add bounds checking
if (len >= 64) len = 63;  // Truncate to fit
```

## 📈 Fuzzer Performance

- **Executions/sec:** 27,000
- **Time to crash:** < 1 second
- **Unique crashes:** 6+
- **False positives:** 0

## 🛠️ Tools Used

- **Python 3** - Fuzzer implementation
- **GCC 11+** - Compilation with sanitizers
- **AddressSanitizer** - Memory error detection
- **GDB** - Debugging and forensics
- **Git** - Version control

## 📞 Contact

**LinkedIn:** [Your LinkedIn]  
**GitHub:** [Your GitHub]  
**Email:** [Your Email]

---

**Note:** This is a security research project on intentionally vulnerable code. Do not use these techniques on systems without authorization.
