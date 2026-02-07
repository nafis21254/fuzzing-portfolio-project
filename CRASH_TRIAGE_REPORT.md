# Crash Triage Report: Heap Buffer Overflow in vuln_parser

**Date:** February 7, 2026  
**Researcher:** Fuad  
**Target:** vuln_json/vuln_parser  
**Vulnerability:** CWE-122 (Heap-based Buffer Overflow)  
**CVSS Score:** 8.6 (HIGH)

## Executive Summary

A heap buffer overflow vulnerability was discovered in the `extract_string()` function through automated fuzzing. The vulnerability allows writing arbitrary data past a 64-byte heap buffer, leading to memory corruption, denial of service, and potentially arbitrary code execution.

## Vulnerability Details

**File:** `target/vuln_json/vuln_parser.c`  
**Function:** `extract_string()`  
**Lines:** 31-64

### Root Cause
```c
31  char* extract_string(const char* json, const char* key) {
32      char* result = malloc(64);  // Fixed 64 bytes - VULNERABLE!
...
59      // BUG: No length check before copy
60      int len = end - start;
61      memcpy(result, start, len);  // UNSAFE: len can exceed 64 bytes
62      result[len] = '\0';
63      return result;
64  }
```

The function allocates a fixed 64-byte buffer but performs no bounds checking before copying user-controlled data. If the JSON value exceeds 64 bytes, `memcpy()` writes past the buffer boundary.

## Proof of Concept

### Triggering Input (113 bytes)
```json
{"data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

### Reproduction
```bash
# Compile with ASan
gcc vuln_parser.c -o vuln_parser -g -fsanitize=address -O1

# Trigger crash
echo '{"data": "'$(python3 -c 'print("A"*100)')'"} ' > crash.json
./vuln_parser crash.json
```

### Expected Output
```
=================================================================
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 100 at 0x506000000060
    #0 extract_string vuln_parser.c:61
    #1 process_with_cache vuln_parser.c:105
    
0x506000000060 is located 0 bytes after 64-byte region
allocated by malloc at vuln_parser.c:32

SUMMARY: AddressSanitizer: heap-buffer-overflow
=================================================================
```

## Technical Analysis

### Memory Layout
```
Allocated Buffer:
[0x506000000020] ← 64 bytes start
[0x506000000060] ← 64 bytes end (overflow boundary)

Overflow:
Buffer size:  64 bytes
Input size:   100 bytes
Overflow:     36 bytes beyond buffer
```

### Impact Assessment

**Exploitability:** HIGH
- Attacker controls overflow size (JSON value length)
- Attacker controls overflow data (JSON value content)

**Impact:**
1. **Denial of Service** - Guaranteed crash (trivial)
2. **Memory Corruption** - Heap metadata/adjacent objects overwritten
3. **Information Disclosure** - Potential leak of adjacent heap data
4. **Code Execution** - Possible via heap exploitation techniques

## Fuzzer Discovery Metrics

**Tool:** simple_fuzz.py  
**Strategy:** Random mutation with chunk duplication  

**Results:**
- Time to discovery: < 1 second
- Iterations to crash: 0-7
- Total crashes found: 6+
- Execution speed: 27,000 exec/sec
- False positives: 0

## Proof-of-Concept Test Results

| Test # | Input Size | Overflow | Result |
|--------|-----------|----------|--------|
| 1 | 50 bytes | None | ✅ No crash |
| 2 | 63 bytes | None | ✅ No crash |
| 3 | 65 bytes | 1 byte | ❌ **CRASH** |
| 4 | 100 bytes | 36 bytes | ❌ **CRASH** |
| 5 | 500 bytes | 436 bytes | ❌ **CRASH** |

**Crash Boundary Identified:** Exactly 64 bytes  
**Reproducibility:** 100%

## Remediation

### Recommended Fix (Dynamic Allocation)
```c
char* extract_string(const char* json, const char* key) {
    const char* start = strstr(json, key);
    // ... parsing logic ...
    
    int len = end - start;
    char* result = malloc(len + 1);  // ✅ Allocate exact size
    if (!result) return NULL;
    
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}
```

### Alternative Fix (Bounds Checking)
```c
char* result = malloc(64);
int len = end - start;

if (len >= 64) {  // ✅ Add bounds check
    len = 63;
}

memcpy(result, start, len);
result[len] = '\0';
```

### Additional Hardening

1. **Input Validation** - Enforce maximum JSON value size
2. **Compiler Flags** - Enable `-D_FORTIFY_SOURCE=2`
3. **Safe Functions** - Use `strncpy()` instead of `memcpy()`
4. **Continuous Fuzzing** - Integrate into CI/CD pipeline

## References

- **CWE-122:** Heap-based Buffer Overflow  
  https://cwe.mitre.org/data/definitions/122.html
- **AddressSanitizer:** https://github.com/google/sanitizers
- **CVSS v3.1 Calculator:** https://www.first.org/cvss/calculator/3.1

---

**End of Report**
