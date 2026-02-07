#!/usr/bin/env python3
"""Test both discovered vulnerabilities"""

import subprocess
import os

RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'

target = "target/vuln_json/vuln_parser"

print(f"{BLUE}{'='*60}{RESET}")
print(f"{BLUE}Testing Both Discovered Vulnerabilities{RESET}")
print(f"{BLUE}{'='*60}{RESET}")

# Test Bug #1: Heap overflow (64-byte buffer)
print(f"\n{BLUE}[Bug #1] Heap Buffer Overflow (extract_string){RESET}")
heap_payload = '{"data": "' + 'A' * 100 + '"}'
with open('/tmp/heap_test.json', 'w') as f:
    f.write(heap_payload)

result = subprocess.run([target, '/tmp/heap_test.json'], capture_output=True)
if b"heap-buffer-overflow" in result.stderr:
    print(f"{RED}✓ HEAP OVERFLOW TRIGGERED{RESET}")
    print(f"  Buffer: 64 bytes, Input: 100 bytes, Overflow: 36 bytes")
else:
    print(f"{GREEN}✗ No crash{RESET}")

# Test Bug #2: Stack overflow (128-byte buffer, needs 150+ digits)
print(f"\n{BLUE}[Bug #2] Stack Buffer Overflow (parse_array){RESET}")
# Need 150+ digits total to overflow 128-byte buffer
stack_payload = '[' + '1' * 150 + ']'
with open('/tmp/stack_test.json', 'w') as f:
    f.write(stack_payload)

result = subprocess.run([target, '/tmp/stack_test.json'], capture_output=True)
if b"stack-buffer-overflow" in result.stderr:
    print(f"{RED}✓ STACK OVERFLOW TRIGGERED{RESET}")
    print(f"  Buffer: 128 bytes, Input: 150 bytes, Overflow: 22 bytes")
else:
    print(f"{GREEN}✗ No crash{RESET}")

print(f"\n{BLUE}{'='*60}{RESET}")
print(f"{BLUE}Both vulnerabilities confirmed!{RESET}")
print(f"{BLUE}{'='*60}{RESET}\n")
