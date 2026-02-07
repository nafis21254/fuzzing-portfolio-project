#!/usr/bin/env python3
import subprocess
import random
import os
from pathlib import Path

corpus_dir = Path("corpus")
crash_dir = Path("crashes")
target = "target/vuln_json/vuln_parser"

crash_dir.mkdir(exist_ok=True)

# Load corpus
corpus = []
for f in corpus_dir.glob("*.json"):
    corpus.append(f.read_bytes())

print(f"[+] Loaded {len(corpus)} files")
print(f"[+] Starting simple fuzzer...")

crashes_found = 0

for i in range(10000):
    # Pick random seed
    seed = random.choice(corpus)
    
    # Simple mutation: duplicate a random chunk
    if len(seed) > 10 and random.random() > 0.5:
        pos = random.randint(0, len(seed)-10)
        chunk = seed[pos:pos+random.randint(10, 50)]
        mutated = seed + chunk
    else:
        mutated = seed
    
    # Write to temp file
    test_file = "/tmp/test_fuzz.json"
    with open(test_file, 'wb') as f:
        f.write(mutated)
    
    # Run target
    try:
        result = subprocess.run(
            [target, test_file],
            timeout=1,
            capture_output=True
        )
        
        # Check if crashed
        if result.returncode != 0 or b"AddressSanitizer" in result.stderr:
            crashes_found += 1
            crash_file = crash_dir / f"crash_{crashes_found}.json"
            crash_file.write_bytes(mutated)
            stderr_file = crash_dir / f"crash_{crashes_found}.txt"
            stderr_file.write_bytes(result.stderr)
            print(f"\n[!] CRASH {crashes_found} found at iteration {i}")
            
    except subprocess.TimeoutExpired:
        pass
    
    if i % 500 == 0:
        print(f"\r[*] Iteration {i}, crashes: {crashes_found}", end='', flush=True)

print(f"\n\n[+] Done! Found {crashes_found} crashes")
