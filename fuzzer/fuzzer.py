#!/usr/bin/env python3
"""
Simple Mutation-Based Fuzzer for cJSON
Monitors for crashes and saves unique crash cases
"""

import os
import sys
import random
import subprocess
import hashlib
import time
from pathlib import Path

class JSONFuzzer:
    def __init__(self, target_binary, corpus_dir, crash_dir, max_iterations=10000):
        self.target = target_binary
        self.corpus_dir = Path(corpus_dir)
        self.crash_dir = Path(crash_dir)
        self.max_iterations = max_iterations
        self.crash_hashes = set()
        self.total_execs = 0
        self.unique_crashes = 0
        
        # Create crash directory if it doesn't exist
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        
        # Load corpus files into memory
        self.corpus = []
        for f in self.corpus_dir.glob("*.json"):
            with open(f, 'rb') as fp:
                self.corpus.append(fp.read())
        
        if not self.corpus:
            print("[!] ERROR: No corpus files found!")
            sys.exit(1)
        
        print(f"[+] Loaded {len(self.corpus)} corpus files")
        print(f"[+] Target binary: {self.target}")
        print(f"[+] Crash directory: {self.crash_dir}")
        print(f"[+] Max iterations: {self.max_iterations}")
        print(f"[+] Starting fuzzing campaign...\n")
    
    def mutate(self, data):
        """Apply random mutations to input data"""
        data = bytearray(data)
        mutation_count = random.randint(1, 10)
        
        for _ in range(mutation_count):
            if len(data) == 0:
                break
            
            strategy = random.randint(0, 7)
            
            if strategy == 0:  # Bit flip
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= 1 << random.randint(0, 7)
            
            elif strategy == 1:  # Byte flip
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= 0xFF
            
            elif strategy == 2:  # Insert random byte
                pos = random.randint(0, len(data))
                data.insert(pos, random.randint(0, 255))
            
            elif strategy == 3:  # Delete byte
                if len(data) > 1:
                    pos = random.randint(0, len(data) - 1)
                    del data[pos]
            
            elif strategy == 4:  # Replace with interesting integer
                pos = random.randint(0, len(data))
                interesting = [0, 1, -1, 127, 128, 255, 256, 32767, 32768, 65535, 65536, -2147483648, 2147483647]
                val = str(random.choice(interesting)).encode()
                for byte in reversed(val):
                    data.insert(pos, byte)
            
            elif strategy == 5:  # Duplicate chunk
                if len(data) > 10:
                    chunk_size = random.randint(1, min(50, len(data) // 2))
                    pos = random.randint(0, len(data) - chunk_size)
                    chunk = data[pos:pos + chunk_size]
                    insert_pos = random.randint(0, len(data))
                    for i, byte in enumerate(chunk):
                        data.insert(insert_pos + i, byte)
            
            elif strategy == 6:  # Insert magic values (JSON-specific)
                pos = random.randint(0, len(data))
                magic = [b'null', b'true', b'false', b'[]', b'{}', b'""', b'\\u0000', b'\\xFF']
                chosen = random.choice(magic)
                for byte in reversed(chosen):
                    data.insert(pos, byte)
            
            elif strategy == 7:  # Truncate
                if len(data) > 5:
                    new_len = random.randint(1, len(data) - 1)
                    data = data[:new_len]
        
        return bytes(data)
    
    def run_target(self, test_case):
        """Execute target binary with mutated input"""
        temp_file = "/tmp/fuzz_input.json"
        
        try:
            # Write test case to temp file
            with open(temp_file, 'wb') as f:
                f.write(test_case)
            
            # Run target with timeout
            result = subprocess.run(
                [self.target, temp_file],
                timeout=2,
                capture_output=True,
                stderr=subprocess.PIPE
            )
            
            # Check for crash indicators
            crashed = result.returncode != 0
            asan_error = b"AddressSanitizer" in result.stderr
            segfault = b"Segmentation fault" in result.stderr or b"SEGV" in result.stderr
            
            return (crashed or asan_error or segfault), result.stderr
            
        except subprocess.TimeoutExpired:
            return False, b"[TIMEOUT]"
        except Exception as e:
            return False, f"[ERROR: {str(e)}]".encode()
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    def save_crash(self, test_case, stderr):
        """Save unique crash to disk"""
        # Hash stderr to identify unique crashes
        crash_hash = hashlib.md5(stderr).hexdigest()
        
        if crash_hash in self.crash_hashes:
            return False  # Duplicate
        
        self.crash_hashes.add(crash_hash)
        self.unique_crashes += 1
        
        # Save crash input
        crash_file = self.crash_dir / f"crash_{crash_hash[:12]}.json"
        with open(crash_file, 'wb') as f:
            f.write(test_case)
        
        # Save stderr output
        stderr_file = self.crash_dir / f"crash_{crash_hash[:12]}.txt"
        with open(stderr_file, 'wb') as f:
            f.write(stderr)
        
        return True
    
    def fuzz(self):
        """Main fuzzing loop"""
        start_time = time.time()
        last_status = time.time()
        
        try:
            for iteration in range(self.max_iterations):
                # Select random corpus file
                seed = random.choice(self.corpus)
                
                # Mutate it
                mutated = self.mutate(seed)
                
                # Run target
                crashed, stderr = self.run_target(mutated)
                self.total_execs += 1
                
                # Handle crash
                if crashed:
                    if self.save_crash(mutated, stderr):
                        crash_preview = stderr[:200].decode('utf-8', errors='replace')
                        print(f"\n[!] NEW CRASH FOUND!")
                        print(f"    Unique crashes: {self.unique_crashes}")
                        print(f"    Preview: {crash_preview}...")
                        print(f"    Saved to: {self.crash_dir}\n")
                
                # Status update every 2 seconds
                current_time = time.time()
                if current_time - last_status >= 2:
                    elapsed = current_time - start_time
                    execs_per_sec = self.total_execs / elapsed if elapsed > 0 else 0
                    print(f"\r[*] Exec: {self.total_execs}/{self.max_iterations} | "
                          f"Speed: {execs_per_sec:.1f}/s | "
                          f"Crashes: {self.unique_crashes} | "
                          f"Time: {int(elapsed)}s", 
                          end='', flush=True)
                    last_status = current_time
        
        except KeyboardInterrupt:
            print("\n\n[!] Fuzzing stopped by user (Ctrl+C)")
        
        # Final statistics
        elapsed = time.time() - start_time
        print(f"\n\n{'='*60}")
        print(f"[+] FUZZING CAMPAIGN COMPLETED")
        print(f"{'='*60}")
        print(f"    Total executions: {self.total_execs}")
        print(f"    Runtime: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
        print(f"    Unique crashes: {self.unique_crashes}")
        print(f"    Average speed: {self.total_execs/elapsed:.1f} exec/s")
        print(f"    Crash directory: {self.crash_dir}")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 fuzzer.py <target_binary> <corpus_dir> <crash_dir> [max_iterations]")
        print("\nExample:")
        print("  python3 fuzzer.py ../target/cJSON/json_parser ../corpus ../crashes 100000")
        sys.exit(1)
    
    # Allow custom iteration count from command line
    max_iters = int(sys.argv[4]) if len(sys.argv) == 5 else 10000
    
    fuzzer = JSONFuzzer(
        target_binary=sys.argv[1],
        corpus_dir=sys.argv[2],
        crash_dir=sys.argv[3],
        max_iterations=max_iters
    )
    
    fuzzer.fuzz()
