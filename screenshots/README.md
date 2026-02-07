# Screenshots

## PoC Demonstration
Screenshots showing successful exploitation of heap buffer overflow.

### Test Results
- ✅ Control (50 bytes): No crash
- ✅ Edge case (63 bytes): No crash  
- ❌ Exploit (65 bytes): **CRASH** - Heap overflow detected
- ❌ Exploit (100 bytes): **CRASH** - 36-byte overflow
- ❌ Exploit (500 bytes): **CRASH** - 436-byte overflow

