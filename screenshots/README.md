# Screenshots
<img width="1920" height="1016" alt="Screenshot at 2026-02-08 05-28-54" src="https://github.com/user-attachments/assets/86f22875-eb78-4ee2-b7fb-1794b259d347" />
<img width="1920" height="1016" alt="Screenshot at 2026-02-08 05-29-19" src="https://github.com/user-attachments/assets/67923534-cb60-4358-b25c-58d965efa76e" />

## PoC Demonstration
Screenshots showing successful exploitation of heap buffer overflow.

### Test Results
- ✅ Control (50 bytes): No crash
- ✅ Edge case (63 bytes): No crash  
- ❌ Exploit (65 bytes): **CRASH** - Heap overflow detected
- ❌ Exploit (100 bytes): **CRASH** - 36-byte overflow
- ❌ Exploit (500 bytes): **CRASH** - 436-byte overflow

