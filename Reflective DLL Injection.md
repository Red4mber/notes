## Introduction

Reflective DLL injection differs from the regular way of performing DLL injection in several key aspects:

**Regular DLL Injection:**
- Requires writing the malicious DLL to disk first
- Uses system APIs like LoadLibrary() to load the DLL into the target process
- Leaves artifacts on disk that can be detected by security software

**Reflective DLL Injection:**
- Does not require writing the DLL to disk
- The entire DLL code is loaded directly into the memory of the target process
- No files are created on disk, making it more stealthy
- Uses manual memory mapping and loading techniques instead of system APIs
- The malicious code "reflects" itself into the target process memory

By avoiding disk access and not using typical Windows APIs, reflective DLL injection can bypass many security monitoring tools and techniques that look for DLL loads from disk. The malicious code exists only in memory, leaving a smaller forensic footprint.

However, reflective injection is more complex to implement and often requires manually mapping memory, resolving import addresses, and handling relocations. But its stealthier nature makes it a popular technique among malware authors and penetration testers.