DLL hijacking is, in the broadest sense, **tricking a legitimate/trusted application into loading an arbitrary DLL**. Terms such as _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ and _DLL Side-Loading_ are often -mistakenly- used to say the same.

## Finding missing DLLs
Easy to do using [procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
To see all missing DLLs in procmon, Set up these 2 filters :
 - Result - Contains - "not found"
 - Path - Ends with - ".dll"

## DLL Search order 
By default, Windows will search the DLL path in the following order :
	1- The folder of the application
	2- The system folder (usually C:\\Windows\\System you can find it using [GetSystemDirectory](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya))
	3- The windows folder (usually C:\\Windows you can find it with [GetWindowsDirectory](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya))
	4- The current directory
	5- The directories in the PATH 
If **SafeDllSearchMode** is disabled, then the current directory is the second directory searched.
You can disable it in the registry here :
`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode`

**Interesting PowerSploit functions**: 
_Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll_
## Creating and compiling Dlls

### DllMain
In DLLs, the entrypoint is the function DllMain. It is called on the DLL Attach and Detach.
There are 3 arguments to this function, a handle to the DLL module, a DWORD (u32) called "fdwReason" and a reserved LPVOID pointer, which should be null for dynamic loads.

fdwReason is the most notable and the only one we'll really use. Its value will change whether the DllMain is called on attach or on detach and on processes or on threads
There are constants such as DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH  and DLL_THREAD_ATTACH, DLL_THREAD_DETACH.

Here is a short example of a DllMain : 
```rust
#[no_mangle]  
extern "system" fn DllMain(  
    _: HINSTANCE,  
    reason: u32,  
    _: *mut ()  
) -> bool {  
    match reason {  
        DLL_PROCESS_ATTACH=> on_attach(),  
        DLL_PROCESS_DETACH=> on_detach(),  
        _ => ()  
    }
   true  
}
```

### Dll Proxying
DLL Proxying is creating a Proxy DLL, which will execute malicious code but relaying calls to the actual library.  
There are tools like [Spartacus](https://github.com/Accenture/Spartacus) or [DLLirant](https://github.com/redteamsocietegenerale/DLLirant) can help analyze a binary and generate a DLL but i think it's more fun if we do it ourselves.