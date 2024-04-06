The original paper by Vx-Underground :
[Knocking on Hell's Gate - EDR Evasion Through Direct Syscalls](https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/14/syscalls.html)
by smelly__vx ([@RtlMateusz](https://twitter.com/RtlMateusz)) and am0nsec ([@am0nsec](https://twitter.com/am0nsec))
# Introduction
The paper introduces a technique called "Hell's Gate" that allows dynamically resolving and invoking Windows syscalls at runtime without relying on any static or hardcoded SSNs.
It can be split in two main steps, first, we find a pointer to NTDLL, then we parse NTDLL's export table and retrieve the SSN from the code, in essence, we are going to write our own *GetModuleHandle* and *GetProcAddress* functions. 

## In Short
The first steps consist to walking the PEB structures until we find 
- From the PEB, we read a pointer to PEB_LDR_DATA
- From the PEB_LDR_DATA , read the first element of the InMemoryOrderModuleList linked list
- Flink (forward link) through each element of the list until we find NTDLL.dll's LIST_ENTRY
- Read the pointer to the DLL's base

Here is a handy diagram to explain the first steps of this technique : 
![[./Notes/Maldev/Syscalls/Resources/PEB_Walking.webp|690]]
Thanks a lot to Alice Climent-Pommeret for [this diagram](https://www.linkedin.com/posts/alice-c-140504b2_recently-i-saw-many-people-struggling-with-activity-7066740521930485760-bOcq/?trk=public_profile_like_view)

The next few steps are a bit more complicated, and require parsing the headers of the DLL,  




## Declaring the structures
For this technique we are going to need a few Windows data structures. If you don't want to write them yourself, you can use those of crates like windows-rs, windows_sys or winapi.
We will need at least those structures:
- PEB 
- PEB_LDR_DATA
- LIST_ENTRY
- LDR_DATA_TABLE_ENTRY
- and UNICODE_STRING
You can find all these structures with even aa few undocumented fields in my code o this project, but i recommend dumping them using WinDbg and declaring them yourself, explore, there's far more in Windows than you'll find in the documentation. 
If you want to dump them yourself, open WinDbg, load any program, go to "Command" and use the `dt` (Display Type) command to display all the information about a data structure.
```
0:021> dt nt!_LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   .....ETC ... 
```
But creating the structure in your code is going to take a very long time if you want to do it by hand. I recommend giving the WinDbg log to a LLM and let it generate structure with the correct syntax. 
Take note that you don't have to specify all the fields in your code, you can leave "holes" in your structs as long at the remaining fields are at the correct offset.
For example, with a part of the PEB structure :
```rust
pub OSMajorVersion: u32,  
pub OSMinorVersion: u32,  
pub OSBuildNumber: u16,  
pub OSCSDVersion: u16,  
pub OSPlatformId: u32,  
pub ImageSubsystem: u32,  
pub ImageSubsystemMajorVersion: u32,
```
you can do this :
```rust
pub OSMajorVersion: u32, 
pub PADDING: [u32;4]
pub ImageSubsystemMajorVersion: u32,
```
but not this :
```rust
pub OSMajorVersion: u32, 
pub ImageSubsystemMajorVersion: u32,
```
because my padding has the same size in memory as the fields i removed, the remaining fields are still in the same offset. Although this is only possible because of  the `#[repr(C)]` attribute on my structures, as I assures the structures will maintain the same layout in memory. 

\<INSERT A LINK TO THE CODE HERE>

###  Our own *GetModuleHandle*
As stated in the introduction, the first step is to find the address of a module.
We're going to start from the PEB, or **Process Environment Block**, a structure containing all User-Mode parameters associated by system with our current process.
The address of this structure is stored in the gs register (and the fs register on 32-bit windows).
You can read this value like using inline assembly : 
```rust
unsafe fn get_peb_address() -> *const PEB {  
    let peb_ptr;
    asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);  
    peb_ptr  
}
```
Then, dereference the structure, access a field, repeat etc... hence "walking" the PEB, move structure to structure until you find a *LIST_ENTRY*, a doubly-linked list pointing to *LDR_DATA_TABLE_ENTRY* structures which contain the module information.
By following the ***Flink*** (Forward Link) and ***Blink*** (Backward Link) pointers, you can enumerate the loaded modules.
As an example, I decomposed everything in multiple variables so it's easier to understand : 
```rust
let peb: PEB = *get_peb_address();  
let peb_loader_data =  peb.Ldr;  
let first_entry = (*peb_loader_data).InMemoryOrderModuleList.Flink;  
let second_entry = (*first_entry).Flink;  
let third_entry = (*second_entry).Flink;  
  
let module_base = second_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;  
println!("{}", (*module_base).BaseDllName);  
println!("{}", (*module_base).FullDllName);
```
But if you're really allergic to clean code, it can also be written like :
```rust
let module_base = (*(*peb.Ldr).InMemoryOrderModuleList.Flink).Flink.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;  
println!("{}", (*module_base).BaseDllName);
```

The most important part here, and the most easy to miss is the `.byte_sub(0x10)` 
This is because each Flink in the linked list do not point to the *LDR_DATA_TABLE_ENTRY*, but to the next *LIST_ENTRY* in the list. If you dump *LDR_DATA_TABLE_ENTRY* as shown earlier using WinDgb, you'll see this that the InMemoryOrderLinks field is the second list in the layout, at offset 0x10.
```
+0x000 InLoadOrderLinks : _LIST_ENTRY
+0x010 InMemoryOrderLinks : _LIST_ENTRY
+0x020 InInitializationOrderLinks : _LIST_ENTRY
+0x030 DllBase          : Ptr64 Void
....etc
```
So we need to offset it back by 16 bytes (0x10 in hex) to get the pointer to the start of the structure. 
We use InMemoryOrderLinks and not the other because *InLoadOrderLinks* and *InInitializationOrderLinks* are not defined in Windows crates, so unless you defined *LDR_DATA_TABLE_ENTRY* yourself (or just grabbed my own), you can not use those.

For your convenience, here is a nice function that does everything we just talked about :
```rust
unsafe fn get_module_base_address(module_name: &str) -> Result<*const c_void, &str> {  
    let peb = *get_peb_address();  
    let last_module = (*peb.Ldr).InMemoryOrderModuleList.Blink;  
    let mut module_entry: *mut LIST_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink;  
    let mut module_base: *const LDR_DATA_TABLE_ENTRY;  
  
    loop {  
        module_base = module_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;  
        println!("[?-?] Module : {}", (*module_base).BaseDllName);  
        if (*module_base).BaseDllName.to_string().eq_ignore_ascii_case( module_name ) {  
            println!("[^-^] Module Found at address : {:x?}", (*module_base).DllBase);  
            return Ok((*module_base).DllBase);  
        }  
        if module_entry == last_module {  
            return Err("Module not found !")  
        }  
  
        module_entry = (*module_entry).Flink;  
    }  
}
```

## Parsing the headers
Now that we have the address of a loaded module, it is time to parse it.
I will sometimes refer to it as a file, because this is literally the entire dll file loaded in our programs memory.
We must first understand its structure, and for that i will refer you to the incredibly helpful OsDev wiki page on the **Portable Executable** File Format : [here](https://wiki.osdev.org/PE). 
### The DOS header
For historic reasons, every PE File contains a MS-DOS executable, called the *DOS Stub*.
It contains a DOS Header and an actual MS-DOS program, that would simply output "This program cannot be run in DOS mode." in the case someone ran an exe file in a DOS environment.

Because it is the first bytes of the file, so we can easily read it by casting our pointer to the module to a pointer to the *IMAGE_DOS_HEADER* structure.
We can then easily access it's fields by dereferencing it.
```rust
let dos_header_ptr = base_address as *const IMAGE_DOS_HEADER;  
if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE { // 0x5A4D  
    return Err("Invalid DOS header".to_string())  
}
```

We are interested in only two fields of this structure:
- *e_magic* which is the DOS Header signature and should always be `0x5A4D` (or "MZ")
- *e_lfanew* at offset 0x3C which contains an offset to the start of the NT Header 
### The NT Headers
The NT Headers, or sometimes called *PE headers* or *COFF headers*, named after *Portable Executable* and *Common Object File Format*, can be found after the *DOS Stub*. 
As with the DOS header, the first bytes are a signature, this time 4 bytes long, which should always be `0x00004550` or "PE\\0\\0" (PE followed by two null bytes).
This allows us to ensure we got the right address, before dereferencing it as our structure.

The rest is in two structures, the *File Header* and the *Optional Header*, which, in the case of Image files, is not optional, so i do just like the *DOS header* and just dereference a pointer to a struct to access its field. 
It does, however, vary in size depending on the architecture, either 64bit or not, but it's relatively easy to deal with using something like this :
```rust
#[cfg(target_pointer_width = "64")]  
pub type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
```

#### The data directory
What we're really after is the last field of the optional header, named data directory. It is an array of IMAGE_DATA_DIRECTORY elements, each containing an address and a size. 
The address is a *Relative Virtual Address* or RVA, meaning it's really an offset relative to the base of Image, just like the `e_lfanew` field in the DOS Header we saw earlier.

Each element in this array is a different directory, each containing various information such as the exports (index 0) and imports (index 1) the security directory, the exceptions etc....  
What we are interested in is the export table, at index 0. It contains 


### References 

[Knocking on Hell's Gate - EDR Evasion Through Direct Syscalls](https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/14/syscalls.html)
[0xca7 - Notes on PEB Walking](https://0xca7.github.io/mw/pebwalk_notes/)
[](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2)

Thank you, unknown hero MarkHC, for helping me realize i was trying to fix a bug that never even existed in the first place : 
>Each Flink and Blink are pointers to LDR_DATA_TABLE_ENTRY, like MSDN says. But they don't point to the start of struct like your last piece of code assumes. They point to the InMemoryOrderModuleList member of the struct.  
>
https://www.unknowncheats.me/forum/general-programming-and-reversing/190128-inmemoryordermodulelist-documentation-im-confused.html





