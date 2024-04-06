# Introduction
## User Mode vs Kernel Mode
The x86 processor architecture provides multiple "rings" of privilege, numbered 0 to 3, called **protection rings**.
Ring 3 has the least privilege while Ring 0 has complete access over the hardware of your computer. This allows your processor to avoid giving every program access to resources it doesn't need. In other words, it allows your processor to respect the **Principle of Least Privilege**.  
![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Priv_rings.svg/1280px-Priv_rings.svg.png)
Ring 1 and 2 are very rarely used. Most applications running on your computer run at Ring 3, while only the kernel of your operating system Ring 0.
The Windows Operating System only uses Ring 0 and 3, to maintain compatibility with other architectures such as ARM, which only implement two protection modes, **Kernel mode** and **User Mode**. 
You see, your programs run in user mode but sometimes they need to do some fancy stuff that requires special permissions. That's where syscalls come in, acting as your middleman to request those privileged operations from the kernel, which runs in kernel mode.
## Fucking Syscalls, how do they work ?
![[./Notes/Maldev/Syscalls/Resources/Insane_Clown_Posse.bmp|Insane_Clown_Posse.bmp]]

When you call a function like *WriteFile*, the windows API will then call the Native API, which will then call the syscall instruction for you, which will then put the processor in kernel mode and execute what you need. 
Here's a handy image i shamelessly stolen from RedOps.at blog : 
![Transition from User mode to kernel mode - from RedOps.at](https://redops.at/assets/images/blog/notepad_transition_syscall.png)
But most EDRs will hook these functions in ntdll.dll, and that no good for us malware developers, our code would probably trigger an alert.
We need a way to call the syscall ourselves, hence bypassing any EDR hook in user space APIs.
To understand how to do this, let's take a look at the *NtCreateFile* function from Ntdll.dll : 
![[./Notes/Maldev/Syscalls/Resources/NtCreateFile_Syscall_Disassembled.png|NtCreateFile_Syscall_Disassembled.png]]The code of a syscall (also called the `syscall stub`) : 
```asm
mov r10, rcx	; Move the parameters in the r10 register
mov eax, 55h	; Store the syscall ID in the EAX register 
syscall			; Switch to kernel mode
ret				; return
```
It moves "0x55" in the EAX register, then use the *syscall* instruction.
Since *syscall* is a single instruction, this is how we identify what syscall is called. This number is called a **System Service Number** (or SSN).
Here, we have 0x55, the SSN for the *NtCreateFile* syscall - For Windows 10 and 11 x64.

> You might wonder what is the `test [7FFE0308]` instruction just before the syscall instruction.
> On some legacy systems, the `syscall` instruction doesn't exist, instead need to use the interrupt 2E.
> In the KUSER_SHARED_DATA structure (found at address 0x7FFE0000), there is a field called SystemCall at offset 0x0308, storing the type of system call the OS need to use.
> This check the value of this field, if it's not equal to 1, it jumps after the return and executes INT 2E.
# System Service Numbers
## Retrieving the System Service Numbers
Microsoft being Microsoft, you can forget about legit documentation for syscalls. Most legit programs don't need to call syscalls directly, the Windows API does that for them, but we aren't writing a legit program, so how do we find them ?
Well there are multiple ways: 
### Hardcoding SSNs using a lookup table
You might just want to look them up and hardcode them in your program, but there a problem. As i said earlier, you are not supposed to call them yourself, the windows API does.
This means all the syscalls are **undocumented** and the SSNs are very prone to change from a version of windows to another. It means that with poor luck, the SSN you find might only be valid for the version of windows you are currently running.
However, some giga chads already did the work of dumping SSNs for most versions of windows, and put everything online for you to use in your code !~
[Windows X86-64 NT Syscall table by j00ru](https://j00ru.vexillium.org/syscalls/nt/64/).
#### Reading build number from the PEB
As said just above, you need precise version information to find the correct SSN, and there an easy way to do that. 
The *Process Environment Block* contains all the information we need.
You can easily get the base address of the PEB structure at offset 0x60 in the gs register on 64-bits systems, and at offset 0x30 in the fs register for 32-bits systems.
You can then find the build number at offset 0x0120 for 64 bits system and 0xAC for 32 bits systems.
Here is an example in Rust :
```rust
use core::ptr;
use core::arch::asm;

unsafe fn get_build_number() -> u32 {
    let build_number, peb_address;
    #[cfg(target_arch = "x86_64")]
    {
	    asm!("mov {}, gs:[0x60]", out(reg) peb_address);
        build_number = ptr::read((peb_address + 0x0120) as *const u32);
    }
    #[cfg(target_arch = "x86")]
    {
	    asm!("mov {}, fs:[0x30]", out(reg) peb_address);
        build_number = ptr::read((peb_address + 0xAC) as *const u32);
    }
    build_number
}

fn main() {
	let build_number = unsafe { get_build_number() };
    println!("Build number: {build_number}");
}
```
## Dynamic Retrieval of SSNs
A slightly more complicated way is to dynamically extract the SSN from the NTDLL library.
All syscalls in Ntdll.dll have the exact same structure :
![[./Notes/Maldev/Syscalls/Resources/NtCreateFile_Syscall_Disassembled.png|NtCreateFile_Syscall_Disassembled.png]]
Or, if i write the actual bytes in the binary : 
```
4C 8B D1
B8 ?? 00 00 00
...
0F 05
c3
```
The SSN we are looking for is the 5th byte of that procedure, so to read it, we need to read 1 byte starting at the procedure address + 4.

Using the GetProcAddress function, we can get the address of any procedure in a module, then look 4 bytes after this address to get the SSN of that syscall :
```rust 
use std::mem::transmute;  
use std::ptr;  
use windows::core::s;  
use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};  
  
fn main() {  
    unsafe {  
        let ntdll_handle = GetModuleHandleA(s!("ntdll.dll")).unwrap_or_else(|e| {  
            eprintln!("[-] Failed to get a handle on ntdll.dll: {e}");  
            std::process::exit(-1);  
        });  
        let ntcreatefile_ptr = GetProcAddress(ntdll_handle, s!("NtCreateFile"));  
        let ntcreatefile_ptr: usize = transmute(ntcreatefile_ptr);  
        let ntcreatefile_ssn = ptr::read((ntcreatefile_ptr as usize + 4) as *const u32);  
        println!("[+] NtCreateFile SSN : {:#04x}", ntcreatefile_ssn);
        // NtCreateFile SSN : 0x55   
    }  
}
```
For debugging, you can check your results against j00ru's [Windows X86-64 NT Syscall table](https://j00ru.vexillium.org/syscalls/nt/64/).
### But what if it's hooked ?
However, there is a catch, this technique doesn't work if that syscall is hooked by an EDR, as we would have a jmp to the EDR hook as the first instruction, so the SSN would not be at offset +0x4 ! 

A quick and dirty way to mitigate this issue would be to read multiple bytes, and if we read 0xB8, which is the MOV EAX instruction, we know the SSN is the following byte. 
A less dirty way to mitigate this issue is to first read the first byte, if it's a JMP instruction (0xE9), then skip at least the next 4 bytes (which would be the jump address).
Here's a program detecting hooks and verifying the presence of the mov eax instruction to ensure the retrieval of the correct SSN : 
```rust
use std::ptr;
use std::mem::transmute;
use windows::core::{PCSTR, s};
use windows::Win32::Foundation::*;
use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};

unsafe fn get_ssn(ntdll_handle: HMODULE, syscall_name: PCSTR) -> Option<u8> {
    let start_ptr = GetProcAddress(ntdll_handle, syscall_name);
    let start_ptr: *const u8 = transmute(start_ptr); 
    let first_byte = ptr::read(start_ptr);
    let mut offset = 3;
    let ssn;

    // If a hook is detected
    if first_byte == 0xE9 {
        println!("[!] Hook detected, skipping the next 4 bytes");
        offset += 5; // Skip 4 bytes + the byte we just read 
    }
    if ptr::read(start_ptr.add(offset.clone())) == 0xB8 {   // If we find MOV EAX  
        ssn = Some(ptr::read(start_ptr.add(offset+1)));     // We found the SSN
    } else {                                                // Else
        ssn = None;                                         // We did not :c
    }
    ssn
}

fn main() {
    let ntdll_handle: HMODULE = unsafe { GetModuleHandleA(s!("ntdll.dll")) }.unwrap_or_else(|e| {
        eprintln!("[-] Failed to get a handle on ntdll.dll: {e}");
        std::process::exit(-1);
    });

    unsafe {
        match get_ssn(ntdll_handle, s!("NtCreateFile")) {
            Some(ntcreatefile_ssn) => {
                println!("[+] Found NtCreateFile SSN : {:#04x}", ntcreatefile_ssn);
                std::process::exit(0);
            },
            None => {
                eprintln!("[-] SSN Not Found");
                std::process::exit(-1);
            }
        }
    }
}
```
Ideally, we would not use the `GetModuleHandleA` and `GetProcAddress` functions because them back to back as they're used in our code would absolutely trigger alerts on any half decent security solutions.
This program is far from perfect, but for now, let's focus on using the syscalls, we'll work on defense evasion later when we'll implement Hell's Gate PEB Walking techniques to our program.
> "Make it work, Make it right, Make it fast" - Kent Beck
> Right now, we have to make it work

# Direct Syscalls 
## Back to hardcoded SSNs :c
We finally have the SSN, cool, but we're gonna have to wait a little bit before doing everything dynamically. We're first gonna use syscalls with hardcoded SSNs to understand how everything works, and only then we're going to put everything together.

For this purpose, we're going to write a basic shellcode injector using direct syscalls. This time I am not going to show the entire code at each step, but you'll find the shellcode injector on github and in a folder in this post's files.

If you remember earlier in this post when I talked about extracting the build number from the PEB, you may have noticed i used a macro to run an arbitrary assembly instruction, to read the PEB address from a register.

We already saw the `asm!()` which allows us to run arbitrary instructions like so :
```rust
asm!("mov {}, gs:[0x60]", out(reg) peb_addr);
```
Here, we moved the value at offset 0x60 in the gs register to another register, which will output to the `peb_addr` variable. 
This is only a small example of what this powerful macro can do but there is a catch, we can't use this macro outside of a function scope. 

To quote [The Rust Reference](https://doc.rust-lang.org/nightly/reference/inline-assembly.html) :
>With the `asm!` macro, the assembly code is emitted in a function scope and integrated into the compiler-generated assembly code of a function. This assembly code must obey [strict rules](https://doc.rust-lang.org/nightly/reference/inline-assembly.html#rules-for-inline-assembly) to avoid undefined behavior. Note that in some cases the compiler may choose to emit the assembly code as a separate function and generate a call to it.
>
With the `global_asm!` macro, the assembly code is emitted in a global scope, outside a function. This can be used to hand-write entire functions using assembly code, and generally provides much more freedom to use arbitrary registers and assembler directives.

The `global_asm!` macro, however, can't take any variable as input and output, but this macro is *global*, meaning it is outside of any function's scope, we can define our own functions in assembly and use them in our rust code like any extern C library.
As an example, here's how to make a direct syscall to NtOpenProcess :
```rust
// Write the actual syscall in assembly
// All syscalls have the same structure
global_asm!(r#"
.section .text
.global NtOpenProcess
NtOpenProcess:
		mov r10, rcx
		mov eax, 0x26
		syscall
		ret
"#);

// We need to declare the signature of the extern function
// To tell rust this function exists and how to use it
extern "C" {  
    pub fn NtOpenProcess(  
        ProcessHandle: *mut HANDLE,  
        AccessMask: u32,  
        ObjectAttributes: *const OBJECT_ATTRIBUTES,  
        ClientId: *const CLIENT_ID,  
    ) -> NTSTATUS;
}

// Now we can use this function in our code o/
status = syscalls::NtOpenProcess(&mut process_handle, PROCESS_ALL_ACCESS, &oa, &cid);  
if status != 0 {  
    eprintln!("[TwT] Failed to open process: {status:#x}");  
    process::exit(-1);  
}
```
You may need to import structures from windows libraries, but this is optional as you can also defined those yourself.
You will notice the code of the syscall procedure is exactly the code we saw previously, in the chapter on dynamic SSN retrieval,  but we added these two lines :
```
.section .text
.global NtOpenProcess
```
The first line, `.section .text` will tell the compiler to assembled the following code into a section named `.text`.  The `.text` section is usually the section of the code contaning executable instructions. 
The second line, `.global NtOpenProcess` is an export. The `global` keyword tells the linker that the `NtOpenProcess` symbol is global, and not just local to the assembly, this allows us to call the code from the rust code.  

But this method is a pain in the ass.... Not only we have to define the signature of every syscall we want to use in our code, but our assembly is only going to work for a single version of windows, because SSNs change all the time ! 
I think it's time to combine everything we did so far, dynamically retrieving SSNs to make direct syscalls.
## 






To read more : 
[Hell's Gate by Smelly and am0nsec](https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/HellsGate.pdf)([Download Link](https://samples.vx-underground.org/Papers/Windows/Evasion%20-%20Systems%20Call%20and%20Memory%20Evasion/2021-12-07%20-%20Dynamically%20Retrieving%20SYSCALLs%20-%20Hells%20Gate.7z))
[Detecting Hooked Syscalls by ired.team](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions)
[Direct Syscalls by Crow](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/direct-syscalls) [and his awesome video on the subject <3](https://www.youtube.com/watch?v=-M2_mZg_2Ew)
[Alice Climent-Pommeret's excellent blog](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/) [and this post too](https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/)
[RedOps blog post too](https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low)
https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-4/

https://offensivedefence.co.uk/posts/dinvoke-syscalls/
https://blog.lystic.dev/2023/05/30/manual-syscalls-on-windows/ <3

https://github.com/huntandhackett/process-cloning