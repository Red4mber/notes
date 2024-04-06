More Info [page 580-585 of the Intel Manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf#page=580&zoom=auto,-210,670)and [on Wikipedia](https://en.wikipedia.org/wiki/X86_debug_register)
## Summary  
On x86 architecture, there are six debug registers. These registers allow us to set `Hardware Breakpoints`. Hardware breakpoints are much more powerful than software breakpoints and can be set on a memory address, to trigger whenever it is read, executed or written to.

You can have up to 4 hardware breakpoints, and they can be set to either trigger locally, or globally, allowing us to break on local addresses too.

The `DR0`, `DR1`, `DR2` and `DR3` registers store the addresses of the breakpoints, while `DR7` is the Debug __Control__ Register, it enables or disable breakpoints and sets the breakpoint conditions.

## Setting up a breakpoint

## The DR7 register
The DR7 register is 32 bits long (actually 64 like the other but the last 32-bits are all zeroed)
The first 8-bits are `Local Flags` and `Global Flags` for every breakpoints. 
`Global Flags` are bits 1, 3, 5 and 7 and `Local Flags` are bits 0, 2, 4 and 6 (see [Figure 17-2](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf#page=585&zoom=auto,-210,624))

The last 16bits of DR7 contains the information about the breakpoints conditions and address length. Their values are a bit weird, so here's a table mapping bits to length / conditions :

| Value | Condition  | Length                                     |
| ----- | ---------- | ------------------------------------------ |
| `00`  | EXECUTION  | 1 byte                                     |
| `01`  | WRITE      | 2 bytes                                    |
| `10`  | I/O        | 8 bytes  <br>(only defined in 64-bit mode) |
| `11`  | READ+WRITE | 4 bytes                                    |

## DR7 in details
Thank you Wikipedia for this table :3

| Bits  | Abbreviation | Description                                                                                                                                                                                                                     |
| ----- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | **L0**       | Local enable for breakpoint #0.                                                                                                                                                                                                 |
| 1     | **G0**       | Global enable for breakpoint #0.                                                                                                                                                                                                |
| 2     | **L1**       | Local enable for breakpoint #1.                                                                                                                                                                                                 |
| 3     | **G1**       | Global enable for breakpoint #1.                                                                                                                                                                                                |
| 4     | **L2**       | Local enable for breakpoint #2.                                                                                                                                                                                                 |
| 5     | **G2**       | Global enable for breakpoint #2.                                                                                                                                                                                                |
| 6     | **L3**       | Local enable for breakpoint #3.                                                                                                                                                                                                 |
| 7     | **G3**       | Global enable for breakpoint #3.                                                                                                                                                                                                |
| 8     | **LE**       | (386 only) Local Exact Breakpoint Enable.                                                                                                                                                                                       |
| 9     | **GE**       | (386 only) Global Exact Breakpoint Enable.                                                                                                                                                                                      |
| 10    | **—**        | Reserved, read-only, read as 1 and should be written as 1.                                                                                                                                                                      |
| 11    | **RTM**      | (Processors with Intel TSX only)  Enable advanced debugging of RTM transactions (only if `DEBUGCTL` bit 15 is also set)  <br>On other processors: reserved, read-only, read as 0 and should be written as 0.                    |
| 12    | **IR,SMIE**  | (386/486 processors only) Action on breakpoint match: <br>0 = INT 1 (#DB exception, default) <br>1 = Break to ICE/SMMi/X86_debug_register)  <br>On other processors: Reserved, read-only, read as 0 and should be written as 0. |
| 13    | **GD**       | General Detect Enable. If set, will cause a debug exception on any attempt at accessing the DR0-DR7 registers                                                                                                                   |
| 15:14 | **—**        | Reserved, should be written as all-0s.                                                                                                                                                                                          |
| 17:16 | **R/W0**     | Breakpoint condition for breakpoint #0                                                                                                                                                                                          |
| 19:18 | **LEN0**     | Breakpoint length for breakpoint #0.                                                                                                                                                                                            |
| 21:20 | **R/W1**     | Breakpoint condition for breakpoint                                                                                                                                                                                             |
| 23:22 | **LEN1**     | Breakpoint length for breakpoint #1.                                                                                                                                                                                            |
| 25:24 | **R/W2**     | Breakpoint condition for breakpoint #2                                                                                                                                                                                          |
| 27:26 | **LEN2**     | Breakpoint length for breakpoint #2.                                                                                                                                                                                            |
| 29:28 | **R/W3**     | Breakpoint condition for breakpoint #3                                                                                                                                                                                          |
| 31:30 | **LEN3**     | Breakpoint length for breakpoint #3.                                                                                                                                                                                            |
|       |              |                                                                                                                                                                                                                                 |
|       |              |                                                                                                                                                                                                                                 |
## The code now

On windows, the state of those registers can be set 

```
NtSetContextThread(
  IN HANDLE               _ThreadHandle_,
  IN PCONTEXT             _Context_ );

NtGetContextThread(
  IN HANDLE               _ThreadHandle_,
  OUT PCONTEXT            _pContext_ );
```