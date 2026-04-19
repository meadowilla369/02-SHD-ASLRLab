# Lab 06 Report - ASLR Bypass

## 1. Overview

- Topic: Bypassing ASLR using egg hunting and ROP
- Objectives:
  - Locate a mapped memory page inside a randomized address range.
  - Exploit a buffer overflow to hijack control flow.
  - Build ROP chains and combine them with address discovery to defeat ASLR.

## 2. Solution Summary

### Part 1A - Egg Hunter with `access()`

The idea is to probe each page in the range `[low_bound, high_bound)` with a step size of `PAGE_SIZE`.
Each candidate address is passed to `access((const char *)addr, F_OK)` as if it were a pathname pointer.

- If the syscall returns `-1` and `errno == EFAULT`, the pointer is invalid and the page is not mapped.
- If the syscall succeeds, or fails with an error other than `EFAULT`, the kernel was still able to dereference the pointer, which means the page is mapped.

Since the lab places only one hidden page inside the search interval, returning the first valid candidate is sufficient.

### Part 2A - ret2win

The function `vulnerable()` copies attacker-controlled data into `stackbuf[16]` without checking the input length. As a result, the overflow can overwrite:

- 16 bytes of `stackbuf`
- 8 bytes of saved `RBP`
- 8 bytes of the saved return address

The payload uses the first three qwords as padding and overwrites the saved return address with the address of `win()`. When `vulnerable()` returns, execution jumps directly to `win()`.

### Part 2B - ROP

In this part there is no `win()` function to jump to directly, so the exploit must use the gadgets in `gadgets.s` to prepare the arguments for:

```c
call_me_maybe(rdi, rsi, rdx)
```

The target conditions are:

- `(rdi & 0x02) != 0`
- `rsi == 2 * rdi`
- `rdx == 1337`

The ROP chain is constructed as follows:

1. `gadget3`: execute `xor rdi, rdi` to set `rdi = 0`
2. `gadget5` three times: increment `rdi` until `rdi = 3`
3. `gadget6`: copy `rdi` into `rsi`, so `rsi = 3`
4. `gadget2`: shift `rsi` left once, so `rsi = 6`
5. `gadget1`: pop `191` into `rax`
6. `gadget4`: compute `rdx = rax * 7 = 1337`
7. Return into `call_me_maybe(3, 6, 1337)`

### Part 3 - Combining Egg Hunting and ROP

Part 3 combines the techniques from the previous sections:

- Reuse the egg-hunting technique to locate the hidden page that contains the gadgets.
- Once the base address of that page is known, reconstruct the absolute gadget addresses using their fixed offsets:
  - `+0x00`, `+0x10`, `+0x20`, `+0x30`, `+0x40`, `+0x50`
- Build a new ROP chain that satisfies the constraints for Part 3.

The target conditions for Part 3 are:

- `(rdi & 0x04) != 0`
- `rsi == 8 * rdi`
- `rdx == 93599359`

The final chain is:

1. `gadget3` sets `rdi = 0`
2. `gadget5` four times sets `rdi = 4`
3. `gadget6` copies `rdi` to `rsi`, so `rsi = 4`
4. `gadget2` three times shifts `rsi` to `32 = 8 * 4`
5. `gadget1` loads `rax = 13371337`
6. `gadget4` computes `rdx = 13371337 * 7 = 93599359`
7. Control flows into `call_me_maybe(4, 32, 93599359)`

## 3. Verification

Each part can be checked with:

```bash
python3 check.py 1a
python3 check.py 2a
python3 check.py 2b
python3 check.py 3
```

- Screenshots of the `check.py` output

![check.py output](./image.png)


## 4. Written Questions

### 1-2. Identify one other syscall that could be used for egg hunting.

One possible alternative syscall is `write()`.
If `addr` is passed as the source buffer in `write(1, (void *)addr, 1)`, the kernel will attempt to read one byte from that address.

- If the address is invalid, the syscall will fail with `EFAULT`.
- If the address is valid, the syscall may still fail for another reason, but it already reveals that the page is mapped.

Therefore, `write()` can also be used to distinguish mapped pages from unmapped pages.

### 1-4. Imagine you are the Intel engineer tasked with fixing this problem. How would you approach fixing it?

If I were responsible for mitigating this issue at the hardware or low-level system layer, I would focus on the following points:

1. Prevent prefetching and speculative execution from creating observable side effects for user-supplied addresses that are not permitted to be accessed.
2. Ensure that pointer validation happens before any optimization path can expose information through timing, cache state, TLB state, or page-walk behavior.
3. Make invalid-pointer handling terminate early and consistently, without leaking whether an address is mapped.
4. Add regression tests for syscalls and execution paths that may be abused for memory probing, such as `access()`, `write()`, `stat()`, and related speculative behaviors.

The goal is to guarantee that an invalid pointer reveals only one piece of information: that the pointer is invalid, and nothing more about the process address space layout.

## 5. Conclusion

This lab shows that ASLR alone is not a complete defense when an attacker can still:

- Discover which pages are mapped in the address space
- Combine that knowledge with a buffer overflow
- Reuse existing instruction sequences to build a ROP chain

In practice, effective memory protection requires a combination of randomization, safe pointer handling, and mitigation of side-channel leakage.
