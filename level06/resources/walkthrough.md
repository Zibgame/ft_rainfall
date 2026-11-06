# Rainfall — Level06 Walkthrough

## 1. Understanding the program

We connect as `level06`. The home directory contains the SUID binary
`3jane` (owned by `flag06`) — and NOTHING else. First level without
source code and without README: everything comes from reversing.

The program shows two prompts: `[3JANE] Request ID:` then
`[3JANE] Access code:`, then prints a vault status with four entries
(ALPHA/BETA/GAMMA/DELTA, clearance 1/2/4/8).

## 2. Protections: the canary changes the game

```text
Stack canary : ON  (first level of the chain with one)
NX           : ON
PIE          : no
RELRO        : partial
```

A naive overflow overwrites the canary and the program aborts with
`*** stack smashing detected ***` before its `ret`. The old
level03/05 recipe (blind padding + ROP) is dead here.

## 3. Two bugs, mapped by disassembly

The binary is not stripped, so `nm` gives the whole layout:

| Function | Address | What it does |
|---|---|---|
| `log_request` | 0x401418 | `fgets(buf, 0x40)` + `strcspn` then **`printf(buf)`** |
| `authenticate` | 0x4014de | `gets(buf@rbp-0x90)` + `strncmp(buf, "STRAYLIGHT_", 11)` |

- In `log_request` (0x4014a9), the user-controlled buffer is passed as
  the FORMAT of `printf` (rdi = buffer, no `%s` argument): a format
  string bug, like level04 but with 63 usable characters.
- In `authenticate`, `gets` writes unbounded bytes into a buffer at
  `rbp-0x90` — a real overflow — and the function HAS a canary at
  `rbp-0x8` (`mov %fs:0x28` in the prologue, `__stack_chk_fail` in the
  epilogue).

## 4. Leaking the canary

The canary is thread-local: the SAME value for every function of the
process. `log_request` runs BEFORE `authenticate` in the same run, so a
leak through the format string gives the exact value to rewrite later.

Frame walk for `printf(buf)` called from `log_request` (`sub $0x50`):

```text
arg  6..13 : buf qwords   (rbp-0x50 .. rbp-0x18)
arg     14 : unused slot   (rbp-0x10)
arg     15 : CANARY        (rbp-0x8)
```

The probe is five characters: `%15$p`. It prints the canary — which
always ends in 0x00 (the LSB is null by design, to resist string leaks).

## 5. Rebuilding a safe payload

`gets` copies raw bytes (including 0x00) until a newline, so the canary
can be rewritten byte-for-byte:

```text
"A" * 136        buffer (up to the canary)
canary (8)       leaked value, unchanged  -> check passes
fake RBP (8)     junk
ROP chain        see below
```

Offsets: buffer -> canary = 0x88 = 136, buffer -> return address =
0x98 = 152. The chain is the level03/05 recipe: `setreuid(1023, 1023)`
then `system("/bin/sh")` with the fixed libc base `0x7ffff7c00000`
(pop rdi at +0x10c08d, pop rsi at +0x110b7d, setreuid at +0x127370,
system at +0x58750, "/bin/sh" at +0x1cc42f). The "Access denied." line
is cosmetic: `gets` has already overwritten everything before the
`strncmp` even runs.

## 6. Practical notes

- The canary is random per run (kernel AT_RANDOM), so the leak and the
  exploit must happen in the SAME process — they do: one run, two
  prompts.
- A random canary byte can be 0x0a (2.7% chance over 7 bytes), which
  would truncate the gets line: the poc retries with a fresh process.
- pwntools trap: after `recvuntil(b"Access code: ")` the marker is
  consumed — sending with `sendafter(b"Access code: ", ...)` waits for
  it again and hangs forever. Use `send()`.

## 7. Result

```text
uid=1023(flag06) gid=1009(level06) groups=1009(level06),1001(levelgroup)
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```

The flag is the SSH password for level07.
