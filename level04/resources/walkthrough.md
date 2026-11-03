# Rainfall — Level04 Walkthrough

## 1. Understanding the program

We connect as `level04`. The home directory contains the SUID binary
`riviera` (owned by `flag04`) and its source `riviera.c`.

The program asks for a tag (31 bytes) and a message (255 bytes), stores
them, and displays them. The goal: run code as `flag04` and read
`/home/flag04/.pass`.

## 2. The vulnerability

In `display_entry`:

```c
printf(log_buf[idx].tag);      // user-controlled FORMAT STRING
```

The tag is passed to `printf` as the format itself. Classic format string:
`%n` writes anywhere, positional `%N$` reaches stack slots.

Key constraints found by reading the code and the disassembly:

- the tag is only 31 characters long (fgets 32) — every format must fit;
- the tag becomes `printf`'s ONLY argument, so printf's varargs walk
  `handle_input`'s stack frame: `%10$` = first qword of our message
  (msg is at `rbp-0x120`), verified with a `%10$p %11$p` probe;
- `fgets` stops at `\n`, so no address may contain the byte 0x0a.

## 3. Why system() is a dead end

First idea: overwrite `printf@got` (0x404010, writable, partial RELRO)
with `system`, so `printf(tag)` becomes `system(tag)` on the next call.

Problem: `system()` runs `/bin/sh -c <command>` — and that outer shell
DROPS the effective uid (uid=level04 != euid=flag04) before running
anything. Every command executed through system() runs as level04.
Confirmed on level02: an euid!=uid shell always drops.

And glibc refuses the shortcut anyway: mixing sequential (`%191c`) and
positional (`%11$hn`) specs crashes inside `printf_positional` — every
spec must be positional (`%1$...c`), which eats the 31-char budget.

## 4. The plan: steal the saved RBP, pivot the stack

`handle_input`'s saved RBP sits at `[rbp_handle]` and its return address
at `[rbp_handle+8]`. Both are reachable by the write, and both are
consumed AFTER the format write fires (handle returns after display).

- Write 1: `[rbp_handle]` low 2 bytes ← address inside our message
  (`fake_rbp = msg_addr + 8`). A single `%hn` — the high bytes already
  match (same 64K block).
- Write 2: `[rbp_handle+8]` low 2 bytes ← `0x1444`, a `leave ; ret`
  gadget inside the binary (display's own epilogue, non-PIE so fixed).

Then:

```text
handle's leave : pop rbp  <- [rbp_handle] = fake_rbp
handle's ret   : rip = [rbp_handle+8] = leave;ret gadget
leave          : rsp = fake_rbp  -> rsp now points INSIDE our message
ret            : rip = msg[2]    -> ROP chain built in the message
```

Format (all positional, 29 chars):

```text
%1$5188c%11$hn%1$52564c%10$hn
```

## 5. The ROP chain (lives inside the 256-byte message)

NX is on, so no shellcode — but ASLR is off, so libc gadgets are fixed:

| Item | Address |
|---|---|
| pop rdi ; ret (libc) | 0x7ffff7d0c08d |
| pop rsi ; ret (libc) | 0x7ffff7d10b7d |
| execv (libc) | 0x7ffff7cef010 |
| leave ; ret (binary) | 0x401444 |

`execv("/bin/sh", ["/bin/sh", "-p", NULL])` — execv inherits `environ`
(it needs only rdi+rsi, and this libc has no clean `pop rdx; ret`),
and `-p` makes dash KEEP the euid: the shell runs as flag04.

## 6. Calibration

msg lives at `rbp_handle-0x120`; the leak is deterministic because ASLR
is off and the poc spawns both runs with the same environment:
phase 1 prints `%8$p %46$p %10$p` (saved RBP, main's RBP, msg marker),
phase 2 recomputes every address from `rbp_handle`.

## 7. Result

```text
uid=1005(level04) gid=1007(level04) euid=1021(flag04) groups=1007(level04),1001(levelgroup)
x0w8xdgapz3tjopq2s11a27yro7krazm
```

The flag is the SSH password for level05.
