#!/usr/bin/env python3
from pwn import *

BINARY = "./armitage"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"

PAYLOAD = b"JOB:hello\n"

io = process(BINARY)
io.sendafter(b"Prove yourself: ", PAYLOAD)
print(io.recvall(timeout=2).decode(errors="replace"))