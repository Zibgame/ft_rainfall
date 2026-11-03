#!/usr/bin/env python3
from pwn import *

BINARY = "./riviera"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

TAG = b"hologram"
MESSAGE = b"nothing to see here"

io = process(BINARY)
io.sendafter(b"Tag: ", TAG + b"\n")
io.sendafter(b"Message: ", MESSAGE + b"\n")
out = io.recvall(timeout=2)
print(out.decode(errors="replace"), flush=True)
