#!/usr/bin/env python3
from pwn import *

BINARY = "./3jane"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

REQUEST_ID = b"test"
ACCESS_CODE = b"code"

io = process(BINARY)
io.sendafter(b"Request ID: ", REQUEST_ID + b"\n")
io.sendafter(b"Access code: ", ACCESS_CODE + b"\n")
out = io.recvall(timeout=2)
print(out.decode(errors="replace"), flush=True)
