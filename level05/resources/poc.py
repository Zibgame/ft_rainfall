#!/usr/bin/env python3
from pwn import *

BINARY = "./wintermute"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

QUERY = b"what is the matrix"

io = process(BINARY)
io.sendafter(b"Query: ", QUERY + b"\n")
out = io.recvall(timeout=2)
print(out.decode(errors="replace"), flush=True)
