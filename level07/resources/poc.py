#!/usr/bin/env python3
from pwn import *

BINARY = "./sprawl"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

ROUTE_TAG = b"test"
HEADER = b"00"

io = process(BINARY)
io.sendafter(b"Route tag: ", ROUTE_TAG + b"\n")
io.sendafter(b"Header (hex): ", HEADER + b"\n")
out = io.recvall(timeout=2)
print(out.decode(errors="replace"), flush=True)
