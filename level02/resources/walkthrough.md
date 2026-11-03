# Rainfall — Level02 Walkthrough

## 1. Understanding the program

We connect as `level02`. The home directory contains the SUID binary
`dixie` (owned by `flag02`) and its source `dixie.c`.

The program stores one record: a 64-byte buffer read one byte at a time,
then printed back. The goal: run code as `flag02` and read
`/home/flag02/.pass`.

## 2. The vulnerability: an off-by-one on the saved RBP

In `store_record()`:

```c
in_len = 0;
while (in_len <= BUF_SIZE) {          /* <= instead of < */
    in_ch = read(0, &buf[in_len], 1);
    ...
}
```

The loop stops on `in_len <= 64`, so a 65-byte payload also writes
`buf[64]`. gcc aligns `buf` at `rbp-0x40` with no padding, so `buf[64]`
IS the low byte of the saved RBP — a classic off-by-one.

## 3. What one corrupted byte gives us

1. `store_record` ends with `leave; ret`: RBP becomes the corrupted
   value (= `buf`) and control returns to `main`, which keeps this RBP.
2. `main` then runs `dump_records` / `printf` and ends with `leave; ret`.
3. That final `leave` does `rsp = rbp` (= our buffer):
   `pop rbp` takes `payload[0:8]` (8 fully controlled bytes), then
   `ret` jumps to `payload[8:16]`. RIP controlled + stack pivot.

## 4. The trap: the blast zone

The buffer lives BELOW main's rsp: between store_record's return and the
final leave, the printf frames built by dump_records/main write over
bytes `buf+32..buf+47` (verified under gdb: a saved-RBP/return-address
pair lands there). Any payload placed in that window is destroyed before
the pivot. Only `buf+16..buf+31` survives — the first version of the
probe "worked" only because its write syscall fired before the clobbered
tail.

## 5. The exploit in two stages

- **Stage 1**: a 14-byte stub inside the surviving window
  (`buf+16..buf+29`). It inherits `rbp = payload[0:8]` (fully controlled):

  ```asm
  xor eax, eax
  mov rsi, rbp          ; target = payload[0:8]
  xor edi, edi          ; stdin
  push LEN ; pop rdx
  syscall               ; read(0, buf-0x800, LEN)
  jmp rsi
  ```

  `buf-0x800` is dead stack far below the blast zone, and the stack is
  RWX on this level.

- **Stage 2**: 46 bytes sent right after the payload (one write, atomic
  on a pipe, so the stub's read() grabs it whole):
  `setreuid(geteuid(), geteuid())` + `execve("/bin//sh",
  ["/bin//sh", NULL], NULL)`. The flag02 SUID is kept, then a shell
  reads the rest of stdin.

## 6. Calibration

The buffer address depends on the environment: a position-independent
probe (`write(1, "HIT\n")`) is brute-forced over the stack range.

Two traps met on the way:

- **False positive**: `dump_records` prints `%.64s` of `records[0].data`
  (a copy of the payload!) — a probe containing "HIT" inline is detected
  for ANY address. The probe must travel through stdin only, never land
  in the buffer.
- **Wrong syscall**: `0x75` = 117 = `setresuid`, not `setreuid` (113 =
  `0x71`) — EINVAL, and dash then drops the euid at startup.
- Physical limit: the low byte of `buf` must be <= `0xbf` (otherwise
  `buf+0x40` carries into the next byte and the pivot cannot land on
  `buf`) — those addresses are skipped by the scan.

## 7. Result

```text
uid=1019(flag02) gid=1005(level02) groups=1005(level02),1001(levelgroup)
qeplvibynup98phqb312dkvhtpdkklac
```

The flag is the SSH password for level03.
