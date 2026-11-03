# level04 — riviera (setup)

Objectif : lire `/home/flag04/.pass` en tant que flag04 via le binaire SUID
`~/riviera` sur la VM. À faire en dev, pas encore résolu.

## Fichiers

- `program/riviera` — binaire SUID flag04 (copie de `~/riviera` sur la VM)
- `program/riviera.c` — source fournie sur la VM
- `program/README` — indice : "Riviera showed you what wasn't there."
- `poc.py` — squelette pwntools de départ (Tag/Message placeholders, affiche la sortie)

## Environnement VM

Connexion : `./assets/scripts/rainfall-vm ssh level04`
Binaire sur la VM : `~/riviera` (SUID flag04, exécuté avec euid=flag04)

Outils dispo sur la VM : gdb+pwndbg, ROPgadget 7.7, one_gadget, pwntools 4.15.
ASLR désactivé sur la VM (`/proc/sys/kernel/randomize_va_space` = 0).
libc chargée à adresse fixe : `0x00007ffff7c00000`.

## Protections du binaire (relevées)

| Protection | État |
|---|---|
| NX (GNU_STACK RW) | **activée** |
| Stack canary (`__stack_chk_fail`) | absent |
| PIE | absent (Type: EXEC, code à 0x400000) |
| RELRO | partiel (pas de BIND_NOW) |

Profil identique à level03 : pas de shellcode sur la pile, pas de gadgets
`pop rdi` dans le binaire lui-même (gcc moderne sans `__libc_csu_init`),
donc gadgets/symboles depuis la libc à base fixe si besoin.

## Workflow dev

```sh
./assets/scripts/rainfall-vm ssh level04
python3 ~/poc.py          # a copier sur la VM (base64) ou dev local puis push
gdb -q ~/riviera          # pwndbg chargé via ~/.gdbinit
ROPgadget --binary ~/riviera
```
