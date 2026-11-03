# level03 — armitage (setup)

Objectif : lire `/home/flag03/.pass` en tant que flag03 via le binaire SUID
`~/armitage` sur la VM. À faire en dev, pas encore résolu.

## Fichiers

- `program/armitage` — binaire SUID flag03 (copie de `~/armitage` sur la VM)
- `program/armitage.c` — source fournie sur la VM
- `program/README` — indice : "Armitage always had a plan. Find it."
- `poc.py` — squelette pwntools de départ (envoie un job valide, affiche la sortie)

## Environnement VM

Connexion : `./assets/scripts/rainfall-vm ssh level03`
Binaire sur la VM : `~/armitage` (SUID flag03, executé avec euid=flag03)

Outils dispo sur la VM : gdb+pwndbg, ROPgadget 7.7, one_gadget, pwntools 4.15.
ASLR désactivé sur la VM (`/proc/sys/kernel/randomize_va_space` = 0).

## Protections du binaire (relevées)

| Protection | État |
|---|---|
| NX (GNU_STACK RW) | **activée** — la pile n'est pas exécutable |
| Stack canary (`__stack_chk_fail`) | absent |
| PIE | absent (Type: EXEC, code à 0x400000) |
| RELRO | partiel (pas de BIND_NOW) |

Contrairement à level02, la pile est ici **non exécutable** : le shellcode
sur la pile ne fonctionnera pas. NX activée = le niveau où passer à autre
chose (ROP / ret2libc).

## Workflow dev

```sh
./assets/scripts/rainfall-vm ssh level03
python3 ~/poc.py          # a copier sur la VM (base64) ou dev local puis push
gdb -q ~/armitage         # pwndbg chargé via ~/.gdbinit
ROPgadget --binary ~/armitage
```