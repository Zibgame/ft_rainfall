# level05 — wintermute (setup)

Objectif : lire `/home/flag05/.pass` en tant que flag05 via le binaire SUID
`~/wintermute` sur la VM. À faire en dev, pas encore résolu.

## Fichiers

- `program/wintermute` — binaire SUID flag05 (copie de `~/wintermute` sur la VM)
- `program/wintermute.c` — source fournie sur la VM
- `program/README` — indice : "Wintermute was everywhere at once."
- `poc.py` — squelette pwntools de départ (envoie une query placeholder, affiche la sortie)

## Environnement VM

Connexion : `./assets/scripts/rainfall-vm ssh level05`
Binaire sur la VM : `~/wintermute` (SUID flag05, exécuté avec euid=flag05)

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

Profil identique à level03/04 : pas de shellcode sur la pile, gadgets
depuis la libc à base fixe si besoin. Retours d'expérience des niveaux
précédents :
- level03 : ret2libc simple (chain ROP dans le buffer d'overflow) ;
- level04 : `system()` est une impasse (le sh extérieur drope l'euid) —
  `execv(path, argv)` avec argv contenant `-p` conserve le SUID ;
- glibc plante sur le mélange séquentiel/positionnel en format string.

## Workflow dev

```sh
./assets/scripts/rainfall-vm ssh level05
python3 ~/poc.py          # a copier sur la VM (base64) ou dev local puis push
gdb -q ~/wintermute       # pwndbg chargé via ~/.gdbinit
ROPgadget --binary ~/wintermute
```
