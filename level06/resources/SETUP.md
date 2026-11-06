# level06 — 3jane (setup)

Objectif : lire `/home/flag06/.pass` en tant que flag06 via le binaire SUID
`~/3jane` sur la VM. À faire en dev, pas encore résolu.

## Fichiers

- `program/3jane` — binaire SUID flag06 (copie de `~/3jane` sur la VM)
- `poc.py` — squelette pwntools (les deux prompts, placeholders, affiche la sortie)

**Premier niveau binaire seul** : ni source `3jane.c`, ni README sur la VM.
Tout passe par l'analyse du binaire (nm, strings, objdump, gdb).

## Environnement VM

Connexion : `./assets/scripts/rainfall-vm ssh level06`
Binaire sur la VM : `~/3jane` (SUID flag06, exécuté avec euid=flag06)

Outils dispo sur la VM : gdb+pwndbg, ROPgadget 7.7, one_gadget, pwntools 4.15.
ASLR désactivé sur la VM (`/proc/sys/kernel/randomize_va_space` = 0).
libc chargée à adresse fixe : `0x00007ffff7c00000`.

## Protections du binaire (relevées)

| Protection | État |
|---|---|
| **Stack canary** (`__stack_chk_fail`) | **activé — premier niveau avec canary** |
| NX (GNU_STACK RW) | **activée** |
| PIE | absent (Type: EXEC, code à 0x400000) |
| RELRO | partiel (pas de BIND_NOW) |

Un canary change la donne : un overflow naïf qui écrase le return address
fera aborter le programme (`*** stack smashing detected ***`). Pistes
classiques : leak du canary (format string si printf contrôlable), ou
overwrite qui ne touche PAS le canary (e.g. off-by-one, variables cibles).

## Recon (faits observés, pas d'analyse d'exploit)

Comportement : prompt `[3JANE] Request ID:` (log via strcspn) puis prompt
`[3JANE] Access code:` (check, prefix `STRAYLIGHT_` dans les strings), puis
statut du vault.

Symboles utiles (binaire non strippé) :
- fonctions : `init_vault` (0x401276), `log_request` (0x401418),
  `authenticate` (0x4014de), `display_vault` (0x401594), `main` (0x40165c)
- imports : `gets@plt` (0x4010d0), `fgets`, `strcspn`, `strncmp`, `printf`,
  `puts`, `putchar`, `snprintf`, `strncpy`, `fflush`
- strings : `STRAYLIGHT_`, `entry_%04x`, `Access granted. Clearance level: %u`,
  `Access denied.`, `Vault status:`, ALPHA/BETA/GAMMA/DELTA
- global : `vault` @ `0x4040c0` (.bss)

Retours d'expérience des niveaux précédents :
- libc fixe à `0x7ffff7c00000`, gadgets libc : `pop rdi` +0x10C08D,
  `pop rsi` +0x110B7D, `execv` +0xEF010, `"/bin/sh"` +0x1CC42F
- `system()` ok uniquement après `setreuid(geteuid(), geteuid())`
  (sinon dash dropp l'euid) ; sinon `execv("/bin/sh", ["/bin/sh","-p",NULL])`
- glibc plante sur le mélange séquentiel/positionnel en format string

## Workflow dev

```sh
./assets/scripts/rainfall-vm ssh level06
python3 ~/poc.py          # a copier sur la VM (base64) ou dev local puis push
gdb -q ~/3jane            # pwndbg chargé via ~/.gdbinit
ROPgadget --binary ~/3jane
```
