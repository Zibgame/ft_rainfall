# level07 — sprawl (setup)

Objectif : lire `/home/flag07/.pass` en tant que flag07 via le binaire SUID
`~/sprawl` sur la VM. À faire en dev, pas encore résolu.

**Setup volontairement neutre (spoiler-free)** : aucune analyse de faille,
aucune carte de fonctions, aucun indice d'interprétation. Tout le reste est
à découvrir sur le binaire.

## Fichiers

- `program/sprawl` — binaire SUID flag07 (copie de `~/sprawl` sur la VM),
  non strippé, binaire seul (ni source ni README sur la VM)
- `poc.py` — squelette pwntools (les deux prompts, placeholders, affiche la sortie)

## Environnement VM

Connexion : `./assets/scripts/rainfall-vm ssh level07`
Binaire sur la VM : `~/sprawl` (SUID flag07, exécuté avec euid=flag07)

Outils dispo sur la VM : gdb+pwndbg, ROPgadget 7.7, one_gadget, pwntools 4.15.
ASLR désactivé sur la VM (`/proc/sys/kernel/randomize_va_space` = 0).
libc chargée à adresse fixe : `0x00007ffff7c00000`.

## Protections du binaire (relevées)

| Protection | État |
|---|---|
| Stack canary (`__stack_chk_fail`) | **activé** |
| NX (GNU_STACK RW) | **activée** |
| PIE | absent (Type: EXEC, code à 0x400000) |
| RELRO | partiel (pas de BIND_NOW) |

## Méthodologie (générique, sans indice)

La marche à suivre est la même que pour les niveaux précédents, voir les
walkthroughs de `level01` à `level06` pour le fond :

1. Cartographier le binaire (`nm`, `strings`, `objdump -R/-d`)
2. Repérer les protections actives et leurs implications
3. Localiser les entrées utilisateur et leur cheminement en mémoire
4. Identifier la primitive puis construire le PoC

Leçons déjà acquises (détaillées dans les walkthroughs 02-06) : piège du
drop d'euid via `system()`, `execv("-p")`, leak de canary par format
string, calcul d'index varargs, retry si octet `0x0a`.

## Workflow dev

```sh
./assets/scripts/rainfall-vm ssh level07
python3 ~/poc.py          # a copier sur la VM (base64) ou dev local puis push
gdb -q ~/sprawl           # pwndbg chargé via ~/.gdbinit
ROPgadget --binary ~/sprawl
```
