# level02 — dixie (off-by-one sur le RBP sauvegardé)

Flag : `qeplvibynup98phqb312dkvhtpdkklac` (mot de passe SSH de level03)

## Lancement

```sh
./assets/scripts/rainfall-vm ssh level02
python3 ~/poc.py
```

## La faille

Dans `store_record()`, la boucle de lecture s'arrête sur `in_len <= BUF_SIZE`
(au lieu de `<`) : un payload de 65 octets écrase `buf[64]`.
gcc aligne `buf` à `rbp-0x40` sans padding, donc `buf[64]` est **l'octet de
poids faible du RBP sauvegardé** — un off-by-one classique (un byte trop
loin == un wrong move).

## La chaîne d'exécution

1. `store_record` finit par `leave; ret` : `rbp` devient le RBP corrompu
   (= `buf`), retour dans `main` qui garde ce `rbp` faussé.
2. `main` enchaîne `dump_records` / `printf`, puis finit par `leave; ret`.
3. Ce second `leave` fait `rsp = rbp` (= notre buffer) :
   `pop rbp` prend `payload[0:8]` (8 octets totalement contrôlés),
   `ret` saute sur `payload[8:16]`. RIP contrôlé + pivot de pile.

## Le piège : la zone écrasée (blast zone)

Le buffer vit **sous le rsp de main** : entre le retour de `store_record` et
le `leave` final, les frames de `printf` construites par `dump_records/main`
écrasent les octets `buf+32..buf+47` (paire rbp sauvé / adresse de retour
d'un printf, vérifié sous gdb). Un shellcode inline à cet endroit est
détruit avant le pivot. Seule la fenêtre `buf+16..buf+31` survit.

## L'exploit en deux étapes

- **Étape 1** : stub de 14 octets dans la fenêtre survivante `buf+16..buf+29`.
  Il hérite de `rbp = payload[0:8]` (pleinement contrôlé) :
  `xor eax,eax ; mov rsi,rbp ; xor edi,edi ; push LEN ; pop rdx ; syscall`
  → `read(0, buf-0x800, LEN)`, puis `jmp rsi`.
  `buf-0x800` = pile morte, loin sous la zone écrasée, et la pile est RWX
  sur ce niveau.
- **Étape 2** : 46 octets envoyés juste après le payload (écriture ≤ PIPE_BUF
  donc atomique sur le pipe : le `read()` du stub les récupère d'un bloc) :
  `setreuid(geteuid(), geteuid())` + `execve("/bin//sh", ["/bin//sh", NULL],
  NULL)`. Le SUID flag02 est conservé puis un shell lit la suite de stdin.

## Calibration (phase 1)

L'adresse de `buf` dépend de l'environnement : sonde `write(1,"HIT\n")`
envoyée **par stdin** (lue par le stub vers la pile morte). Si on voit
`HIT`, l'adresse devinée est la bonne.

Deux pièges rencontrés :
- **Faux positif** : `dump_records` affiche `%.64s` de `records[0].data`
  (copie du payload !) — une sonde inline contenant `"HIT"` est "détectée"
  pour n'importe quelle adresse. La sonde ne transite que par stdin, jamais
  dans le buffer.
- **Syscall faux** : `0x75` = 117 = `setresuid` (et non `setreuid` = 113 =
  `0x71`) → EINVAL, et dash droppe l'euid au lancement.
- Contrainte physique : l'octet bas de `buf` doit être ≤ `0xbf` (sinon
  `buf+0x40` déborde sur l'octet suivant et le pivot ne peut pas retomber
  sur `buf`) — ces adresses sont ignorées par le scan.

## Vérification

```
uid=1019(flag02) gid=1005(level02) groups=1005(level02),1001(levelgroup)
qeplvibynup98phqb312dkvhtpdkklac
```