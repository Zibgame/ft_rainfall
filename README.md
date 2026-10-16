# RainFall

> Reverse engineering et exploitation de binaires ELF x86-64 dans un environnement contrôlé.

RainFall est un projet de cybersécurité offensive réalisé dans le cadre du cursus de l'École 42. L'objectif est d'auditer une série de programmes volontairement vulnérables, de comprendre précisément leur comportement puis d'exploiter leurs failles afin de progresser d'un niveau au suivant.

Au-delà de l'exploitation, ce projet développe une compétence essentielle en sécurité applicative : savoir identifier les hypothèses dangereuses dans un programme pour ensuite écrire du code plus robuste.

## Ce que ce projet démontre

- Analyse méthodique d'un programme sans documentation préalable
- Lecture de code assembleur et compréhension de la mémoire d'un processus
- Identification de vulnérabilités et construction de preuves de concept reproductibles
- Adaptation d'une stratégie face aux mécanismes modernes de protection
- Documentation claire d'un raisonnement technique complexe
- Persévérance, autonomie et collaboration dans la résolution de problèmes

## Périmètre technique

Le parcours principal comprend **11 niveaux**, chacun centré sur une faiblesse ou une technique d'exploitation différente :

- dépassements de tampon sur la pile ;
- erreurs *off-by-one* et dépassements d'entiers ;
- vulnérabilités de chaînes de format ;
- corruption de mémoire sur la pile et le tas ;
- détournement du flot d'exécution ;
- *Return-Oriented Programming* et `ret2libc` ;
- fuites d'adresses et calculs d'offsets à l'exécution ;
- contournement de protections telles que **NX**, **stack canaries**, **ASLR**, **RELRO** et **PIE**.

Le dernier niveau obligatoire combine plusieurs de ces protections et impose de chaîner différentes primitives d'exploitation dans une même solution.

## Démarche suivie

Pour chaque binaire, l'analyse suit une méthode reproductible :

1. **Reconnaissance** — identification du format, de l'architecture, des symboles et des protections actives.
2. **Analyse statique** — désassemblage et reconstitution de la logique du programme.
3. **Analyse dynamique** — observation des registres, de la pile, du tas et du flot d'exécution.
4. **Identification de la faille** — validation de la primitive disponible et de ses contraintes.
5. **Exploitation** — construction d'une preuve de concept minimale et fiable.
6. **Documentation** — explication de la vulnérabilité, de la stratégie et des mesures correctives possibles.

## Outils et environnement

| Domaine | Outils / notions |
| --- | --- |
| Analyse statique | `objdump`, `readelf`, `nm`, assembleur x86-64 |
| Débogage | `gdb`, inspection des registres et de la mémoire |
| Sécurité binaire | `checksec`, ELF, SUID, conventions d'appel |
| Exploitation | ROP, `ret2libc`, format strings, stack/heap corruption |
| Automatisation | Shell, scripts de génération de charges utiles |
| Environnement | Linux, SSH, machine virtuelle VirtualBox |

## Organisation des livrables

Chaque niveau est documenté séparément afin de rendre l'analyse vérifiable et facile à présenter :

```text
levelXX/
├── flag
└── resources/
    ├── walkthrough.md
    └── scripts et ressources utiles
```

Les binaires vulnérables ne sont pas versionnés. Ils sont analysés exclusivement dans la machine virtuelle fournie avec le projet.

## Compétences transférables

L'intérêt professionnel de RainFall dépasse le cadre du pentest. Le projet renforce la capacité à :

- diagnostiquer un comportement bas niveau difficile à reproduire ;
- raisonner à partir de faits observables plutôt que d'hypothèses ;
- mesurer l'impact réel d'une vulnérabilité ;
- expliquer une chaîne de causes techniques à différents interlocuteurs ;
- intégrer les réflexes de sécurité dès la conception et la revue de code.

## Cadre éthique

Toutes les manipulations présentées dans ce projet sont réalisées sur des programmes intentionnellement vulnérables, au sein d'un environnement isolé et autorisé à des fins pédagogiques. Les techniques décrites ne doivent être utilisées que sur des systèmes pour lesquels une autorisation explicite a été accordée.

## À propos

Projet du cursus **42** — catégorie *cybersécurité offensive / exploitation binaire*.

Pour découvrir mes autres projets : [profil GitHub](https://github.com/Zibgame).
