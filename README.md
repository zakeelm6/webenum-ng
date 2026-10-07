# webenum-ng

L'equivalent web de `enum4linux-ng` : un seul orchestrateur qui enchaine
**fingerprint -> decouverte de contenu -> scan de vulns -> outils CMS**, tout
en parallele, s'adapte aux outils installes, puis sort un rapport HTML / Markdown
/ JSON avec une liste de **prochaines etapes priorisees**.

Au lieu de retaper 6 outils a la main, tu lances une commande et tu obtiens une
vue d'ensemble plus un plan d'action.

## Caracteristiques

- **Rapide** : toutes les phases tournent en parallele ; nuclei est *product-aware*
  (il detecte la techno au fingerprint et ne charge que les templates utiles via
  `-tags`, ex. `dell,iis`) avec des flags optimises (`-duc -ni -timeout 10 -retries 1`).
- **Adaptatif** : detecte le CMS et lance l'outil dedie tout seul
  (WordPress -> wpscan, Joomla -> joomscan, Drupal -> droopescan).
- **S'auto-configure** : saute proprement les outils absents, probe http/https,
  gere les certificats auto-signes.
- **Scans authentifies** : `--creds` (basic) et `--cookie` propages a tous les outils.
- **Recommandations** : analyse les findings et dit quoi exploiter en premier.
- **Rapports** : HTML autonome (theme sombre, severites), Markdown (checklist), JSON.

## Installation

```bash
git clone https://github.com/zakeelm6/webenum-ng.git
cd webenum-ng
chmod +x webenum-ng.py
# optionnel : l'appeler de partout
ln -sf "$PWD/webenum-ng.py" ~/.local/bin/webenum-ng
```

Dependances : Python 3 (stdlib uniquement) + les outils que tu veux enveloppes
(`whatweb`, `feroxbuster`/`ffuf`, `nuclei`, `nikto`, `nmap`, `wpscan`, et pour
`--active` : `sqlmap`, `dalfox`). Tout ce qui manque est simplement saute.

## Usage

```bash
webenum-ng http://10.129.44.80                     # scan complet
webenum-ng https://10.10.10.10:1311 --only vuln    # juste les vulns sur un port precis
webenum-ng 10.10.10.10 -w big.txt -t 80 --full     # profondeur max
webenum-ng http://target --creds admin:pass --active   # authentifie + exploit leger
webenum-ng target --dry-run                        # affiche les commandes sans rien lancer
```

Options cles :

| Option | Effet |
|---|---|
| `-w` | wordlist (chemin complet ou nom court cherche dans seclists Web-Content) |
| `-t` / `-j` | threads par outil / outils en parallele |
| `--fast` / `--full` | rapide (nikto off, nuclei high+) / complet |
| `--only` / `--skip` | par categorie : `fingerprint,content,vuln,cms,active` |
| `--creds USER:PASS` | auth HTTP basic injectee dans les scans |
| `--cookie NAME=VAL` | cookie de session pour scans authentifies |
| `--active` | phase exploit legere (sqlmap + dalfox), voir plus bas |
| `--nuclei-tags t1,t2` | force les tags nuclei (sinon auto-detectes) |
| `--all-templates` | nuclei charge tout (lent) au lieu du ciblage par produit |
| `--no-open` | ne pas ouvrir le rapport HTML a la fin |
| `--dry-run` | affiche les commandes sans executer |

## Prochaines etapes (recommandations)

A la fin du scan, l'outil analyse les findings et sort une liste d'actions
concretes **priorisees** (HIGH / MED / LOW) avec la commande a lancer. Exemples
declenches automatiquement : `.git` expose -> git-dumper ; phpMyAdmin -> creds
defaut + INTO OUTFILE ; Dell OpenManage -> CVE-2020-5377 (file read) ; WordPress
-> wpscan enum+brute ; erreur SQL -> sqlmap ; 403 -> techniques de bypass ;
backups / robots / upload / API, etc. Present en console, en HTML (badges) et en
Markdown (checklist cochable).

## Phase active (exploit leger)

```bash
webenum-ng http://target --active
```

Ajoute, **uniquement avec le flag** (passage de enum a exploit) :
- **sqlmap** : SQLi, crawl + forms (`--crawl=2 --forms --level=2 --risk=2`)
- **dalfox** : XSS avec mining de parametres (DOM + dict)

Envoie de vrais payloads offensifs. L'auth (`--creds` / `--cookie`) est transmise
a ces outils.

## Sorties

Dans `webenum-<host>-<timestamp>/` :
- `report.html` : rapport autonome, theme sombre, sections repliables, findings
  colores par severite, prochaines etapes en badges
- `report.md` : meme contenu en Markdown (checklist)
- `report.json` : exploitable par script (`next_steps` + `results`)
- `raw/<outil>.txt` : sortie brute de chaque outil

## Avertissement

A n'utiliser que sur des cibles que tu es **autorise** a tester (labs, CTF,
missions). La phase `--active` envoie des payloads offensifs : redouble de
prudence sur le scope.

## Auteur

Zakariya Elmansouri
- GitHub : [@zakeelm6](https://github.com/zakeelm6)
- LinkedIn : [zakariya-el-mansouri](https://www.linkedin.com/in/zakariya-el-mansouri)
