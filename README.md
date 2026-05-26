# Blue Team Tools

Outils d'analyse de sécurité développés dans le cadre de la formation Jedha.

---

## log_analyzer_v3.py — Apache Access Log Security Analyzer

Analyseur de logs Apache (Combined Log Format) orienté Blue Team.  
Détecte les tentatives d'attaque courantes à partir des logs d'accès HTTP.

### Détections

| Type d'attaque | Description |
|---|---|
| XSS | Patterns d'injection JavaScript (balises, événements, encodages) |
| SQL Injection | Patterns SQLi courants (UNION, OR 1=1, sleep, DROP, etc.) |
| Path Traversal / LFI | Traversées de répertoire et inclusion de fichiers locaux |
| Brute-force / Scan | Volume d'erreurs 401/403/404 par IP dépassant un seuil configurable |

### Usage

```bash
# Analyse basique
python log_analyzer_v3.py access.log

# Avec export du rapport dans un fichier
python log_analyzer_v3.py access.log --output rapport.txt

# Mode verbose (affiche chaque ligne parsée)
python log_analyzer_v3.py access.log --verbose

# Seuil brute-force personnalisé (défaut : 20 erreurs par IP)
python log_analyzer_v3.py access.log --bf-threshold 15
```

### Exemple de sortie

```
[+] 1247 entrées parsées (3 lignes ignorées)
[+] XSS=2  SQLi=5  PathTraversal=1  BruteForce/Scan=1 IP(s)

============================================================
  SECURITY ANALYSIS REPORT — Blue Team Lab
============================================================
  Généré le       : 2026-05-26 14:32:11
  Entrées lues    : 1247

  XSS détectés        : 2
  SQLi détectés       : 5
  Path Traversal      : 1
  IPs brute-force/scan: 1

  ⚠️  POTENTIELLEMENT RÉUSSIES (HTTP 200) : 1

  IPs attaquantes uniques : 2
    - 192.0.2.1
    - 192.0.2.2
```

### Format de log attendu

Combined Log Format (Apache / Nginx) :
```
127.0.0.1 - - [10/Jan/2026:10:30:00 +0000] "GET /page?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
```

### Prérequis

- Python 3.7+
- Aucune dépendance externe (stdlib uniquement : `argparse`, `re`, `collections`, `datetime`, `urllib.parse`)

### Architecture du script

| Module / Fonction | Rôle |
|---|---|
| `setup_cli()` | Configuration des arguments CLI |
| `read_log_file()` | Lecture en streaming (générateur, économe en RAM) |
| `parse_log_line()` | Parsing regex du format Combined Log |
| `_normalize()` | Double décodage URL + lowercase (anti-évasion) |
| `detect_xss/sqli/path_traversal()` | Détection par patterns |
| `detect_bruteforce()` | Comptage d'erreurs 401/403/404 par IP |
| `generate_report()` | Rapport consolidé avec identification des HTTP 200 |

### Limitations

- Analyse statique uniquement (pas de corrélation temporelle avancée)
- Faux positifs possibles sur des requêtes légitimes contenant des mots-clés SQL
- Combined Log Format uniquement

---

## Compétences démontrées

- Python (stdlib) — argparse, re, collections, datetime, urllib.parse
- Architecture modulaire (CLI / parsing / détection / rapport)
- Gestion d'erreurs et d'encodage
- Analyse de logs de sécurité
- Détection de patterns d'attaque (XSS, SQLi, Path Traversal, brute-force)
- Documentation technique

---

## Avertissement

Outil développé dans un cadre éducatif pour l'analyse de logs de test.  
À adapter, tester et valider avant tout usage en environnement de production.
