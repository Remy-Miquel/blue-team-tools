#!/usr/bin/env python3
"""
Apache Access Log Security Analyzer — v3
Blue Team Lab Tool

Détections :
  - XSS
  - SQL Injection
  - Path Traversal / LFI
  - Brute-force / scan (volume par IP sur codes 401/404)

Usage :
  python log_analyzer_v3.py access.log
  python log_analyzer_v3.py access.log --output rapport.txt --verbose
  python log_analyzer_v3.py access.log --bf-threshold 15
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote


# =========================================================
# PATTERN LISTS — XSS / SQLi / Path Traversal
# =========================================================

XSS_PATTERNS = [
    # Balises/événements dangereux (formes précises pour réduire les faux positifs)
    '<script', '</script>', 'javascript:',
    'alert(', 'prompt(', 'confirm(', 'eval(',
    'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
    '<iframe src=', '<img src=javascript:', 'document.cookie',
    'document.write(', 'window.location',
    # Encodages URL
    '%3cscript', '%3c%2fscript', 'javascript%3a',
    # Encodages HTML / unicode
    '&#x3c;script', '&#60;script', '\x3cscript',
    # Marqueur de test courant
    '<xsstag',
]

SQL_PATTERNS = [
    # Conditions booléennes classiques
    'or 1=1', "or '1'='1", 'or "1"="1', "' or '", '" or "',
    'and 1=1', 'and 1=2',
    # UNION
    'union select', 'union all select',
    # Commentaires SQL
    "'--", '";--', "';--", '--+', '/*', '*/',
    # Time-based blind
    'sleep(', 'benchmark(', 'waitfor delay', 'pg_sleep(',
    # Exfiltration de schéma
    'information_schema', 'sys.tables', 'sysobjects',
    # Fonctions de fichier
    'load_file(', 'into outfile', 'into dumpfile',
    # DDL/DML dangereux
    'drop table', 'drop database', 'delete from', 'truncate table',
    # Exécution de commande
    'xp_cmdshell', 'exec(', 'execute(',
    # Concaténation / encodage
    'group_concat(', 'char(', 'concat(', 'cast(', 'convert(',
    'hex(', '0x',
    # Encodages URL
    '%27%20or', '%27--', 'union%20select', '%20or%201',
    '%20union%20', '%27%20and',
]

PATH_TRAVERSAL_PATTERNS = [
    # Traversées classiques (décodées par unquote avant comparaison)
    '../', '..\\',
    # Variantes encodées résiduelles (après un seul passage d'unquote)
    '%2e%2e%2f', '%2e%2e/', '..%2f', '..%5c',
    # Fichiers système Linux cibles
    '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group',
    '/proc/self/environ', '/proc/self/cmdline',
    # Fichiers système Windows cibles
    'win.ini', 'boot.ini', 'system32/drivers/etc/hosts',
    # Wrappers PHP d'inclusion (LFI)
    'php://filter', 'php://input', 'php://fd',
    'data://', 'file://',
    # expect:// est un wrapper d'exécution (RCE), pas d'inclusion — retiré de cette catégorie
    # Il serait plus pertinent dans un scanner de Command Injection
    # Inclusion distante via paramètre applicatif (ex: ?page=http://attacker.com)
    # NOTE: on ne cherche pas 'http://' ou 'https://' en général —
    # ils apparaissent dans chaque referer et créeraient des milliers de faux positifs.
    # On cible les patterns typiques d'inclusion de fichier distant.
    '?page=http', '?file=http', '?include=http',
    '?page=ftp', '?url=http', '?redirect=http',
]


# -- Regex de parsing (format Combined Log Apache/Nginx) --

#  IP  ident  user  [timestamp]  "request"  status  size  "referer"  "user-agent"
_LOG_RE = re.compile(
    r'(?P<ip>\S+)'
    r' \S+ \S+'
    r' \[(?P<timestamp>[^\]]+)\]'
    r' "(?P<request>[^"]*)"'
    r' (?P<status>\d{3})'
    r' (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)")?'
    r'(?: "(?P<user_agent>[^"]*)")?'
)


# CLI / arguments

def setup_cli():
    # Arguments CLI — retourne le namespace argparse.
    parser = argparse.ArgumentParser(
        description="Analyseur de logs Apache — Blue Team Lab",
    )
    parser.add_argument("file",
                        help="Chemin vers le fichier de log à analyser")
    parser.add_argument("--output", "-o", default=None,
                        help="Enregistrer le rapport dans un fichier (optionnel)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Afficher chaque entrée parsée pendant l'analyse")
    parser.add_argument("--bf-threshold", type=int, default=20,
                        metavar="N",
                        help="Seuil d'erreurs 401/404 par IP pour alerter brute-force/scan (défaut: 20)")
    return parser.parse_args()


# --- Lecture fichier ---

def read_log_file(file_path):
    # Générateur — évite de charger tout le fichier en RAM.
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                yield line
    except FileNotFoundError:
        print(f"[!] Erreur : fichier introuvable — {file_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[!] Erreur : permission refusée — {file_path}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Erreur lecture fichier : {exc}", file=sys.stderr)
        sys.exit(1)


# Parsing ligne par ligne

def parse_log_line(line):
    """
    Parse une ligne de log Apache/Nginx Combined Format via regex.
    Retourne un dict ou None si la ligne est invalide.
    """
    line = line.strip()
    if not line:
        return None

    match = _LOG_RE.match(line)
    if not match:
        return None

    return {
        'ip':         match.group('ip'),
        'timestamp':  match.group('timestamp'),
        'request':    match.group('request'),
        'status_code': match.group('status'),
        'size':       match.group('size'),
        'referer':    match.group('referer') or '-',
        'user_agent': match.group('user_agent') or '-',
    }


# Détection des attaques (double-décodage URL avant comparaison)

def _normalize(text):
    # Double-décodage URL + lowercase — couvre la plupart des évasions par encodage.
    try:
        decoded = unquote(unquote(text))  # double-décodage
    except Exception:
        decoded = text
    return decoded.lower()


def detect_xss(entries):
    hits = []
    for entry in entries:
        req = _normalize(entry['request'])
        for pattern in XSS_PATTERNS:
            if pattern in req:
                hits.append({**entry, 'matched_pattern': pattern, 'attack_type': 'XSS'})
                break
    return hits


def detect_sqli(entries):
    hits = []
    for entry in entries:
        req = _normalize(entry['request'])
        for pattern in SQL_PATTERNS:
            if pattern in req:
                hits.append({**entry, 'matched_pattern': pattern, 'attack_type': 'SQLi'})
                break
    return hits


def detect_path_traversal(entries):
    hits = []
    for entry in entries:
        req = _normalize(entry['request'])
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in req:
                hits.append({**entry, 'matched_pattern': pattern, 'attack_type': 'PathTraversal'})
                break
    return hits


def detect_bruteforce(entries, threshold):
    """
    Détecte le brute-force (401) et le scan de répertoires (404)
    en comptant les occurrences par IP.
    Retourne un dict { ip: {'401': n, '404': n} } pour les IPs
    dépassant le seuil sur au moins un code.
    """
    counts = defaultdict(lambda: defaultdict(int))
    for entry in entries:
        if entry['status_code'] in ('401', '403', '404'):
            counts[entry['ip']][entry['status_code']] += 1

    suspicious = {}
    for ip, codes in counts.items():
        total_auth_errors = codes.get('401', 0) + codes.get('403', 0)
        total_404 = codes.get('404', 0)
        if total_auth_errors >= threshold or total_404 >= threshold:
            suspicious[ip] = {
                '401/403': total_auth_errors,
                '404':     total_404,
            }
    return suspicious


# =========================================================
# RAPPORT + ORCHESTRATION
# =========================================================

def _section(title):
    return [f"\n{'─' * 60}", f"  {title}", '─' * 60]


def generate_report(entries, xss_hits, sqli_hits, path_hits,
                    bf_ips, output_file=None):
    """
    Construit et affiche le rapport de sécurité consolidé.
    Sauvegarde optionnellement dans output_file.
    """
    all_attacks = xss_hits + sqli_hits + path_hits
    attacker_ips = {h['ip'] for h in all_attacks} | set(bf_ips.keys())

    # Attaques potentiellement réussies (code 200)
    successful = [h for h in all_attacks if h['status_code'] == '200']

    lines = []
    lines.append("=" * 60)
    lines.append("  SECURITY ANALYSIS REPORT — Blue Team Lab")
    lines.append("=" * 60)
    lines.append(f"  Généré le       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Entrées lues    : {len(entries)}")
    lines.append("")
    lines.append(f"  XSS détectés        : {len(xss_hits)}")
    lines.append(f"  SQLi détectés       : {len(sqli_hits)}")
    lines.append(f"  Path Traversal      : {len(path_hits)}")
    lines.append(f"  IPs brute-force/scan: {len(bf_ips)}")
    lines.append("")

    if successful:
        lines.append(f"  ⚠️  POTENTIELLEMENT RÉUSSIES (HTTP 200) : {len(successful)}")
    else:
        lines.append(f"  ✅  Aucune attaque avec réponse 200 détectée")

    lines.append(f"\n  IPs attaquantes uniques : {len(attacker_ips)}")
    for ip in sorted(attacker_ips):
        lines.append(f"    - {ip}")

    # --- Détail XSS ---
    if xss_hits:
        lines += _section(f"XSS — {len(xss_hits)} hit(s)")
        for h in xss_hits:
            flag = " ⚠️ 200" if h['status_code'] == '200' else f" [{h['status_code']}]"
            lines.append(f"  {h['ip']}{flag}  pattern={h['matched_pattern']!r}")
            req = h['request']
            display = req[:100] + ('…' if len(req) > 100 else '')
            lines.append(f"    → {display}")

    # --- Détail SQLi ---
    if sqli_hits:
        lines += _section(f"SQL Injection — {len(sqli_hits)} hit(s)")
        for h in sqli_hits:
            flag = " ⚠️ 200" if h['status_code'] == '200' else f" [{h['status_code']}]"
            lines.append(f"  {h['ip']}{flag}  pattern={h['matched_pattern']!r}")
            req = h['request']
            display = req[:100] + ('…' if len(req) > 100 else '')
            lines.append(f"    → {display}")

    # --- Détail Path Traversal ---
    if path_hits:
        lines += _section(f"Path Traversal / LFI — {len(path_hits)} hit(s)")
        for h in path_hits:
            flag = " ⚠️ 200" if h['status_code'] == '200' else f" [{h['status_code']}]"
            lines.append(f"  {h['ip']}{flag}  pattern={h['matched_pattern']!r}")
            req = h['request']
            display = req[:100] + ('…' if len(req) > 100 else '')
            lines.append(f"    → {display}")

    # --- Brute-force / Scan ---
    if bf_ips:
        lines += _section(f"Brute-force / Scan de répertoires — {len(bf_ips)} IP(s)")
        for ip, codes in sorted(bf_ips.items()):
            lines.append(f"  {ip}")
            lines.append(f"    401/403 : {codes['401/403']}  |  404 : {codes['404']}")

    lines.append("\n" + "=" * 60)

    report = "\n".join(lines)
    print(report)

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report + "\n")
            print(f"\n[+] Rapport sauvegardé → {output_file}")
        except OSError as exc:
            print(f"[!] Impossible d'écrire le rapport : {exc}", file=sys.stderr)



def main():
    """Orchestre le workflow complet d'analyse."""
    args = setup_cli()

    # --- Lecture et parsing ---
    entries = []
    skipped = 0
    for raw_line in read_log_file(args.file):
        entry = parse_log_line(raw_line)
        if entry is None:
            skipped += 1
        else:
            entries.append(entry)
            if args.verbose:
                print(f"  [parsed] {entry['ip']} {entry['status_code']} {entry['request'][:80]}")

    print(f"[+] {len(entries)} entrées parsées ({skipped} lignes ignorées)")

    if not entries:
        print("[!] Aucune entrée valide — vérifiez le format du fichier (Combined Log Format attendu).")
        sys.exit(0)

    # --- Détections ---
    xss_hits  = detect_xss(entries)
    sqli_hits = detect_sqli(entries)
    path_hits = detect_path_traversal(entries)
    bf_ips    = detect_bruteforce(entries, threshold=args.bf_threshold)

    print(f"[+] XSS={len(xss_hits)}  SQLi={len(sqli_hits)}  "
          f"PathTraversal={len(path_hits)}  BruteForce/Scan={len(bf_ips)} IP(s)")

    # --- Rapport ---
    generate_report(entries, xss_hits, sqli_hits, path_hits,
                    bf_ips, output_file=args.output)


if __name__ == "__main__":
    main()
