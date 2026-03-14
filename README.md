# Log Analysis — SIEM / Open Detection Engine

**Réalisé par : Omar Camara**
Portfolio Master Cybersécurité — Projet Purple Team

---

## Contexte / Context

FR — Ce projet constitue le **volet défensif (Blue Team)** d'un exercice Purple Team.
Il est conçu pour analyser et détecter les traces laissées par l'outil offensif
**[rrf_nemesis](https://github.com/RRF-cyber/rrf_nemesis)** (Red Team), tout en restant
un moteur de détection générique applicable à n'importe quelle source de logs.

EN — This project is the **defensive (Blue Team) component** of a Purple Team exercise.
It is built to analyze and detect traces left by the offensive tool
**[rrf_nemesis](https://github.com/RRF-cyber/rrf_nemesis)** (Red Team), while remaining
a generic detection engine applicable to any log source.

---

## Architecture

```
parse_logs.py
├── LogEvent         — Dataclass: unified event model
├── DetectionRule    — Dataclass: portable, self-contained detection rule
├── LogParser        — Apache Combined/Common + Syslog SSH parser
├── DetectionEngine  — Rule-based engine with pluggable rule sets
│   ├── rule set: rrf_nemesis   (CRITICAL)
│   ├── rule set: generic_web   (WARNING — SQLi, XSS, Path Traversal, scanners)
│   ├── rule set: auth          (WARNING — HTTP 401)
│   └── rule set: ssh           (WARNING — SSH brute force)
└── ReportGenerator  — Writes events.csv, top_ips.csv, summary.txt, iocs.json
```

---

## Lien Purple Team / Purple Team Link

| Outil offensif (rrf_nemesis) | Détection SIEM |
|---|---|
| User-Agent `Nemesis-Security-Scanner/2.0` | Rule set `rrf_nemesis` → CRITICAL |
| Payload XSS `<script>alert('NEMESIS_XSS')</script>` | Rule set `rrf_nemesis` → CRITICAL |
| Payload SQLi `' OR '1'='1` | Rule set `rrf_nemesis` → CRITICAL |
| Directory bruteforce (>10 × 404/403) | Corrélation automatique → CRITICAL |

L'export `--export-iocs` génère un fichier `iocs.json` structuré (IP, alerte, rule set,
timestamp) qui peut être réinjecté dans rrf_nemesis comme blocklist ou transmis à un SOAR.

The `--export-iocs` flag produces a structured `iocs.json` (IP, alert, rule set,
timestamp) that can be fed back into rrf_nemesis as a blocklist or forwarded to a SOAR.

---

## Utilisation / Usage

```bash
# Analyse standard
python3 parse_logs.py --input sample_logs.log --output output/

# Avec export IOCs (tous les rule sets)
python3 parse_logs.py --input sample_logs.log --output output/ --export-iocs

# Avec export IOCs filtré (ex: rrf_nemesis uniquement)
python3 parse_logs.py --input sample_logs.log --output output/ --export-iocs rrf_nemesis

# Avec règles de détection supplémentaires (format JSON)
python3 parse_logs.py --input sample_logs.log --output output/ --rules custom_rules.json
```

### Outputs générés dans `output/`

| Fichier | Contenu |
|---|---|
| `events.csv` | Tous les événements parsés avec sévérité, alerte et tags |
| `top_ips.csv` | Top 20 IPs par volume d'événements |
| `summary.txt` | Rapport texte structuré avec section "Security Alerts (SIEM)" |
| `iocs.json` | Indicateurs de compromission exportables (si `--export-iocs`) |

---

## Règles custom / Custom Rules

Il est possible d'injecter des règles supplémentaires via un fichier JSON sans modifier le code :

```json
[
  {
    "name": "Nikto Scanner",
    "severity": "CRITICAL",
    "tags": ["nikto", "scanner"],
    "field": "user_agent",
    "pattern": "Nikto",
    "match_type": "contains",
    "rule_set": "scanners"
  }
]
```

---

## Prérequis / Requirements

Python 3.10+ — stdlib uniquement, aucune dépendance externe.

---

> Projet d'entraînement / portfolio. Aucune action offensive incluse — lecture et analyse de logs uniquement.
