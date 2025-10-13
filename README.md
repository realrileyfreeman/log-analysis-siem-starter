Log Analysis — SIEM Starter

Projet personnel : analyse de logs (syslog et Apache) développée pour mon portfolio.
Réalisé par : [Ton Nom]

Objectif
Je pars d’un jeu de logs, j’automatise le parsing pour extraire des indicateurs utiles en détection (tentatives SSH échouées, erreurs HTTP, top IPs) et je produis des exports CSV + un résumé texte. L’idée : démontrer la chaîne complète (collecte → parsing → indicateurs → export).

Fonctionnalités principales
- Parsing de logs syslog et Apache (exemples fournis).
- Détection simple : tentatives SSH échouées, erreurs HTTP (4xx/5xx), top IPs, détection basique de scan de ports.
- Exports générés : events.csv, top_ips.csv, summary.txt.

Comment exécuter
1) Créer un environnement Python (recommendé) :
   python -m venv venv
   source venv/bin/activate

2) Installer les dépendances (optionnel) :
   pip install -r requirements.txt

3) Lancer l’analyse :
   python parse_logs.py --input sample_logs.log --output output/

Remarques
- C’est un projet d’entraînement / portfolio. Aucune action offensive n’est incluse : tout est en lecture et analyse de logs.
