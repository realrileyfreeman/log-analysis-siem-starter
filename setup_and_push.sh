#!/usr/bin/env bash
# Usage: bash ./setup_and_push.sh GITHUB_USERNAME REPO_NAME
set -e

GITHUB_USER="$1"
REPO_NAME="$2"
LOCAL_DIR="${HOME}/projects/${REPO_NAME}"
REPO_DESC="Projet personnel — Log Analysis (parsing de logs, détections basiques, exports CSV)"

cho
echo "== Création du dossier local et des fichiers de base =="
mkdir -p "${LOCAL_DIR}"
cd "${LOCAL_DIR}"

# README
cat > README.md <<'EOF'
Log Analysis — SIEM Starter

Projet personnel : analyse de logs (syslog et Apache) développée pour mon portfolio.
Réalisé par : Omar Camara

Objectif
Je pars d’un jeu de logs, j’automatise le parsing pour extraire des indicateurs utiles en détection (tentatives SSH échouées, erreurs HTTP, top IPs) et je produis des exports CSV + un résumé texte. L’idée : démontrer la chaîne complète (collecte → parsing → indicateurs → export).

Fonctionnalités principales
- Parsing de logs syslog et Apache (exemples fournis).
- Détection simple : tentatives SSH échouées, erreurs HTTP (4xx/5xx), top IPs, détection basique de scan de ports.
- Exports générés : events.csv, top_ips.csv, summary.txt.

Comment exécuter
1) Créer un environnement Python :
   python -m venv venv
   source venv/bin/activate

2) Installer les dépendances (optionnel) :
   pip install -r requirements.txt

3) Lancer l’analyse :
   python parse_logs.py --input sample_logs.log --output output/

Remarques
- C’est un projet d’entraînement / portfolio. Aucune action offensive n’est incluse : tout est en lecture et analyse de logs.
EOF

# create minimal parse_logs.py if missing
if [ ! -f parse_logs.py ]; then
  cat > parse_logs.py <<'PYEOF'
#!/usr/bin/env python3
# Simplified parser: usage: python parse_logs.py --input sample_logs.log --output output/
import re, csv, os, argparse
from collections import Counter
SSH_FAIL_RE = re.compile(r'(?P<ts>\S+ \d+ \d+:\d+:\d+) .*sshd.*Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
APACHE_LOG_RE = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<ts>[^\]]+)\] "(?P<req>[^"]+)" (?P<code>\d{3}) (?P<size>\d+)')
def main(input_file, output_dir):
    events=[]; ipc=Counter()
    with open(input_file,'r',encoding='utf-8') as fh:
        for line in fh:
            line=line.strip()
            if not line: continue
            m=SSH_FAIL_RE.search(line)
            if m:
                ip=m.group('ip'); ipc[ip]+=1; events.append({'type':'ssh_failed','ip':ip,'raw':line}); continue
            m=APACHE_LOG_RE.search(line)
            if m:
                ip=m.group('ip'); ipc[ip]+=1; events.append({'type':'http','ip':ip,'code':m.group('code'),'raw':line}); continue
            events.append({'type':'other','raw':line})
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir,'events.csv'),'w',newline='',encoding='utf-8') as csvf:
        keys = events[0].keys() if events else ['raw']; writer=csv.DictWriter(csvf,fieldnames=keys); writer.writeheader()
        for e in events: writer.writerow(e)
    with open(os.path.join(output_dir,'summary.txt'),'w',encoding='utf-8') as s:
        s.write(f"Total events: {len(events)}\n"); s.write("Top IPs:\n")
        for ip,c in ipc.most_common(10): s.write(f"- {ip}: {c}\n")
    print("Outputs in", output_dir)

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--input','-i',required=True); p.add_argument('--output','-o',required=True)
    args=p.parse_args(); main(args.input,args.output)
PYEOF
  chmod +x parse_logs.py
fi

# sample logs + small extras
cat > sample_logs.log <<'LOGS'
Oct 13 12:00:01 host1 sshd[1234]: Failed password for invalid user admin from 198.51.100.23 port 45213 ssh2
127.0.0.1 - - [13/Oct/2025:12:05:01 +0200] "GET /index.html HTTP/1.1" 200 512
LOGS

echo "pandas==2.1.1" > requirements.txt
cat > .gitignore <<'GIT'
venv/
__pycache__/
output/
docs/screenshots/
*.pyc
GIT

mkdir -p docs/screenshots

# git init + commit
if [ ! -d .git ]; then
  git init
  git checkout -b main || git branch -M main
fi
git add .
git commit -m "chore: initial commit — Log Analysis project" || true

echo "=== Création du repository sur GitHub et push ==="
gh repo create "${GITHUB_USER}/${REPO_NAME}" --public --description "${REPO_DESC}" --source=. --remote=origin --push

echo "Terminé. Repo: https://github.com/${GITHUB_USER}/${REPO_NAME}"
