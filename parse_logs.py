#!/usr/bin/env python3
# Minimal parser placeholder (usage: python parse_logs.py --input sample_logs.log --output output/)
import re, csv, os, argparse
from collections import Counter
SSH_FAIL_RE = re.compile(r'Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)')
APACHE_LOG_RE = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] ".*" (?P<code>\d{3}) .*')
def main(input_file, output_dir):
    events=[]; ipc=Counter()
    with open(input_file,'r',encoding='utf-8') as fh:
        for line in fh:
            line=line.strip(); 
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
        keys = events[0].keys() if events else ['raw']
        writer=csv.DictWriter(csvf,fieldnames=keys); writer.writeheader()
        for e in events: writer.writerow(e)
    with open(os.path.join(output_dir,'summary.txt'),'w',encoding='utf-8') as s:
        s.write(f"Total events: {len(events)}\n")
        s.write("Top IPs:\\n")
        for ip,c in ipc.most_common(10): s.write(f"- {ip}: {c}\\n")
    print('Outputs in', output_dir)

if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('--input','-i',required=True); p.add_argument('--output','-o',required=True)
    args=p.parse_args(); main(args.input,args.output)
