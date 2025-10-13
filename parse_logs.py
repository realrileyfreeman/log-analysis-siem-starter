#!/usr/bin/env python3
"""
parse_logs.py
Simple log parser for demo / portfolio:
- Detecte tentatives SSH échouées
- Compte les erreurs HTTP 4xx/5xx
- Top IPs
- Détection basique "scanner" : même IP qui contacte plusieurs ports en <window_seconds>

Usage:
    python parse_logs.py --input sample_logs.log --output output/
"""
import re
import csv
import os
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# --- Config / regex basiques (adaptées au sample_logs.log fourni) ---
SSH_FAIL_RE = re.compile(r'(?P<ts>\S+ \d+ \d+:\d+:\d+) .*sshd.*Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
APACHE_LOG_RE = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<ts>[^\]]+)\] "(?P<req>[^"]+)" (?P<code>\d{3}) (?P<size>\d+)')

def parse_syslog_ts(ts_str):
    try:
        this_year = datetime.now().year
        return datetime.strptime(f"{ts_str} {this_year}", "%b %d %H:%M:%S %Y")
    except Exception:
        return None

def parse_apache_ts(ts_str):
    try:
        return datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def main(input_file, output_dir, scanner_window=10, scanner_port_threshold=5):
    events = []
    failed_ssh = Counter()
    http_errors = Counter()
    ip_counter = Counter()
    ip_ports = defaultdict(list)

    with open(input_file, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            m = SSH_FAIL_RE.search(line)
            if m:
                ts = parse_syslog_ts(m.group('ts'))
                ip = m.group('ip')
                port = int(m.group('port'))
                events.append({
                    'timestamp': ts.isoformat() if ts else '',
                    'type': 'ssh_failed',
                    'ip': ip,
                    'port': port,
                    'raw': line
                })
                failed_ssh[ip] += 1
                ip_counter[ip] += 1
                ip_ports[ip].append((ts, port))
                continue

            m = APACHE_LOG_RE.search(line)
            if m:
                ip = m.group('ip')
                ts = parse_apache_ts(m.group('ts'))
                code = int(m.group('code'))
                req = m.group('req')
                events.append({
                    'timestamp': ts.isoformat() if ts else '',
                    'type': 'http',
                    'ip': ip,
                    'code': code,
                    'req': req,
                    'raw': line
                })
                ip_counter[ip] += 1
                if 400 <= code < 600:
                    http_errors[code] += 1
                continue

            events.append({'timestamp': '', 'type': 'other', 'ip': '', 'raw': line})

    suspected_scanners = []
    for ip, hits in ip_ports.items():
        hits_sorted = sorted(hits, key=lambda x: x[0] or datetime.min)
        for i in range(len(hits_sorted)):
            window_ports = set()
            t0 = hits_sorted[i][0]
            if not t0:
                continue
            j = i
            while j < len(hits_sorted) and (hits_sorted[j][0] - t0).total_seconds() <= scanner_window:
                window_ports.add(hits_sorted[j][1])
                j += 1
            if len(window_ports) >= scanner_port_threshold:
                suspected_scanners.append({'ip': ip, 'start': hits_sorted[i][0].isoformat(), 'ports_count': len(window_ports)})
                break

    ensure_dir(output_dir)
    events_csv = os.path.join(output_dir, 'events.csv')
    top_ips_csv = os.path.join(output_dir, 'top_ips.csv')
    summary_txt = os.path.join(output_dir, 'summary.txt')

    with open(events_csv, 'w', newline='', encoding='utf-8') as csvfile:
        if events:
            fieldnames = list(events[0].keys())
        else:
            fieldnames = ['timestamp', 'type', 'ip', 'raw']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow(e)

    with open(top_ips_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ip', 'count'])
        for ip, cnt in ip_counter.most_common(50):
            writer.writerow([ip, cnt])

    with open(summary_txt, 'w', encoding='utf-8') as fh:
        fh.write("=== Log Analysis Summary ===\n")
        fh.write(f"Total events parsed: {len(events)}\n\n")

        fh.write("Top IPs:\n")
        for ip, cnt in ip_counter.most_common(10):
            fh.write(f"- {ip}: {cnt}\n")
        fh.write("\n")

        fh.write("SSH failed attempts (top 10):\n")
        for ip, cnt in failed_ssh.most_common(10):
            fh.write(f"- {ip}: {cnt} failed auth\n")
        fh.write("\n")

        fh.write("HTTP errors (by status code):\n")
        for code, cnt in sorted(http_errors.items()):
            fh.write(f"- {code}: {cnt}\n")
        fh.write("\n")

        fh.write("Suspected scanners (basic rule: >= {} ports within {}s):\n".format(scanner_port_threshold, scanner_window))
        if suspected_scanners:
            for s in suspected_scanners:
                fh.write(f"- {s['ip']} started {s['start']} -> ports seen: {s['ports_count']}\n")
        else:
            fh.write("- None detected\n")

    print("Done.")
    print(f"- events: {events_csv}")
    print(f"- top ips: {top_ips_csv}")
    print(f"- summary: {summary_txt}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple log parser for portfolio")
    parser.add_argument('--input', '-i', required=True, help='Input log file')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--scanner-window', type=int, default=10, help='Window seconds to detect port scanning')
    parser.add_argument('--scanner-threshold', type=int, default=5, help='Distinct ports threshold to flag scanner')
    args = parser.parse_args()
    main(args.input, args.output, scanner_window=args.scanner_window, scanner_port_threshold=args.scanner_threshold)
