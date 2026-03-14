#!/usr/bin/env python3
"""
SIEM Log Analyzer — Open Detection Engine
Purple Team Edition

Usage:
    python parse_logs.py --input sample_logs.log --output output/
    python parse_logs.py --input sample_logs.log --output output/ --export-iocs
    python parse_logs.py --input sample_logs.log --output output/ --export-iocs rrf_nemesis
    python parse_logs.py --input sample_logs.log --output output/ --rules custom_rules.json
"""

import re
import csv
import os
import json
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═══════════════════════════════════════════════════════════════════

@dataclass
class LogEvent:
    raw:           str
    source:        str = "other"     # apache | syslog | correlation | other
    ip:            str = ""
    timestamp:     str = ""
    method:        str = ""
    url:           str = ""
    http_version:  str = ""
    status_code:   str = ""
    response_size: str = ""
    user_agent:    str = ""
    port:          str = ""
    # Detection output
    severity:      str = "INFO"      # INFO | WARNING | CRITICAL
    alert_type:    str = ""
    rule_set:      str = ""
    tags:          list = field(default_factory=list)


@dataclass
class DetectionRule:
    name:       str
    severity:   str        # CRITICAL | WARNING | INFO
    tags:       list
    field:      str        # LogEvent attribute to inspect
    pattern:    str        # literal string or regex
    match_type: str        # "contains" | "regex" | "equals"
    rule_set:   str        # "rrf_nemesis" | "generic_web" | "auth" | "ssh" | custom


# ═══════════════════════════════════════════════════════════════════
#  BUILT-IN RULE SETS
# ═══════════════════════════════════════════════════════════════════

BUILTIN_RULES: list[DetectionRule] = [
    # ── rrf_nemesis signatures (CRITICAL) ──────────────────────────
    DetectionRule(
        name="Nemesis Scanner Detected",
        severity="CRITICAL",
        tags=["rrf_nemesis", "scanner"],
        field="user_agent",
        pattern="Nemesis-Security-Scanner/2.0",
        match_type="contains",
        rule_set="rrf_nemesis",
    ),
    DetectionRule(
        name="XSS Attempt (Nemesis)",
        severity="CRITICAL",
        tags=["rrf_nemesis", "xss"],
        field="raw",
        pattern=re.escape("<script>alert('NEMESIS_XSS')</script>"),
        match_type="regex",
        rule_set="rrf_nemesis",
    ),
    DetectionRule(
        name="SQLi Attempt (Nemesis)",
        severity="CRITICAL",
        tags=["rrf_nemesis", "sqli"],
        field="raw",
        pattern=re.escape("' OR '1'='1"),
        match_type="regex",
        rule_set="rrf_nemesis",
    ),
    # ── generic_web (WARNING) ──────────────────────────────────────
    DetectionRule(
        name="SQLi Attempt (Generic)",
        severity="WARNING",
        tags=["sqli"],
        field="url",
        pattern=r"(?:union\s+select|drop\s+table|insert\s+into|--|;--|'--|'\s+or\s+)",
        match_type="regex",
        rule_set="generic_web",
    ),
    DetectionRule(
        name="XSS Attempt (Generic)",
        severity="WARNING",
        tags=["xss"],
        field="url",
        pattern=r"(?:<script|javascript:|on\w+=|<img[^>]+onerror)",
        match_type="regex",
        rule_set="generic_web",
    ),
    DetectionRule(
        name="Path Traversal Attempt",
        severity="WARNING",
        tags=["traversal"],
        field="url",
        pattern=r"(?:\.\./|\.\.%2[Ff])",
        match_type="regex",
        rule_set="generic_web",
    ),
    DetectionRule(
        name="Suspicious Scanner UA",
        severity="WARNING",
        tags=["scanner"],
        field="user_agent",
        pattern=r"(?:nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|zgrab)",
        match_type="regex",
        rule_set="generic_web",
    ),
    # ── auth (WARNING) ─────────────────────────────────────────────
    DetectionRule(
        name="Auth Failure",
        severity="WARNING",
        tags=["auth"],
        field="status_code",
        pattern="401",
        match_type="equals",
        rule_set="auth",
    ),
    # ── ssh (WARNING) — applied by _check_syslog, listed for reference
    DetectionRule(
        name="SSH Brute Force Attempt",
        severity="WARNING",
        tags=["ssh"],
        field="source",
        pattern="syslog",
        match_type="equals",
        rule_set="ssh",
    ),
]

_SEVERITY_RANK = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}


# ═══════════════════════════════════════════════════════════════════
#  LOG PARSER
# ═══════════════════════════════════════════════════════════════════

class LogParser:
    """Parses Apache Combined/Common log format and Syslog SSH entries."""

    # Apache Combined Log Format (referer + UA optional for Common Log compat)
    APACHE_RE = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
        r' \S+ \S+ '
        r'\[(?P<ts>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) (?P<http_ver>HTTP/[\d.]+)" '
        r'(?P<code>\d{3}) '
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"'
        r'\s+"(?P<ua>[^"]*)")?'
    )

    SSH_FAIL_RE = re.compile(
        r'(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: '
        r'Failed password for (?:invalid user )?\S+ '
        r'from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)'
    )

    def _parse_apache(self, line: str) -> Optional[LogEvent]:
        m = self.APACHE_RE.match(line)
        if not m:
            return None
        return LogEvent(
            raw=line,
            source="apache",
            ip=m.group("ip"),
            timestamp=m.group("ts"),
            method=m.group("method"),
            url=m.group("url"),
            http_version=m.group("http_ver"),
            status_code=m.group("code"),
            response_size=m.group("size"),
            user_agent=m.group("ua") or "",
        )

    def _parse_syslog_ssh(self, line: str) -> Optional[LogEvent]:
        m = self.SSH_FAIL_RE.search(line)
        if not m:
            return None
        return LogEvent(
            raw=line,
            source="syslog",
            ip=m.group("ip"),
            timestamp=m.group("ts"),
            port=m.group("port"),
        )

    def parse_line(self, line: str) -> LogEvent:
        return (
            self._parse_apache(line)
            or self._parse_syslog_ssh(line)
            or LogEvent(raw=line, source="other")
        )

    def parse_file(self, filepath: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(self.parse_line(line))
        return events


# ═══════════════════════════════════════════════════════════════════
#  DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Rule-based detection engine. Rules are DataClass objects sorted by
    severity; the first matching rule wins (short-circuit).

    External rule sets can be loaded from JSON and merged at runtime.
    """

    BRUTEFORCE_THRESHOLD = 10

    def __init__(self, extra_rules: list[DetectionRule] | None = None):
        rules = BUILTIN_RULES[:]
        if extra_rules:
            rules.extend(extra_rules)
        # Sort CRITICAL → WARNING → INFO so high-severity rules fire first
        self._rules: list[DetectionRule] = sorted(
            rules, key=lambda r: _SEVERITY_RANK.get(r.severity, 9)
        )
        # Pre-compile regex patterns
        self._compiled: dict[str, re.Pattern] = {}
        for rule in self._rules:
            if rule.match_type in ("regex", "contains"):
                try:
                    self._compiled[rule.pattern] = re.compile(
                        rule.pattern, re.IGNORECASE
                    )
                except re.error:
                    pass

    @staticmethod
    def load_rules_from_json(path: str) -> list[DetectionRule]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [DetectionRule(**entry) for entry in data]

    def _match(self, rule: DetectionRule, event: LogEvent) -> bool:
        value = str(getattr(event, rule.field, "") or "")
        if rule.match_type == "equals":
            return value == rule.pattern
        pattern = self._compiled.get(rule.pattern)
        if pattern is None:
            return False
        return bool(pattern.search(value))

    def _apply_rules(self, event: LogEvent) -> None:
        for rule in self._rules:
            if rule.rule_set == "ssh":
                continue  # handled separately by _check_syslog
            if self._match(rule, event):
                event.severity  = rule.severity
                event.alert_type = rule.name
                event.rule_set  = rule.rule_set
                event.tags      = rule.tags[:]
                return

    def _check_syslog(self, event: LogEvent) -> None:
        event.severity  = "WARNING"
        event.alert_type = "SSH Brute Force Attempt"
        event.rule_set  = "ssh"
        event.tags      = ["ssh"]

    def analyze(self, events: list[LogEvent]) -> list[LogEvent]:
        for event in events:
            if event.source == "apache":
                self._apply_rules(event)
            elif event.source == "syslog":
                self._check_syslog(event)
        return events

    def correlate_bruteforce(self, events: list[LogEvent]) -> list[LogEvent]:
        """
        Correlate 404/403 errors per IP. If an IP exceeds the threshold,
        emit a synthetic CRITICAL alert. If that IP already triggered a
        rrf_nemesis rule, the bruteforce alert inherits the tag.
        """
        error_counts: Counter = Counter()
        nemesis_ips: set[str] = set()

        for e in events:
            if e.source == "apache" and e.status_code in ("404", "403"):
                error_counts[e.ip] += 1
            if "rrf_nemesis" in e.tags:
                nemesis_ips.add(e.ip)

        alerts: list[LogEvent] = []
        for ip, count in error_counts.items():
            if count > self.BRUTEFORCE_THRESHOLD:
                tags = ["bruteforce"]
                rs   = "generic_web"
                if ip in nemesis_ips:
                    tags.append("rrf_nemesis")
                    rs = "rrf_nemesis"
                alerts.append(LogEvent(
                    raw=f"[CORRELATION] {ip} — {count} x 404/403 errors",
                    source="correlation",
                    ip=ip,
                    severity="CRITICAL",
                    alert_type="Directory Bruteforce Detected",
                    rule_set=rs,
                    tags=tags,
                ))
        return alerts


# ═══════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Writes events.csv, top_ips.csv, summary.txt, and optional iocs.json."""

    _CSV_FIELDS = [
        "source", "ip", "timestamp", "method", "url",
        "status_code", "user_agent", "port",
        "severity", "alert_type", "rule_set", "tags", "raw",
    ]

    def write_events_csv(self, events: list[LogEvent], path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for e in events:
                row = {k: getattr(e, k, "") for k in self._CSV_FIELDS}
                row["tags"] = "|".join(e.tags)
                writer.writerow(row)

    def write_top_ips_csv(self, events: list[LogEvent], path: str) -> None:
        counter = Counter(e.ip for e in events if e.ip)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "event_count"])
            for ip, count in counter.most_common(20):
                writer.writerow([ip, count])

    def write_summary(
        self,
        events: list[LogEvent],
        correlation_alerts: list[LogEvent],
        path: str,
    ) -> None:
        all_events    = events + correlation_alerts
        ip_counter    = Counter(e.ip for e in all_events if e.ip)
        apache_events = [e for e in events if e.source == "apache"]
        ssh_events    = [e for e in events if e.source == "syslog"]
        status_counter = Counter(
            e.status_code for e in apache_events if e.status_code
        )

        security_alerts = [e for e in all_events if e.alert_type]
        security_alerts.sort(key=lambda e: _SEVERITY_RANK.get(e.severity, 9))

        # Group by rule_set for structured output
        alerts_by_rs: dict[str, list[LogEvent]] = defaultdict(list)
        for e in security_alerts:
            alerts_by_rs[e.rule_set or "other"].append(e)

        W = 60
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * W + "\n")
            f.write("  SIEM Log Analysis Report — Purple Team Edition\n")
            f.write(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * W + "\n\n")

            f.write(f"Total events parsed  : {len(events)}\n")
            f.write(f"  Apache/HTTP        : {len(apache_events)}\n")
            f.write(f"  Syslog/SSH         : {len(ssh_events)}\n")
            f.write(f"  Correlation alerts : {len(correlation_alerts)}\n\n")

            f.write("─" * W + "\n")
            f.write("Top IPs by event volume:\n")
            for ip, count in ip_counter.most_common(10):
                f.write(f"  {ip:<22} {count} events\n")

            f.write("\n─" * 1 + "─" * (W - 1) + "\n")
            f.write("HTTP Status Code Distribution:\n")
            for code, count in sorted(status_counter.items()):
                f.write(f"  {code}  →  {count} request(s)\n")

            # ── SECURITY ALERTS ────────────────────────────────────
            f.write("\n" + "=" * W + "\n")
            f.write("  SECURITY ALERTS (SIEM)\n")
            f.write("=" * W + "\n")

            if not security_alerts:
                f.write("  No alerts triggered.\n")
            else:
                n_crit = sum(1 for e in security_alerts if e.severity == "CRITICAL")
                n_warn = sum(1 for e in security_alerts if e.severity == "WARNING")
                f.write(f"  Total   : {len(security_alerts)}\n")
                f.write(f"  CRITICAL: {n_crit}\n")
                f.write(f"  WARNING : {n_warn}\n")

                # rrf_nemesis section first (Purple Team highlight)
                if "rrf_nemesis" in alerts_by_rs:
                    f.write("\n  ┌─ rrf_nemesis Signatures Detected ─────────────────┐\n")
                    for e in alerts_by_rs["rrf_nemesis"]:
                        f.write(f"  │  [{e.severity:<8}] {e.alert_type}\n")
                        f.write(f"  │           IP       : {e.ip}\n")
                        if e.url:
                            f.write(f"  │           URL      : {e.url}\n")
                        if e.user_agent:
                            f.write(f"  │           UA       : {e.user_agent}\n")
                        if e.timestamp:
                            f.write(f"  │           Time     : {e.timestamp}\n")
                        f.write(f"  │           Tags     : {', '.join(e.tags)}\n")
                        f.write(f"  │           Rule set : {e.rule_set}\n")
                        f.write("  │\n")
                    f.write("  └─────────────────────────────────────────────────────┘\n")

                # Other rule sets
                other_rs = [rs for rs in alerts_by_rs if rs != "rrf_nemesis"]
                for rs in other_rs:
                    label = rs.replace("_", " ").title()
                    f.write(f"\n  [ {label} ]\n")
                    f.write("  " + "─" * (W - 2) + "\n")
                    for e in alerts_by_rs[rs]:
                        f.write(f"  [{e.severity:<8}] {e.alert_type}  —  {e.ip}\n")
                        if e.url:
                            f.write(f"             URL : {e.url}\n")

            f.write("\n" + "=" * W + "\n")

    def write_iocs(
        self,
        events: list[LogEvent],
        correlation_alerts: list[LogEvent],
        path: str,
        filter_rs: str | None = None,
    ) -> int:
        """
        Export IOCs to JSON. If filter_rs is set, only that rule set is exported.
        Returns the number of IOCs written.
        """
        all_events = events + correlation_alerts
        ioc_events = [e for e in all_events if e.alert_type]
        if filter_rs:
            ioc_events = [e for e in ioc_events if e.rule_set == filter_rs]

        rule_sets_triggered = sorted({e.rule_set for e in ioc_events if e.rule_set})

        iocs = [
            {
                "ip":        e.ip,
                "alert":     e.alert_type,
                "rule_set":  e.rule_set,
                "severity":  e.severity,
                "timestamp": e.timestamp,
                "url":       e.url,
                "user_agent": e.user_agent,
                "tags":      e.tags,
            }
            for e in ioc_events
        ]

        payload = {
            "generated_at":        datetime.now().isoformat(),
            "filter":              filter_rs or "all",
            "rule_sets_triggered": rule_sets_triggered,
            "ioc_count":           len(iocs),
            "iocs":                iocs,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        return len(iocs)


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIEM Log Analyzer — Open Detection Engine (Purple Team)"
    )
    parser.add_argument("--input",  "-i", required=True,
                        help="Log file to analyze")
    parser.add_argument("--output", "-o", required=True,
                        help="Output directory")
    parser.add_argument("--rules",
                        help="Path to a JSON file with extra DetectionRule entries")
    parser.add_argument("--export-iocs", nargs="?", const="__all__", metavar="RULE_SET",
                        help="Export IOCs to iocs.json (optionally filter by rule set)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # Load extra rules if provided
    extra_rules: list[DetectionRule] | None = None
    if args.rules:
        extra_rules = DetectionEngine.load_rules_from_json(args.rules)
        print(f"[*] Loaded {len(extra_rules)} custom rule(s) from {args.rules}")

    log_parser = LogParser()
    engine     = DetectionEngine(extra_rules=extra_rules)
    reporter   = ReportGenerator()

    print(f"[*] Parsing {args.input} ...")
    events = log_parser.parse_file(args.input)
    print(f"[*] {len(events)} event(s) parsed.")

    print("[*] Running detection engine ...")
    engine.analyze(events)
    alerts_count = sum(1 for e in events if e.alert_type)
    print(f"[*] {alerts_count} alert(s) raised by rule matching.")

    print("[*] Running correlation rules ...")
    correlation_alerts = engine.correlate_bruteforce(events)
    if correlation_alerts:
        print(f"[!] {len(correlation_alerts)} bruteforce correlation alert(s).")

    all_events = events + correlation_alerts
    reporter.write_events_csv(all_events, os.path.join(args.output, "events.csv"))
    reporter.write_top_ips_csv(all_events, os.path.join(args.output, "top_ips.csv"))
    reporter.write_summary(events, correlation_alerts,
                           os.path.join(args.output, "summary.txt"))

    if args.export_iocs:
        rs_filter = None if args.export_iocs == "__all__" else args.export_iocs
        ioc_path  = os.path.join(args.output, "iocs.json")
        n = reporter.write_iocs(events, correlation_alerts, ioc_path, filter_rs=rs_filter)
        label = f"rule_set={rs_filter}" if rs_filter else "all rule sets"
        print(f"[+] {n} IOC(s) exported to {ioc_path} ({label})")

    print(f"[+] Done. Outputs written to: {args.output}/")


if __name__ == "__main__":
    main()
