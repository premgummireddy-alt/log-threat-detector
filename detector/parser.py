"""Parse Linux auth.log (sshd) lines into structured events."""
import re
from datetime import datetime

PATTERNS = {
    "failed": re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
    "accepted": re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "invalid": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
    "sudo": re.compile(r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)"),
}
TS = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})")

def parse_line(line, year=2026):
    m = TS.match(line)
    if not m:
        return None
    ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
    for kind, pat in PATTERNS.items():
        g = pat.search(line)
        if g:
            return {"ts": ts, "type": kind, **g.groupdict()}
    return None

def parse_file(path):
    with open(path, errors="ignore") as f:
        return [e for e in (parse_line(l) for l in f) if e]
