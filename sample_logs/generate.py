"""Generate a synthetic auth.log with benign traffic and simulated attacks (for testing only)."""
import random
from datetime import datetime, timedelta
random.seed(7)
t = datetime(2026, 10, 1, 8, 0, 0); out = []
fmt = lambda d: f"{d:%b} {d.day:>2} {d:%H:%M:%S}"
for i in range(150):
    t += timedelta(seconds=random.randint(30, 400))
    ip = f"10.0.0.{random.randint(2, 30)}"; u = random.choice(["alice", "bob", "carol"])
    if random.random() < 0.08:
        out.append(f"{fmt(t)} srv sshd[{1000+i}]: Failed password for {u} from {ip} port 22 ssh2")
    out.append(f"{fmt(t)} srv sshd[{1000+i}]: Accepted password for {u} from {ip} port 22 ssh2")
a = datetime(2026, 10, 2, 2, 13, 0)
for i, u in enumerate(["root", "admin", "test", "oracle", "root", "ubuntu", "root", "admin"] * 3):
    out.append(f"{fmt(a + timedelta(seconds=i*4))} srv sshd[9{i}]: Failed password for invalid user {u} from 203.0.113.45 port 4{i} ssh2")
out.append(f"{fmt(a + timedelta(minutes=3))} srv sshd[999]: Accepted password for admin from 203.0.113.45 port 4444 ssh2")
out.append(f"{fmt(a + timedelta(minutes=5))} srv sudo:    admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
out.append(f"{fmt(a + timedelta(minutes=6))} srv sudo:    admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd backdoor")
open("sample_logs/auth.log", "w").write("\n".join(out) + "\n")
