import subprocess, sys, pathlib
ROOT = pathlib.Path(__file__).parents[1]; sys.path.insert(0, str(ROOT))
from detector.parser import parse_line
from detector.cli import run

def test_parse_failed():
    e = parse_line("Oct  2 02:13:00 srv sshd[1]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2")
    assert e["type"] == "failed" and e["ip"] == "1.2.3.4" and e["user"] == "root"

def test_sample_detections():
    subprocess.run([sys.executable, "sample_logs/generate.py"], cwd=ROOT, check=True)
    _, alerts, anomalies = run(ROOT / "sample_logs/auth.log")
    rules = {a["rule"] for a in alerts}
    assert {"SSH brute force", "Login success after failures", "Username enumeration", "Suspicious sudo command"} <= rules
    assert anomalies.index[0] == "203.0.113.45"
