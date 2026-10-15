# Log Threat Detector

Security analytics tool that parses Linux `auth.log` (SSH/sudo) and detects attacks using **MITRE ATT&CK-mapped rules** plus **unsupervised ML (Isolation Forest)** to rank anomalous source IPs.

## Detections
| Rule | ATT&CK | Severity |
|---|---|---|
| SSH brute force (N failures in a time window) | T1110 | High |
| Successful login after repeated failures | T1078 | Critical |
| Username enumeration (many users from one IP) | T1087 | Medium |
| Suspicious sudo commands (`/etc/shadow`, `useradd`, ...) | T1548 | Medium |

The ML layer builds per-IP features (event count, failures, successes, distinct users, night-time ratio) and scores outliers with scikit-learn's Isolation Forest.

## Run
```bash
pip install -r requirements.txt
python sample_logs/generate.py           # synthetic log with a simulated attack
python -m detector.cli sample_logs/auth.log --json report.json
```
Works on real logs too: `python -m detector.cli /var/log/auth.log`.

## Tests
`pytest tests`

Python · pandas · scikit-learn · regex · MITRE ATT&CK
