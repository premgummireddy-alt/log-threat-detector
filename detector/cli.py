"""Usage: python -m detector.cli sample_logs/auth.log [--json report.json]"""
import argparse, json
from .parser import parse_file
from .rules import ALL_RULES
from .anomaly import score

def run(path):
    events = parse_file(path)
    alerts = [a for rule in ALL_RULES for a in rule(events)]
    return events, alerts, score(events)

def main():
    ap = argparse.ArgumentParser(description="Detect threats in Linux auth logs")
    ap.add_argument("log"); ap.add_argument("--json")
    a = ap.parse_args()
    events, alerts, anomalies = run(a.log)
    print(f"Parsed {len(events)} events, {len(alerts)} alerts\n")
    for al in sorted(alerts, key=lambda x: ["critical", "high", "medium"].index(x["severity"])):
        print(f"[{al['severity'].upper():8}] {al['rule']} ({al['mitre']}) -> " +
              ", ".join(f"{k}={v}" for k, v in al.items() if k not in ("rule", "mitre", "severity")))
    if not anomalies.empty:
        print("\nTop anomalous IPs (Isolation Forest):"); print(anomalies.head(5).round(3).to_string())
    if a.json:
        json.dump({"alerts": alerts, "anomalies": anomalies.reset_index().to_dict("records")}, open(a.json, "w"), indent=2, default=str)

if __name__ == "__main__":
    main()
