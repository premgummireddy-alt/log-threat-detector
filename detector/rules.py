"""Rule-based detections mapped to MITRE ATT&CK."""
from collections import defaultdict
from datetime import timedelta

def brute_force(events, threshold=5, window_min=5):
    """T1110 Brute Force: >= threshold failures from one IP within window."""
    alerts, by_ip = [], defaultdict(list)
    for e in events:
        if e["type"] in ("failed", "invalid"):
            by_ip[e["ip"]].append(e["ts"])
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            j = i
            while j < len(times) and times[j] - times[i] <= timedelta(minutes=window_min):
                j += 1
            if j - i >= threshold:
                alerts.append({"rule": "SSH brute force", "mitre": "T1110", "severity": "high",
                               "ip": ip, "count": j - i, "first_seen": str(times[i])})
                break
    return alerts

def success_after_failures(events, min_fail=3):
    """T1078 Valid Accounts: successful login from an IP that previously failed repeatedly."""
    fails, alerts = defaultdict(int), []
    for e in sorted(events, key=lambda x: x["ts"]):
        if e["type"] in ("failed", "invalid"):
            fails[e["ip"]] += 1
        elif e["type"] == "accepted" and fails[e["ip"]] >= min_fail:
            alerts.append({"rule": "Login success after failures", "mitre": "T1078", "severity": "critical",
                           "ip": e["ip"], "user": e["user"], "prior_failures": fails[e["ip"]], "time": str(e["ts"])})
    return alerts

def user_enumeration(events, min_users=4):
    """T1087 Account Discovery: one IP trying many distinct usernames."""
    users = defaultdict(set)
    for e in events:
        if e["type"] in ("failed", "invalid"):
            users[e["ip"]].add(e["user"])
    return [{"rule": "Username enumeration", "mitre": "T1087", "severity": "medium",
             "ip": ip, "distinct_users": len(u)} for ip, u in users.items() if len(u) >= min_users]

def suspicious_sudo(events, keywords=("/etc/shadow", "useradd", "chmod 777", "nc ", "curl ", "wget ")):
    """T1548 Abuse Elevation Control: risky sudo commands."""
    return [{"rule": "Suspicious sudo command", "mitre": "T1548", "severity": "medium",
             "user": e["user"], "cmd": e["cmd"].strip(), "time": str(e["ts"])}
            for e in events if e["type"] == "sudo" and any(k in e["cmd"] for k in keywords)]

ALL_RULES = [brute_force, success_after_failures, user_enumeration, suspicious_sudo]
