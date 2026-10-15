"""Unsupervised anomaly scoring per source IP using Isolation Forest."""
import pandas as pd
from sklearn.ensemble import IsolationForest

def ip_features(events):
    df = pd.DataFrame(events)
    if df.empty:
        return df
    df["fail"] = df["type"].isin(["failed", "invalid"]).astype(int)
    df["ok"] = (df["type"] == "accepted").astype(int)
    df["hour"] = df["ts"].dt.hour
    g = df[df["ip"].notna()].groupby("ip")
    return pd.DataFrame({
        "events": g.size(), "failures": g["fail"].sum(), "successes": g["ok"].sum(),
        "distinct_users": g["user"].nunique(), "night_ratio": g["hour"].apply(lambda h: ((h < 6) | (h > 22)).mean()),
    })

def score(events, contamination=0.1):
    f = ip_features(events)
    if len(f) < 3:
        return f
    model = IsolationForest(contamination=contamination, random_state=42).fit(f)
    f["anomaly_score"] = -model.score_samples(f)
    f["is_anomaly"] = model.predict(f.drop(columns="anomaly_score")) == -1
    return f.sort_values("anomaly_score", ascending=False)
