"""FastAPI server for the DNS-tunnel classifier.

Loads dns_tunnel_classifier.joblib once at startup and exposes:
  GET  /api/features  → ordered list of feature names + UI groups
  GET  /api/samples   → 15 example rows from the held-out test set
  POST /api/predict   → P(tunnel) for a submitted feature row

The static SPA is served from app/static.

Run:
    pip install -r app/requirements.txt
    uvicorn app.main:app --reload --port 8000
"""

from pathlib import Path
from typing import Dict

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent

bundle = joblib.load(ROOT / "dns_tunnel_classifier.joblib")
MODEL = bundle["model"]
FEATS: list[str] = list(bundle["features"])

# UI grouping mirrors features_documentation.md so the form is navigable.
GROUPS: list[dict] = [
    {"title": "Traffic volumetrics",
     "fields": ["n_packets", "duration_sec", "query_rate"]},
    {"title": "Uniqueness & entropy",
     "fields": ["unique_qnames", "unique_subdomains", "unique_qname_ratio",
                "entropy_mean", "entropy_std", "subdomain_entropy_mean"]},
    {"title": "Inter-arrival time",
     "fields": ["iat_mean", "iat_std", "iat_min", "iat_max"]},
    {"title": "Payload size",
     "fields": ["payload_mean", "payload_std", "payload_max"]},
    {"title": "Query-type fractions",
     "fields": ["txt_frac", "null_frac", "aaaa_frac", "a_frac",
                "any_frac", "tunnel_type_frac"]},
    {"title": "String composition",
     "fields": ["avg_qname_len", "avg_subdomain_len", "avg_label_count",
                "avg_max_label_len", "avg_b64_ratio", "avg_hex_ratio",
                "avg_numeric_ratio", "avg_consonant_ratio",
                "avg_unique_char_ratio"]},
    {"title": "DNS protocol context",
     "fields": ["tcp_frac", "n_responses", "avg_answer_count",
                "avg_rdata_len", "nxdomain_frac"]},
]
# sanity: every model feature is in some group
_assigned = {f for g in GROUPS for f in g["fields"]}
_missing = [f for f in FEATS if f not in _assigned]
if _missing:
    GROUPS.append({"title": "Other", "fields": _missing})


def _build_samples() -> list[dict]:
    """Reproduce the train_classifier.ipynb test split and pull 15 examples
    (8 tunnel from distinct pcaps, 7 benign from distinct pcaps)."""
    tun = pd.read_csv(ROOT / "dns_features_tunnel.csv")
    ben = pd.read_csv(ROOT / "dns_features_nontunnel.csv")
    df = pd.concat([tun, ben], ignore_index=True)
    df["y"] = (df["label"] == 1).astype(int)
    df = df.sort_values(["pcap_file", "src_ip", "window_start"]).reset_index(drop=True)
    df["rank"] = df.groupby(["pcap_file", "src_ip"]).cumcount()
    clean = df[df["rank"] % 2 == 0].drop(columns="rank").reset_index(drop=True)
    clean = clean.drop_duplicates(subset=FEATS, keep="first").reset_index(drop=True)

    pcap_label = clean.groupby("pcap_file")["y"].agg(lambda s: int(s.mode().iloc[0]))
    _, te_pcaps = train_test_split(
        pcap_label.index.values, test_size=0.2, random_state=0,
        stratify=pcap_label.values,
    )
    te = clean[clean["pcap_file"].isin(te_pcaps)]

    tun_te = te[te["y"] == 1].drop_duplicates("pcap_file").head(8)
    ben_te = te[te["y"] == 0].drop_duplicates("pcap_file").head(7)
    chosen = pd.concat([tun_te, ben_te], ignore_index=True)

    out = []
    for _, r in chosen.iterrows():
        out.append({
            "label": "TUNNEL" if int(r["y"]) == 1 else "BENIGN",
            "true_y": int(r["y"]),
            "source": str(r["source"]),
            "pcap_file": str(r["pcap_file"]),
            "features": {f: float(r[f]) for f in FEATS},
        })
    return out


SAMPLES = _build_samples()


class PredictRequest(BaseModel):
    features: Dict[str, float]


app = FastAPI(title="DNS Tunnel Classifier", version="1.0")


@app.get("/api/features")
def features_endpoint():
    return {"features": FEATS, "groups": GROUPS}


@app.get("/api/samples")
def samples_endpoint():
    return {"samples": SAMPLES}


@app.post("/api/predict")
def predict_endpoint(req: PredictRequest):
    missing = [f for f in FEATS if f not in req.features]
    if missing:
        raise HTTPException(400, f"missing features: {missing}")
    row = {f: float(req.features[f]) for f in FEATS}
    x = pd.DataFrame([row])[FEATS]
    p = float(MODEL.predict_proba(x)[0, 1])
    base = {name: float(est.predict_proba(x)[0, 1])
            for name, est in MODEL.named_estimators_.items()}
    return {
        "p_tunnel": p,
        "p_benign": 1.0 - p,
        "decision": "TUNNEL" if p >= 0.5 else "BENIGN",
        "base_probs": base,
        "threshold": 0.5,
    }


# Static SPA — must be mounted last so /api/* routes take precedence.
app.mount(
    "/",
    StaticFiles(directory=Path(__file__).parent / "static", html=True),
    name="static",
)
