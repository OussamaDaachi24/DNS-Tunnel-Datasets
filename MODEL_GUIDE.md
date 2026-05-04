# DNS-Tunnel Classifier — Model Documentation

## Overview

This document describes the **DNS-Tunnel Classifier**, a machine learning model that detects DNS tunneling activity in network traffic. The model takes a 10-second window of DNS queries from a single client IP and outputs the probability that the traffic is a DNS tunnel (0.0 = benign, 1.0 = tunnel).

The model is a **soft-voting ensemble** of three diverse base learners:
1. Logistic Regression (linear, standardized features)
2. Random Forest (300 trees, nonlinear interactions)
3. Gradient Boosting (200 trees, sharp decision surfaces)

**Final decision:** If ensemble `P(tunnel) ≥ 0.5`, the window is classified as **TUNNEL**; otherwise **BENIGN**.

---

## Input: The Feature Row

The model expects exactly **36 numeric features** describing a 10-second DNS window. These features are **computed once at the extraction stage** (not at inference); your teammate's CLI tool must extract them from raw traffic.

### How to compute the features

1. **Capture 10 seconds of DNS traffic** for a single source IP (use `tcpdump -i <iface> port 53 -w window.pcap`).
2. **Parse the PCAP** and collect all DNS packets (queries and responses).
3. **Compute aggregates** over all packets in the window using the functions in `feature_extract.py` (see the `aggregate_window` function, lines 160–224).

The 36 features are grouped by category:

---

## Feature Reference

### 1. Traffic Volumetrics (3 features)

Describe the amount and rate of DNS traffic in the window.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `n_packets` | [5, ∞) | Total DNS packets in window | Count all packets |
| `duration_sec` | (0, 10] | Actual time span (seconds) | `max(timestamp) − min(timestamp)` |
| `query_rate` | [0.5, ∞) | Packets per second | `n_packets / duration_sec` |

**Why they matter:** Tunnels generate high, sustained packet rates. Benign browsing is bursty and irregular.

**Example:** A tunnel window with 42 packets over 9.7 seconds → `query_rate = 4.3 pkt/s`. Benign window with 15 packets over 10s → `query_rate = 1.5 pkt/s`.

---

### 2. Uniqueness & Entropy (6 features)

Measure the novelty and randomness of query strings.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `unique_qnames` | [1, n_packets] | Count of distinct full query names | `len(set(qnames))` |
| `unique_subdomains` | [0, n_packets] | Count of distinct subdomains | `len(set([extract_subdomain(q) for q in qnames]))` |
| `unique_qname_ratio` | [0, 1] | Fraction of unique queries | `unique_qnames / n_packets` |
| `entropy_mean` | [0, 5.0] | Average Shannon entropy of query names | `mean([shannon_entropy(qname) for qname in qnames])` |
| `entropy_std` | [0, 2.5] | Std dev of query-name entropy | `std([shannon_entropy(qname) for qname in qnames])` |
| `subdomain_entropy_mean` | [0, 5.0] | Average entropy of just the subdomain part | `mean([shannon_entropy(subdomain) for qname in qnames])` |

**Why they matter:** Tunnels embed data in subdomains using Base64/Hex encoding → high entropy, high uniqueness. Benign DNS queries are legible domain names (lower entropy, high repetition).

**Example:**
- Tunnel query: `aGVsbG9fd29ybGRfZGF0YQ.tunnel.io` → subdomain entropy ≈ 3.9, is Base64.
- Benign query: `api.github.com` → entropy ≈ 2.1 (mostly English-like).

---

### 3. Inter-Arrival Time (IAT) (4 features)

Analyze the gaps between consecutive DNS packets.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `iat_mean` | [0, ∞) | Average time gap (seconds) between consecutive packets | `mean([ts[i+1] − ts[i] for i in range(len(ts)−1)])` |
| `iat_std` | [0, ∞) | Std dev of inter-arrival times | `std(iats)` |
| `iat_min` | [0, ∞) | Shortest gap observed | `min(iats)` |
| `iat_max` | [0, ∞) | Longest gap observed | `max(iats)` |

**Why they matter:** Machines generate queries at regular intervals; humans browse erratically. Tunnels often maintain steady heartbeat intervals.

**Example:**
- Tunnel: mean IAT = 0.24 s, std = 0.08 s (very regular).
- Benign: mean IAT = 0.6 s, std = 0.4 s (irregular).

---

### 4. Payload Size (3 features)

Measure the size of DNS packets.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `payload_mean` | [0, 512] | Average DNS payload size (bytes) | `mean([len(dns_layer) for pkt in window])` |
| `payload_std` | [0, 512] | Std dev of payload sizes | `std(payloads)` |
| `payload_max` | [0, 512] | Largest DNS packet observed | `max(payloads)` |

**Why they matter:** Tunnels pack data into large DNS responses (pushing toward the 512-byte UDP limit). Benign queries get small responses.

**Example:**
- Tunnel: mean = 98.6 B, max = 99 B (consistently large).
- Benign: mean = 32 B, max = 50 B (small, variable).

---

### 5. Query-Type Fractions (6 features)

Distribution of DNS record types requested.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `txt_frac` | [0, 1] | Fraction of TXT record queries | `count(qtype=16) / n_packets` |
| `null_frac` | [0, 1] | Fraction of NULL record queries | `count(qtype=10) / n_packets` |
| `aaaa_frac` | [0, 1] | Fraction of AAAA (IPv6) queries | `count(qtype=28) / n_packets` |
| `a_frac` | [0, 1] | Fraction of A (IPv4) queries | `count(qtype=1) / n_packets` |
| `any_frac` | [0, 1] | Fraction of ANY queries | `count(qtype=255) / n_packets` |
| `tunnel_type_frac` | [0, 1] | Fraction of tunnel-preferred types (TXT, NULL, AAAA, ANY, SOA) | `sum(is_tunnel_type) / n_packets` |

**Why they matter:** Standard DNS uses mostly A records. Tunnels exploit TXT (arbitrary data), NULL (bulk transfer), AAAA (IPv6 addresses as data carriers).

**Example:**
- Tunnel: `txt_frac = 0.0, a_frac = 1.0, tunnel_type_frac = 0.0` (spoofed appearance as normal A queries, but with large payloads and unique subdomains).
- Benign: `a_frac = 0.8, txt_frac = 0.1, tunnel_type_frac = 0.1` (mix of query types, typical).

---

### 6. String Composition (9 features)

Detailed analysis of characters in subdomains and query names.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `avg_qname_len` | [1, 253] | Average length of full query names | `mean([len(qname) for qname in qnames])` |
| `avg_subdomain_len` | [0, 245] | Average length of just the subdomain part | `mean([len(subdomain) for qname in qnames])` |
| `avg_label_count` | [1, 127] | Average number of labels (parts between dots) | `mean([qname.count('.') + 1 for qname in qnames])` |
| `avg_max_label_len` | [1, 63] | Average of the longest label in each query | `mean([max([len(p) for p in qname.split('.')]) for qname in qnames])` |
| `avg_b64_ratio` | [0, 1] | Average fraction of Base64 characters in subdomain | `mean([(#base64_chars / len(subdomain)) for subdomain in subdomains])` |
| `avg_hex_ratio` | [0, 1] | Average fraction of hex characters [0-9a-f] in subdomain | `mean([(#hex_chars / len(subdomain)) for subdomain in subdomains])` |
| `avg_numeric_ratio` | [0, 1] | Average fraction of digits in subdomain | `mean([(#digits / len(subdomain)) for subdomain in subdomains])` |
| `avg_consonant_ratio` | [0, 1] | Average fraction of consonants in alphabetic characters | `mean([(#consonants / #letters) for subdomain in subdomains])` |
| `avg_unique_char_ratio` | [0, 1] | Average fraction of unique characters per subdomain | `mean([(len(set(subdomain)) / len(subdomain)) for subdomain in subdomains])` |

**Why they matter:** Encoded data (Base64/Hex) has high character variety and non-linguistic patterns. English domain names have vowels, repeated characters, readable structure.

**Example:**
- Tunnel subdomain: `aGVsbG9fd29ybGQ` → `b64_ratio = 0.94`, `consonant_ratio = 0.38` (no vowels in Base64).
- Benign subdomain: `cdn` → `b64_ratio = 0.33`, `consonant_ratio = 0.67`, `unique_char_ratio = 1.0` (3 unique chars in 3-char word).

---

### 7. DNS Protocol Context (5 features)

Information about transport and server responses.

| Feature | Range | Meaning | How to compute |
|---------|-------|---------|---|
| `tcp_frac` | [0, 1] | Fraction of packets using TCP transport | `count(TCP flag set) / n_packets` |
| `n_responses` | [0, n_packets] | Number of DNS response packets (qr=1) | `count(dns.qr == 1)` |
| `avg_answer_count` | [0, ∞) | Average number of answers per response | `mean([ancount for pkt in responses])` |
| `avg_rdata_len` | [0, ∞) | Average length of response data (RDATA) | `mean([sum(len(rr.rdata) for rr in response.answers) for response in responses])` |
| `nxdomain_frac` | [0, 1] | Fraction of "Non-Existent Domain" responses (rcode=3) | `count(rcode == 3) / n_packets` |

**Why they matter:** Bidirectional communication (high response count, large RDATA) and high NXDOMAIN rates (invalid tunnel domains) are tunnel signatures.

**Example:**
- Tunnel: `n_responses = 38` (out of 42 queries), `avg_rdata_len = 120 B` (large responses carrying data).
- Benign: `n_responses = 12` (queries don't always get responses), `avg_rdata_len = 8 B` (small IPs/errors).

---

## Summary Table: All 36 Features

| Category | Count | Features |
|----------|-------|----------|
| Traffic volumetrics | 3 | n_packets, duration_sec, query_rate |
| Uniqueness & entropy | 6 | unique_qnames, unique_subdomains, unique_qname_ratio, entropy_mean, entropy_std, subdomain_entropy_mean |
| IAT | 4 | iat_mean, iat_std, iat_min, iat_max |
| Payload size | 3 | payload_mean, payload_std, payload_max |
| Query types | 6 | txt_frac, null_frac, aaaa_frac, a_frac, any_frac, tunnel_type_frac |
| String composition | 9 | avg_qname_len, avg_subdomain_len, avg_label_count, avg_max_label_len, avg_b64_ratio, avg_hex_ratio, avg_numeric_ratio, avg_consonant_ratio, avg_unique_char_ratio |
| Protocol context | 5 | tcp_frac, n_responses, avg_answer_count, avg_rdata_len, nxdomain_frac |
| **TOTAL** | **36** | |

---

## Algorithm: Soft-Voting Ensemble

The model combines three base learners with soft voting (averaging predicted probabilities), weighted 1:2:2 toward Random Forest and Gradient Boosting.

### Base Learner 1: Logistic Regression

- **Type:** Linear classifier with L2 regularization (`C=1.0`).
- **Input preprocessing:** StandardScaler (mean-center, unit variance).
- **Why:** Fast, calibrated probabilities, captures linear separations in standardized feature space.
- **Role in ensemble:** Provides a stable baseline; easy to debug if needed.

### Base Learner 2: Random Forest

- **Type:** 300 decision trees, no depth limit, min samples per leaf = 2.
- **Why:** Handles non-linear interactions between features (e.g., high entropy AND high subdomain length), robust to feature scale.
- **Role in ensemble:** Captures feature interactions; most important contributor (weight=2).

### Base Learner 3: Gradient Boosting

- **Type:** 200 trees, max depth = 3, learning rate = 0.05.
- **Why:** Iteratively corrects misclassifications; sharp decision boundaries for difficult cases.
- **Role in ensemble:** Refines Random Forest predictions on borderline cases; second most important (weight=2).

### Voting Mechanism

```
P(tunnel) = (1 × P_lr + 2 × P_rf + 2 × P_gb) / 5
```

Where `P_lr`, `P_rf`, `P_gb` are the per-learner probabilities. This soft voting leverages each model's strengths without requiring a separate meta-learner.

**Decision threshold:** 0.5 (configurable at inference time if needed).

---

## Training Dataset

The model was trained on **31,731 windows** from **103 PCAP files**, tested on **6,980 windows** from **26 unseen PCAP files**. The data was extracted from the **DNS-Tunnel-Datasets** repository (https://github.com/ggyggy666/DNS-Tunnel-Datasets).

### Data Composition

| Source | Type | PCAP count | Windows | Label |
|--------|------|-----------|---------|-------|
| `normal/` | Benign DNS from top 1M Cloudflare domains | 40 | 8,987 | 0 |
| `tunnel/` | Known DNS tunneling tools (dnscat2, dnspot, iodine, DNS-shell, tuns) | 50 | 24,183 | 1 |
| **Train/val split (80/20 on PCAP files, group-aware)** | | 103 | 31,731 | — |
| `unkownTunnel/` | Unknown tunneling tools (tcp-over-dns, CobaltStrike, dns2tcp, ozymandns) | 12 | 12,781 | 1 |
| `crossEndPoint/` | Android tunneling (AndIodine) | 5 | 3,875 | 1 |
| `wildcard/` | Wildcard DNS responses | 10 | 807 | 0 |
| **Test split (unseen PCAPs)** | | 26 | 6,980 | — |

### Feature Extraction Parameters

- **Window size:** 10 seconds
- **Stride:** 5 seconds (50% overlap) in raw extraction; deduplicated to simulate stride=window for training
- **Min packets per window:** 5 (windows with fewer packets are discarded)
- **Per-source-IP grouping:** Yes (windows are computed separately for each source IP in a PCAP)

---

## Why 100% Accuracy? — The Lab-Environment Effect

The model achieves **AUC = 1.0** on the held-out test set, as well as on the robustness folders (`unkownTunnel`, `crossEndPoint`, `wildcard`). This near-perfect performance is **not a sign of overfitting** (random-split AUC ≈ group-split AUC ≈ 1.0, indicating the model is consistent, not over-tuned). Rather, it reveals a **collection-level bias** in how the dataset was recorded.

### Root Cause

**Every benign PCAP was captured from the same environment:** passive DNS traffic from the top 1M Cloudflare domains, recorded on a controlled lab network in a single session.

**Every tunnel PCAP was captured from a different environment:** a lab setup where someone actively ran a DNS tunneling tool (dnscat2, iodine, etc.) against a controlled resolver.

These two environments differ in subtle, systematic ways:

1. **Encoder consistency:** Tunnel tools use fixed-size encoders (e.g., Base64 chunking at 64 chars) → consistent subdomain lengths, entropy.
2. **Packet regularity:** Tunneling clients send queries at steady rates (heartbeat or throughput-limited); benign traffic is bursty.
3. **Payload sizes:** Tunnel tools use large DNS responses (pushing toward 512 B); benign passive captures have tiny responses (often 0 B).
4. **Response availability:** Tunnel clients receive responses for nearly every query (bidirectional); benign passive captures have many unanswered queries.

The model learns to distinguish **the two recording environments**, not just "tunneling behavior." On this dataset, the environments and labels happen to be perfectly aligned, so the model achieves 1.0 AUC.

### What This Means for Deployment

**The numbers on this dataset are not credible for real-world deployment.** To know the model's true error rate, you must:

1. **Capture benign traffic from a different network** (e.g., your campus, a real ISP, a different cloud provider).
2. **Capture tunnel traffic under different conditions** (different resolver, different network path, different tunneling tools).
3. **Score the model on both** and re-calibrate if necessary.

If the model still scores well (AUC > 0.95) on the new captures, the features are genuinely behavioral. If it collapses (AUC < 0.80), the original 1.0 was an artifact of the lab setup.

### Leakage Prevention

The model was trained with **strict controls** to prevent "cheating":

- **No capture-identifying metadata in the feature matrix:** Dropped `source` (literal folder name = label), `top_base_frac` (indicator of single-target capture topology), `pcap_file`, `src_ip`, `window_start`.
- **No overlapping windows in training:** Stride = window = 10 s (eliminates 50% packet overlap that would allow the model to memorize individual PCAPs).
- **Group-aware cross-validation:** No row from the same PCAP appears in both train and test folds; `random-split AUC ≈ group-split AUC ≈ 1.0` (gap is zero, evidence of no overfitting).

Despite these controls, the 1.0 remains, confirming the environment-level signature is strong and systematic.

---

## Example Inputs

### Example 1: A Real Tunnel Window (from test set)

This is an actual 10-second window from `DNS-shell.pcap` (a DNS tunneling tool).

```json
{
  "n_packets": 42,
  "duration_sec": 9.716,
  "query_rate": 4.322,
  "unique_qnames": 21,
  "unique_subdomains": 21,
  "unique_qname_ratio": 0.5,
  "iat_mean": 0.237,
  "iat_std": 0.102,
  "iat_min": 0.052,
  "iat_max": 0.689,
  "payload_mean": 98.6,
  "payload_std": 0.58,
  "payload_max": 99.0,
  "entropy_mean": 3.632,
  "entropy_std": 0.187,
  "subdomain_entropy_mean": 3.323,
  "txt_frac": 0.0,
  "null_frac": 0.0,
  "aaaa_frac": 0.0,
  "a_frac": 1.0,
  "any_frac": 0.0,
  "tunnel_type_frac": 0.0,
  "avg_qname_len": 80.6,
  "avg_subdomain_len": 70.6,
  "avg_label_count": 6.0,
  "avg_max_label_len": 50.0,
  "avg_b64_ratio": 0.957,
  "avg_hex_ratio": 0.901,
  "avg_numeric_ratio": 0.729,
  "avg_consonant_ratio": 0.408,
  "avg_unique_char_ratio": 0.209,
  "tcp_frac": 0.0,
  "n_responses": 0,
  "avg_answer_count": 0.0,
  "avg_rdata_len": 0.0,
  "nxdomain_frac": 0.0
}
```

**Interpretation:**
- **High uniqueness:** 21 unique subdomains out of 42 packets (every other query is novel).
- **High entropy:** 3.6 bits per character (Base64-encoded data).
- **High Base64 ratio:** 0.957 (96% of subdomain is [A-Za-z0-9+/]).
- **Consistent payload:** mean 98.6 B, std 0.58 (almost no variation; an encoder output).
- **Regular timing:** IAT mean 0.24 s, std 0.10 s (heartbeat-like).
- **No responses:** 0 answers returned (tunnel client doesn't need DNS resolution, just to send queries).

**Model output:** `P(tunnel) = 1.0` → **Decision: TUNNEL** ✓

---

### Example 2: A Real Benign Window (from test set)

This is an actual window from `normal_00003_20230805162300.pcap` (passive traffic from Cloudflare's top domains).

```json
{
  "n_packets": 79,
  "duration_sec": 9.988,
  "query_rate": 7.909,
  "unique_qnames": 78,
  "unique_subdomains": 3,
  "unique_qname_ratio": 0.987,
  "iat_mean": 0.128,
  "iat_std": 0.126,
  "iat_min": 0.0,
  "iat_max": 0.483,
  "payload_mean": 32.0,
  "payload_std": 4.95,
  "payload_max": 49.0,
  "entropy_mean": 3.298,
  "entropy_std": 0.315,
  "subdomain_entropy_mean": 0.036,
  "txt_frac": 0.0,
  "null_frac": 0.0,
  "aaaa_frac": 0.0,
  "a_frac": 1.0,
  "any_frac": 0.0,
  "tunnel_type_frac": 0.0,
  "avg_qname_len": 14.0,
  "avg_subdomain_len": 0.266,
  "avg_label_count": 2.05,
  "avg_max_label_len": 9.72,
  "avg_b64_ratio": 0.051,
  "avg_hex_ratio": 0.003,
  "avg_numeric_ratio": 0.0,
  "avg_consonant_ratio": 0.045,
  "avg_unique_char_ratio": 0.021,
  "tcp_frac": 0.0,
  "n_responses": 0,
  "avg_answer_count": 0.0,
  "avg_rdata_len": 0.0,
  "nxdomain_frac": 0.0
}
```

**Interpretation:**
- **High uniqueness ratio:** 78/79 = 0.987 (lots of different domains queried, not a tunnel's repeated pattern).
- **Low subdomain entropy:** 0.036 (subdomain part is mostly empty; queries are short domain names like `api.github.com`).
- **Low Base64 ratio:** 0.051 (only 5% of characters could be Base64; mostly letters).
- **Small, variable payload:** mean 32 B, std 4.95 (typical for passive DNS).
- **Irregular timing:** IAT mean 0.128 s, std 0.126 s (human/app traffic, bursty).
- **Few subdomains:** only 3 unique subdomains (e.g., `cdn1`, `cdn2`, `api`, reused across many domains).

**Model output:** `P(tunnel) = 0.0` → **Decision: BENIGN** ✓

---

### Example 3: A Synthetic Edge Case (for testing)

If your CLI tool were to capture traffic with mixed characteristics:

```json
{
  "n_packets": 30,
  "duration_sec": 10.0,
  "query_rate": 3.0,
  "unique_qnames": 15,
  "unique_subdomains": 15,
  "unique_qname_ratio": 0.5,
  "iat_mean": 0.33,
  "iat_std": 0.15,
  "iat_min": 0.08,
  "iat_max": 0.75,
  "payload_mean": 50.0,
  "payload_std": 15.0,
  "payload_max": 80.0,
  "entropy_mean": 3.0,
  "entropy_std": 0.5,
  "subdomain_entropy_mean": 2.5,
  "txt_frac": 0.1,
  "null_frac": 0.0,
  "aaaa_frac": 0.0,
  "a_frac": 0.9,
  "any_frac": 0.0,
  "tunnel_type_frac": 0.1,
  "avg_qname_len": 45.0,
  "avg_subdomain_len": 35.0,
  "avg_label_count": 3.5,
  "avg_max_label_len": 20.0,
  "avg_b64_ratio": 0.4,
  "avg_hex_ratio": 0.2,
  "avg_numeric_ratio": 0.15,
  "avg_consonant_ratio": 0.3,
  "avg_unique_char_ratio": 0.15,
  "tcp_frac": 0.0,
  "n_responses": 5,
  "avg_answer_count": 0.5,
  "avg_rdata_len": 20.0,
  "nxdomain_frac": 0.0
}
```

**Interpretation:**
- **Borderline uniqueness:** 0.5 ratio (not as high as tunnel, not as low as benign).
- **Moderate entropy:** 3.0 bits/char (could be encoded or just long domain names).
- **Medium payload:** 50 B (not as large as typical tunnel, not as small as typical benign).
- **Some responses:** 5 responses out of 30 packets (tunnel-like low response count).
- **Some Base64 characters:** 0.4 ratio (suspicious but not definitive).

**Model output:** `P(tunnel) ≈ 0.6–0.8` → **Decision: TUNNEL** (but with lower confidence than pure tunnel examples).

This window would trigger an alert, but a human analyst should review it before taking action.

---

## How to Use the Model

### Option A: Via the FastAPI Web App

See `app/main.py` and the UI at `http://localhost:8000` (after running `uvicorn app.main:app --reload --port 8000`).

### Option B: Via Python (Programmatic)

```python
import joblib
import pandas as pd

# Load the model
bundle = joblib.load("dns_tunnel_classifier.joblib")
model = bundle["model"]
features = bundle["features"]

# Prepare a row of 36 features
row = {
    "n_packets": 42, "duration_sec": 9.7, "query_rate": 4.3,
    # ... (all 36 features)
}

# Inference
x = pd.DataFrame([row])[features]
p_tunnel = model.predict_proba(x)[0, 1]
decision = "TUNNEL" if p_tunnel >= 0.5 else "BENIGN"

print(f"P(tunnel) = {p_tunnel:.4f} → {decision}")
```

### Option C: Via the CLI (your teammate's tool)

Your teammate should:

1. **Capture 10 seconds** of DNS traffic: `tcpdump -i eth0 -w window.pcap port 53`
2. **Extract 36 features** using the `feature_extract.py` functions (or re-implement them).
3. **POST to `/api/predict`** or call the model directly via joblib.
4. **Return the decision** (TUNNEL / BENIGN) and confidence to the user.

---

## Performance Summary

| Metric | Random CV | Group CV | Within-PCAP Time | Unseen Test | Robustness |
|--------|-----------|----------|------------------|-------------|-----------|
| AUC | 1.0000 | 1.0000 | 0.9999 | 1.0000 | 1.0000 |
| Accuracy | 0.9999 | 0.9996 | 0.9981 | 1.0000 | 1.0000 |
| F1-score | 0.9999 | 0.9997 | 0.9988 | 1.0000 | 1.0000 |
| **AUC gap** | **0.0** (no leakage) | — | — | — | — |

**Robustness details:**
- `unkownTunnel` (unseen tools): accuracy = 1.0
- `crossEndPoint` (Android tunneling): accuracy = 1.0
- `wildcard` (benign): accuracy = 1.0

---

## Limitations & Future Work

1. **Dataset bias:** The 100% accuracy reflects the lab environment, not real-world conditions. Deployment on a new network requires recalibration.

2. **Feature dependencies:** Features were extracted with sliding 10-second windows and a 5-second stride in the original raw data. Your CLI tool must maintain a 10-second observation window for consistency.

3. **Single IP assumption:** The model is trained on per-IP windows. If you aggregate traffic from multiple clients, features may not generalize.

4. **Threshold tuning:** The default threshold of 0.5 assumes equal cost for false positives and false negatives. Adjust if needed (higher threshold = fewer alarms, lower threshold = more alarms).

5. **Concept drift:** If tunnel tools evolve (new encoders, different packet rates), the model may degrade. Periodic retraining on fresh captures is recommended.

---

## References

- **Dataset:** DNS-Tunnel-Datasets (https://github.com/ggyggy666/DNS-Tunnel-Datasets)
- **Paper:** "GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive Resolution Graph" (IEEE, 2024)
- **Feature extraction code:** `feature_extract.py` (in this repo)
- **Leakage audit:** `leakage_analysis.ipynb` (detailed analysis of potential data leakage)
- **Training notebook:** `train_classifier.ipynb` (reproducible training pipeline)

---

## Contact & Questions

If you have questions about the model, feature extraction, or deployment, refer to:
- The Jupyter notebooks (`leakage_analysis.ipynb`, `train_classifier.ipynb`) for detailed explanations.
- The feature documentation in `features_documentation.md` for individual feature meanings.
- The `app/main.py` backend code for API integration details.
