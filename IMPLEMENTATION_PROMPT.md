# DNS Tunnel Classifier CLI Tool - Implementation Specification

## Overview

You are tasked with implementing a **command-line tool** that detects DNS tunneling activity in real-time network traffic. The tool captures live DNS packets from a network interface (or reads a saved pcap file), extracts 36 behavioral features, feeds them to a pre-trained ensemble classifier (provided as `dns_tunnel_classifier.joblib`), and outputs whether the traffic is a tunnel or benign.

**Key point:** You are NOT training the model. The model is already trained and saved as a joblib pickle. Your job is to build the interface and feature extraction pipeline around it.

---

## 1. Input Specification

The tool accepts traffic in **two modes**:

### Mode A: Live Network Interface (Primary)

```bash
python dns_tunnel_cli.py --interface eth0 --duration 10 --output json
```

- Sniffs live DNS packets from the specified network interface
- Captures for `--duration` seconds (default: 10)
- Filters for DNS traffic (UDP port 53, both inbound and outbound)

### Mode B: Pcap File (Secondary)

```bash
python dns_tunnel_cli.py --pcap /path/to/capture.pcap --output table
```

- Reads a saved pcap file instead of live traffic
- Useful for testing, validation, forensics

### Optional Arguments

- `--src-ip <IP>`: Filter results to a specific source IP (optional; if not provided, analyze all sources)
- `--output json|csv|table`: Output format (default: `table`)
- `--output-file <path>`: Write results to a file instead of stdout
- `--threshold 0.5`: Classification threshold for TUNNEL vs BENIGN (default: 0.5)

---

## 2. Processing Pipeline

### Step 1: Traffic Capture

**Input:** Live interface OR pcap file  
**Output:** List of DNS packets (each packet contains: timestamp, src_ip, dst_ip, src_port, dst_port, query_name, response_code, response_len, etc.)

**Tools:** Use `scapy` for both live sniffing and pcap reading:

```python
from scapy.all import sniff, IP, UDP, DNS, rdpcap

# Live capture
packets = sniff(iface="eth0", filter="udp port 53", timeout=10)

# Or read pcap
packets = rdpcap("capture.pcap")
```

**Important:** Extract and preserve these fields from each packet:

- `timestamp` (seconds since packet capture start, or absolute time if available)
- `src_ip` (source IP of the DNS client)
- `dst_ip` (destination IP, typically DNS server)
- `query_name` (the domain being queried, as string)
- `query_type` (A, AAAA, MX, NS, CNAME, TXT, etc.)
- `response_code` (NOERROR=0, NXDOMAIN=3, SERVFAIL=2, etc.)
- `response_len` (byte length of DNS response payload)
- `response_flags` (AA, TC, RD, RA bits)

---

### Step 2: Window Aggregation

**Input:** Flat list of DNS packets  
**Output:** List of (src_ip, features_dict) tuples

**Logic:**

1. Group packets by `src_ip`
2. For each source IP, chunk packets into **10-second windows** (non-overlapping)
   - Window 1: packets with timestamp 0–10s
   - Window 2: packets with timestamp 10–20s
   - etc.
3. For each (src_ip, window) pair, compute 36 features (see Section 3 below)

**Example:**

- Input: 2,340 DNS packets from 3 sources over 45 seconds
- Output:
  ```
  [
    (src_ip="192.168.1.5", window=0, features={...}),
    (src_ip="192.168.1.5", window=1, features={...}),
    (src_ip="192.168.1.100", window=0, features={...}),
    (src_ip="192.168.1.100", window=1, features={...}),
    (src_ip="10.0.0.15", window=0, features={...}),
    ...
  ]
  ```

---

## 3. Feature Extraction (36 Features)

For each (src_ip, window) pair, compute these 36 features from the aggregated packets:

### Group 1: Traffic Volumetrics (5 features)

1. **num_queries** (int)
   - Count of DNS query packets in this window
   - Range: [0, ~1000]

2. **unique_domains** (int)
   - Count of unique domain names queried
   - Range: [0, ~500]

3. **num_responses** (int)
   - Count of DNS response packets received
   - Range: [0, ~1000]

4. **response_ratio** (float)
   - `num_responses / num_queries` (handle division by zero)
   - Range: [0, 1]

5. **average_response_time** (float)
   - Mean time (in milliseconds) between query and matching response
   - Estimate: match query and response by time proximity
   - Range: [0, ~5000]ms

### Group 2: Uniqueness & Entropy (5 features)

6. **unique_qnames_ratio** (float)
   - `unique_domains / num_queries`
   - Range: [0, 1]

7. **entropy_qnames** (float)
   - Shannon entropy of the distribution of query names (normalized by log2(num_unique_domains))
   - High entropy: all queries are different (high uniqueness)
   - Low entropy: queries repeat (low uniqueness)
   - Range: [0, 1]

8. **entropy_qtype** (float)
   - Shannon entropy of query types (A, AAAA, MX, etc.)
   - Range: [0, log2(13)] ≈ [0, 3.7]

9. **entropy_response_code** (float)
   - Shannon entropy of response codes (NOERROR, NXDOMAIN, SERVFAIL, etc.)
   - Range: [0, log2(10)] ≈ [0, 3.3]

10. **base_entropy** (float)
    - Shannon entropy of the distribution of base domain (e.g., "example.com" from "api.example.com")
    - Captures how many distinct base domains are queried
    - Range: [0, ~5]

### Group 3: Inter-Arrival Time (IAT) (5 features)

11. **mean_iat** (float)
    - Mean time (in ms) between consecutive query packets
    - Range: [0, ~10000]ms

12. **std_iat** (float)
    - Standard deviation of IAT
    - Range: [0, ~20000]ms

13. **min_iat** (float)
    - Minimum time between any two consecutive queries
    - Range: [0, ~1000]ms

14. **max_iat** (float)
    - Maximum time between any two consecutive queries
    - Range: [0, ~10000]ms

15. **skew_iat** (float)
    - Skewness of the IAT distribution (scipy.stats.skew)
    - Range: [-5, 5] (unbounded but typically in this range)

### Group 4: Payload Size (5 features)

16. **mean_query_len** (float)
    - Mean length (in bytes) of query packets
    - Range: [20, ~300]

17. **std_query_len** (float)
    - Standard deviation of query packet lengths
    - Range: [0, ~200]

18. **mean_response_len** (float)
    - Mean length of response packets
    - Range: [30, ~1500]

19. **std_response_len** (float)
    - Standard deviation of response packet lengths
    - Range: [0, ~1000]

20. **max_response_len** (float)
    - Maximum response packet size
    - Range: [30, ~65000]

### Group 5: Query Types (5 features)

21. **frac_a_queries** (float)
    - Fraction of queries with type A (IPv4 addresses)
    - Range: [0, 1]

22. **frac_aaaa_queries** (float)
    - Fraction of queries with type AAAA (IPv6 addresses)
    - Range: [0, 1]

23. **frac_mx_queries** (float)
    - Fraction of queries with type MX (mail exchange)
    - Range: [0, 1]

24. **frac_txt_queries** (float)
    - Fraction of queries with type TXT
    - Range: [0, 1]

25. **frac_cname_queries** (float)
    - Fraction of queries with type CNAME
    - Range: [0, 1]

### Group 6: String Composition (5 features)

26. **mean_qname_len** (float)
    - Mean length (in characters) of query domain names
    - Range: [1, ~255]

27. **std_qname_len** (float)
    - Standard deviation of query name lengths
    - Range: [0, ~100]

28. **mean_label_len** (float)
    - Mean length of individual labels (parts between dots)
    - Range: [1, ~63]

29. **frac_numeric_labels** (float)
    - Fraction of labels that are purely numeric
    - Range: [0, 1]

30. **frac_vowel_ratio** (float)
    - Mean fraction of vowels (a,e,i,o,u) across all labels
    - Range: [0, 1]

### Group 7: Protocol Context (6 features)

31. **frac_noerror** (float)
    - Fraction of responses with NOERROR (code 0)
    - Range: [0, 1]

32. **frac_nxdomain** (float)
    - Fraction of responses with NXDOMAIN (code 3)
    - Range: [0, 1]

33. **frac_servfail** (float)
    - Fraction of responses with SERVFAIL (code 2)
    - Range: [0, 1]

34. **frac_aa_set** (float)
    - Fraction of responses with AA (Authoritative Answer) flag set
    - Range: [0, 1]

35. **frac_tc_set** (float)
    - Fraction of responses with TC (Truncation) flag set
    - Range: [0, 1]

36. **frac_ra_set** (float)
    - Fraction of responses with RA (Recursion Available) flag set
    - Range: [0, 1]

**Helper Functions:**

```python
from scipy.stats import entropy, skew
import numpy as np

def shannon_entropy(values):
    """Compute normalized Shannon entropy of a discrete distribution."""
    if len(values) == 0:
        return 0
    counts = np.bincount(values)
    probs = counts / len(values)
    return entropy(probs, base=2) / np.log2(max(len(counts), 2))

def compute_features(packets_in_window):
    """
    Input: list of packet dicts with keys:
      - timestamp, src_ip, query_name, query_type, response_code, response_len, etc.
    Output: dict with 36 feature keys
    """
    # Implement all 36 features as above
    return features_dict
```

---

## 4. Model Loading & Inference

### Load the Model

```python
import joblib

# Load the pre-trained ensemble classifier
model = joblib.load("dns_tunnel_classifier.joblib")

# The joblib file contains:
# - model: a sklearn VotingClassifier with 3 base learners (LogReg, RandomForest, GradientBoosting)
# - feature_names: list of 36 feature names (in order)
```

### Make a Prediction

```python
# For each (src_ip, window), you have a features_dict
# Convert to a list/array in the correct feature order

feature_order = [
    "num_queries", "unique_domains", "num_responses", "response_ratio",
    "average_response_time", "unique_qnames_ratio", "entropy_qnames",
    # ... (all 36 names)
]

feature_vector = [features_dict[name] for name in feature_order]

# Predict
prob_benign, prob_tunnel = model.predict_proba([feature_vector])[0]

decision = "TUNNEL" if prob_tunnel > 0.5 else "BENIGN"

# Also extract per-base-learner probabilities (for transparency)
base_probs = {
    "lr": model.estimators_[0].predict_proba([feature_vector])[0][1],  # P(tunnel)
    "rf": model.estimators_[1].predict_proba([feature_vector])[0][1],
    "gb": model.estimators_[2].predict_proba([feature_vector])[0][1],
}
```

---

## 5. Output Formats

### Format 1: Table (Human-Readable, Default)

```
Source IP       | Decision | P(tunnel) | LR    | RF   | GB
────────────────┼──────────┼───────────┼───────┼──────┼──────
192.168.1.5     | TUNNEL   | 0.9847    | 0.92  | 1.00 | 0.95
192.168.1.100   | BENIGN   | 0.0512    | 0.01  | 0.08 | 0.08
10.0.0.15       | BENIGN   | 0.0089    | 0.00  | 0.01 | 0.02
```

### Format 2: JSON (For Automation & SIEM Integration)

```json
{
  "timestamp": "2026-05-04T14:32:00Z",
  "interface": "eth0",
  "mode": "live",
  "duration_sec": 10,
  "windows": [
    {
      "src_ip": "192.168.1.5",
      "window_id": 0,
      "num_packets": 512,
      "decision": "TUNNEL",
      "p_tunnel": 0.9847,
      "p_benign": 0.0153,
      "base_probs": {
        "lr": 0.92,
        "rf": 1.0,
        "gb": 0.95
      }
    },
    {
      "src_ip": "192.168.1.100",
      "window_id": 0,
      "num_packets": 88,
      "decision": "BENIGN",
      "p_tunnel": 0.0512,
      "p_benign": 0.9488,
      "base_probs": {
        "lr": 0.01,
        "rf": 0.08,
        "gb": 0.08
      }
    }
  ]
}
```

### Format 3: CSV

```
src_ip,decision,p_tunnel,p_benign,lr_prob,rf_prob,gb_prob,num_packets,window_id
192.168.1.5,TUNNEL,0.9847,0.0153,0.92,1.00,0.95,512,0
192.168.1.100,BENIGN,0.0512,0.9488,0.01,0.08,0.08,88,0
10.0.0.15,BENIGN,0.0089,0.9911,0.00,0.01,0.02,301,0
```

---

## 6. Example Walkthrough

### Scenario: Capture 10 seconds from eth0, output as table

```bash
python dns_tunnel_cli.py --interface eth0 --duration 10 --output table
```

**Step-by-step execution:**

1. **Start sniffer** on eth0, listen for UDP port 53 packets
   - Example packets captured:
     ```
     08:15:32.145 | 192.168.1.5:54321 > 8.8.8.8:53 | Query: "google.com" (A)
     08:15:32.267 | 8.8.8.8:53 > 192.168.1.5:54321 | Response: NOERROR, len=45
     08:15:32.512 | 192.168.1.5:54332 > 8.8.8.8:53 | Query: "example.com" (A)
     08:15:32.634 | 8.8.8.8:53 > 192.168.1.5:54332 | Response: NOERROR, len=52
     ... (2,340 more packets)
     ```

2. **Group by source IP and window:**
   - **192.168.1.5, window 0** (0–10s): 512 packets
   - **192.168.1.5, window 1** (10–20s): 498 packets
   - **192.168.1.100, window 0**: 88 packets
   - **192.168.1.100, window 1**: 92 packets
   - **10.0.0.15, window 0**: 301 packets
   - ... (more windows if duration > 10s)

3. **Extract features for 192.168.1.5, window 0:**

   ```python
   features = {
       "num_queries": 512,
       "unique_domains": 47,
       "num_responses": 512,
       "response_ratio": 1.0,
       "average_response_time": 25.3,
       "unique_qnames_ratio": 0.0918,
       "entropy_qnames": 0.89,
       "entropy_qtype": 0.12,  # mostly A queries
       "entropy_response_code": 0.0,  # all NOERROR
       "base_entropy": 2.1,
       "mean_iat": 18.2,
       "std_iat": 12.4,
       "min_iat": 0.1,
       "max_iat": 245.6,
       "skew_iat": 2.3,
       "mean_query_len": 35.8,
       "std_query_len": 8.2,
       "mean_response_len": 89.4,
       "std_response_len": 23.1,
       "max_response_len": 512,
       "frac_a_queries": 0.88,
       "frac_aaaa_queries": 0.08,
       "frac_mx_queries": 0.02,
       "frac_txt_queries": 0.01,
       "frac_cname_queries": 0.01,
       "mean_qname_len": 14.2,
       "std_qname_len": 5.3,
       "mean_label_len": 5.8,
       "frac_numeric_labels": 0.05,
       "frac_vowel_ratio": 0.35,
       "frac_noerror": 1.0,
       "frac_nxdomain": 0.0,
       "frac_servfail": 0.0,
       "frac_aa_set": 0.15,
       "frac_tc_set": 0.0,
       "frac_ra_set": 0.95,
   }
   ```

4. **Load model and predict:**

   ```python
   model = joblib.load("dns_tunnel_classifier.joblib")

   # Convert to feature vector
   feature_vector = [features[name] for name in MODEL_FEATURE_ORDER]

   # Predict
   prob_benign, prob_tunnel = model.predict_proba([feature_vector])[0]
   # prob_benign = 0.0153, prob_tunnel = 0.9847

   decision = "TUNNEL" if prob_tunnel > 0.5 else "BENIGN"
   # decision = "TUNNEL"

   # Base learner probs
   base_probs = {"lr": 0.92, "rf": 1.00, "gb": 0.95}
   ```

5. **Repeat for all other (src_ip, window) pairs**

6. **Format and print output:**
   ```
   Source IP       | Decision | P(tunnel) | LR    | RF   | GB
   ────────────────┼──────────┼───────────┼───────┼──────┼──────
   192.168.1.5     | TUNNEL   | 0.9847    | 0.92  | 1.00 | 0.95
   192.168.1.100   | BENIGN   | 0.0512    | 0.01  | 0.08 | 0.08
   10.0.0.15       | BENIGN   | 0.0089    | 0.00  | 0.01 | 0.02
   ```

---

## 7. File Structure

```
dns-tunnel-cli/
├── dns_tunnel_cli.py              # Main entry point (argparse, orchestration)
├── dns_tunnel_classifier.joblib   # Pre-trained model (provided)
├── traffic_capture.py              # Pcap reading + live sniffing
├── feature_extraction.py           # 36-feature computation
├── inference.py                    # Model loading + prediction
├── output_formatters.py            # Table/JSON/CSV formatting
├── requirements.txt                # Dependencies
└── README.md                       # Usage instructions
```

### Main Entry Point (dns_tunnel_cli.py)

```python
import argparse
from traffic_capture import capture_live, read_pcap
from feature_extraction import compute_features, aggregate_windows
from inference import load_model, predict
from output_formatters import format_table, format_json, format_csv

def main():
    parser = argparse.ArgumentParser(description="DNS Tunnel Classifier CLI")
    parser.add_argument("--interface", help="Network interface (e.g., eth0)")
    parser.add_argument("--pcap", help="Path to pcap file")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration (seconds)")
    parser.add_argument("--src-ip", help="Filter by source IP (optional)")
    parser.add_argument("--output", choices=["json", "csv", "table"], default="table")
    parser.add_argument("--output-file", help="Write to file instead of stdout")
    parser.add_argument("--threshold", type=float, default=0.5)

    args = parser.parse_args()

    # Step 1: Capture traffic
    if args.interface:
        packets = capture_live(args.interface, args.duration)
    elif args.pcap:
        packets = read_pcap(args.pcap)
    else:
        parser.error("Specify either --interface or --pcap")

    # Step 2: Aggregate into windows
    windows = aggregate_windows(packets, window_size=10)

    # Step 3: Extract features
    results = []
    model = load_model("dns_tunnel_classifier.joblib")
    for (src_ip, window_id), packets_in_window in windows.items():
        features = compute_features(packets_in_window)
        prob_tunnel, decision, base_probs = predict(model, features)
        results.append({
            "src_ip": src_ip,
            "window_id": window_id,
            "decision": decision,
            "p_tunnel": prob_tunnel,
            "base_probs": base_probs,
            "num_packets": len(packets_in_window),
        })

    # Step 4: Format output
    if args.output == "json":
        output = format_json(results)
    elif args.output == "csv":
        output = format_csv(results)
    else:
        output = format_table(results)

    # Step 5: Write output
    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(output)
    else:
        print(output)

if __name__ == "__main__":
    main()
```

---

## 8. Dependencies

```
scapy>=2.5.0        # Packet capture and pcap parsing
scikit-learn>=1.3   # Joblib model object (bundled with sklearn)
joblib>=1.3         # Model serialization
numpy>=1.26         # Numerical computations
scipy>=1.10         # Entropy, skew
click>=8.0          # Optional: nicer CLI parsing than argparse
```

---

## 9. Key Implementation Notes

1. **Feature Order Matters**
   - When converting features_dict to a vector, always use the same order as stored in the joblib file.
   - The model was trained expecting features in this exact order. Permuting them will produce garbage predictions.

2. **Handle Missing/Invalid Data**
   - If a window has 0 packets: set all features to 0 (or skip the window)
   - If division by zero occurs (e.g., response_ratio with 0 queries): default to 0

3. **Timestamps**
   - For live capture: use relative time (seconds elapsed since start of capture)
   - For pcap: use timestamps embedded in the pcap file

4. **Source IP Filtering**
   - If `--src-ip` is provided: only output results for that IP
   - If not provided: output all source IPs

5. **Performance Considerations**
   - Load the model **once** at startup (joblib deserialization is slow)
   - Cache the model in memory for repeated predictions
   - For live capture on high-traffic networks, you may need to use threads or async to avoid packet loss

6. **Scapy Tips**
   - To sniff with a filter: `sniff(iface="eth0", filter="udp port 53", ...)`
   - To read a pcap: `packets = rdpcap("file.pcap")`
   - To extract DNS layer: check if packet has `IP`, `UDP`, and `DNS` layers
   - Query/response matching: rough heuristic is to match by timestamp proximity (query slightly before response)

---

## 10. Testing & Validation

**Smoke Test:**

```bash
# Test with a sample pcap
python dns_tunnel_cli.py --pcap test_tunnel.pcap --output json

# Expected output: JSON with results for each source IP/window
# Should include fields: src_ip, decision, p_tunnel, base_probs, num_packets
```

**Live Test:**

```bash
# Capture from localhost or test interface
python dns_tunnel_cli.py --interface lo --duration 5 --output table

# Should show results (or "No DNS traffic detected" if no packets)
```

**Edge Cases:**

- Empty pcap (no packets) → should not crash, output empty results
- Pcap with non-DNS UDP traffic → should filter correctly
- Windows with 0 packets → should skip or output zero features
- Very large pcaps (>10M packets) → may need streaming/chunking logic

---

## 11. Acceptance Criteria

The tool is complete when:

✅ Captures live DNS traffic from a specified interface  
✅ Reads DNS packets from a pcap file  
✅ Aggregates packets into 10-second windows per source IP  
✅ Computes all 36 features correctly  
✅ Loads the pre-trained model (joblib pickle)  
✅ Makes predictions with output of decision + P(tunnel) + base-learner probs  
✅ Formats output as table, JSON, or CSV  
✅ Handles edge cases (no traffic, missing data, zero division)  
✅ Runs without crashing on both synthetic and real traffic  
✅ Matches expected output format from example walkthrough (Section 6)

---

## 12. References & Resources

- **Scapy Documentation:** https://scapy.readthedocs.io/
- **Scikit-learn Voting Classifier:** https://scikit-learn.org/stable/modules/ensemble.html#voting-classifier
- **Joblib (model serialization):** https://joblib.readthedocs.io/
- **DNS Protocol Basics:** RFC 1035 (for packet structure)
- **Entropy (information theory):** https://en.wikipedia.org/wiki/Entropy_(information_theory)

---

## Summary

You have:

1. A **pre-trained model** (`dns_tunnel_classifier.joblib`)
2. A **feature specification** (36 features, grouped into 7 categories)
3. A **processing pipeline** (capture → aggregate → extract → predict → format)
4. **Example walkthrough** (Section 6)
5. **Test criteria** (Section 11)

Your task is to implement the CLI tool that orchestrates these steps. The model inference itself is a single function call (`model.predict_proba()`); the bulk of the work is feature extraction and output formatting.
