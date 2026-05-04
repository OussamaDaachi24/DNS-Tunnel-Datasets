"""
DNS Tunnel Detection - Feature Extraction (Sliding Window + Parallel)
=====================================================================
Each PCAP → many rows (one per sliding time window per source IP).
This produces a much larger, more realistic dataset.

Window : 10 seconds  (configurable via --window)
Stride :  5 seconds  (configurable via --stride)
Min packets per window: 5 (discard noise windows)

Parallelism: one worker process per PCAP file via ProcessPoolExecutor.

Requirements:
    pip install scapy pandas numpy tqdm

Usage:
    python dns_feature_extractor_v2.py \
        --root /path/to/DNS-Tunnel-Datasets \
        --output dns_features.csv \
        --window 10 \
        --stride 5 \
        --workers 8
"""

import os
import math
import argparse
import string
from collections import Counter
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

import numpy as np
import pandas as pd
from tqdm import tqdm

try:
    from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, TCP
except ImportError:
    raise SystemExit("Install scapy first:  pip install scapy")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def shannon_entropy_counts(counts) -> float:
    n = sum(counts.values()) if hasattr(counts, "values") else sum(counts)
    if n == 0:
        return 0.0
    vals = counts.values() if hasattr(counts, "values") else counts
    return -sum((c / n) * math.log2(c / n) for c in vals if c > 0)

def gini_counts(counts) -> float:
    n = sum(counts.values()) if hasattr(counts, "values") else sum(counts)
    if n == 0:
        return 0.0
    vals = counts.values() if hasattr(counts, "values") else counts
    return 1.0 - sum((c / n) ** 2 for c in vals)

def is_base64_like(s: str) -> float:
    b64 = set(string.ascii_letters + string.digits + "+/=")
    return sum(1 for c in s if c in b64) / len(s) if s else 0.0

def is_hex_like(s: str) -> float:
    hx = set("0123456789abcdefABCDEF")
    return sum(1 for c in s if c in hx) / len(s) if s else 0.0

def numeric_ratio(s: str) -> float:
    return sum(1 for c in s if c.isdigit()) / len(s) if s else 0.0

def consonant_ratio(s: str) -> float:
    vowels = set("aeiouAEIOU")
    letters = [c for c in s if c.isalpha()]
    return sum(1 for c in letters if c not in vowels) / len(letters) if letters else 0.0

def unique_char_ratio(s: str) -> float:
    return len(set(s.lower())) / len(s) if s else 0.0

def extract_subdomain(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else ""

def longest_label(domain: str) -> int:
    parts = domain.split(".")
    return max((len(p) for p in parts), default=0)

TUNNEL_FAVOURED_TYPES = {16, 10, 28, 255, 6}  # TXT, NULL, AAAA, ANY, SOA


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: PCAP → list of flat packet dicts  (fast, no aggregation yet)
# ─────────────────────────────────────────────────────────────────────────────

def pcap_to_packet_list(pcap_path: str) -> list[dict]:
    """Read a PCAP and return one dict per DNS packet."""
    try:
        pkts = rdpcap(pcap_path)
    except Exception:
        return []

    records = []
    for pkt in pkts:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        try:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".") if dns.qd else ""
        except Exception:
            qname = ""
        if not qname:
            continue

        subdomain = extract_subdomain(qname)
        qtype     = dns.qd.qtype if dns.qd else 0

        # rdata length from response
        rdata_len = 0
        if dns.qr == 1 and dns.an:
            rr = dns.an
            while rr:
                try:
                    rdata_len += len(rr.rdata) if hasattr(rr, "rdata") else 0
                except Exception:
                    pass
                rr = getattr(rr, "payload", None)
                if rr and not rr.haslayer(DNSRR):
                    break

        # source IP  (used to group per-client windows)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"

        records.append({
            "timestamp":       float(pkt.time),
            "src_ip":          src_ip,
            "qname":           qname,
            "subdomain":       subdomain,
            "qtype":           qtype,
            "is_response":     int(dns.qr == 1),
            "answer_count":    dns.ancount if hasattr(dns, "ancount") else 0,
            "authority_count": dns.nscount if hasattr(dns, "nscount") else 0,
            "rcode":           dns.rcode   if hasattr(dns, "rcode")   else 0,
            "dns_payload_size":len(bytes(dns)),
            "rdata_len":       rdata_len,
            "uses_tcp":        int(pkt.haslayer(TCP)),
            # pre-computed per-query scalars (cheap here, reused many times below)
            "qname_len":       len(qname),
            "subdomain_len":   len(subdomain),
            "label_count":     qname.count(".") + 1,
            "max_label_len":   longest_label(qname),
            "qname_entropy":   shannon_entropy(qname),
            "sub_entropy":     shannon_entropy(subdomain),
            "b64_ratio":       is_base64_like(subdomain),
            "hex_ratio":       is_hex_like(subdomain),
            "num_ratio":       numeric_ratio(subdomain),
            "cons_ratio":      consonant_ratio(subdomain),
            "uniq_ratio":      unique_char_ratio(subdomain),
            "is_tunnel_type":  int(qtype in TUNNEL_FAVOURED_TYPES),
        })
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: aggregate a window of packet-dicts → one feature row
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_window(window: list[dict]) -> dict:
    n = len(window)
    timestamps = [p["timestamp"] for p in window]
    duration   = max(timestamps) - min(timestamps)
    query_rate = n / duration if duration > 0 else float(n)

    sorted_ts = sorted(timestamps)
    iats = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    payloads   = [p["dns_payload_size"] for p in window]
    qnames     = [p["qname"]            for p in window]
    qtype_cnt  = Counter(p["qtype"]     for p in window)
    base_cnt   = Counter(".".join(q.split(".")[-2:]) for q in qnames if q)

    def mean(lst): return float(np.mean(lst)) if lst else 0.0
    def std(lst):  return float(np.std(lst))  if lst else 0.0

    return {
        # flow
        "n_packets":              n,
        "duration_sec":           duration,
        "query_rate":             query_rate,
        "unique_qnames":          len(set(qnames)),
        "unique_subdomains":      len(set(p["subdomain"] for p in window)),
        "unique_qname_ratio":     len(set(qnames)) / n,
        # inter-arrival time
        "iat_mean":               mean(iats),
        "iat_std":                std(iats),
        "iat_min":                float(min(iats)) if iats else 0.0,
        "iat_max":                float(max(iats)) if iats else 0.0,
        # payload
        "payload_mean":           mean(payloads),
        "payload_std":            std(payloads),
        "payload_max":            float(max(payloads)),
        # entropy
        "entropy_mean":           mean([p["qname_entropy"] for p in window]),
        "entropy_std":            std( [p["qname_entropy"] for p in window]),
        "subdomain_entropy_mean": mean([p["sub_entropy"]   for p in window]),
        # query type fractions
        "txt_frac":               qtype_cnt.get(16,  0) / n,
        "null_frac":              qtype_cnt.get(10,  0) / n,
        "aaaa_frac":              qtype_cnt.get(28,  0) / n,
        "a_frac":                 qtype_cnt.get(1,   0) / n,
        "any_frac":               qtype_cnt.get(255, 0) / n,
        "tunnel_type_frac":       sum(p["is_tunnel_type"] for p in window) / n,
        # domain-target distribution shape (replaces top_base_frac, which leaked
        # capture topology: tunnel pcaps target one C2 → ≈1.0, benign → ≈0).
        # Entropy and Gini are bounded distributional shape descriptors that
        # do not encode "this capture is a tunnel".
        "base_entropy":           shannon_entropy_counts(base_cnt),
        "base_gini":              gini_counts(base_cnt),
        # transport
        "tcp_frac":               sum(p["uses_tcp"]   for p in window) / n,
        # per-query averages
        "avg_qname_len":          mean([p["qname_len"]      for p in window]),
        "avg_subdomain_len":      mean([p["subdomain_len"]  for p in window]),
        "avg_label_count":        mean([p["label_count"]    for p in window]),
        "avg_max_label_len":      mean([p["max_label_len"]  for p in window]),
        "avg_b64_ratio":          mean([p["b64_ratio"]      for p in window]),
        "avg_hex_ratio":          mean([p["hex_ratio"]      for p in window]),
        "avg_numeric_ratio":      mean([p["num_ratio"]      for p in window]),
        "avg_consonant_ratio":    mean([p["cons_ratio"]     for p in window]),
        "avg_unique_char_ratio":  mean([p["uniq_ratio"]     for p in window]),
        # response
        "n_responses":            sum(p["is_response"]    for p in window),
        "avg_answer_count":       mean([p["answer_count"] for p in window]),
        "avg_rdata_len":          mean([p["rdata_len"]    for p in window]),
        "nxdomain_frac":          sum(1 for p in window if p["rcode"] == 3) / n,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: sliding window over a sorted packet list
# ─────────────────────────────────────────────────────────────────────────────

def sliding_windows(packets: list[dict],
                    window_sec: float,
                    stride_sec: float,
                    min_packets: int) -> list[dict]:
    """
    Slide a time window over packets (already sorted by timestamp).
    Returns one aggregated row per valid window.
    """
    if not packets:
        return []

    rows  = []
    t0    = packets[0]["timestamp"]
    t_end = packets[-1]["timestamp"]

    win_start = t0
    while win_start < t_end:
        win_end = win_start + window_sec
        window  = [p for p in packets if win_start <= p["timestamp"] < win_end]

        if len(window) >= min_packets:
            row = aggregate_window(window)
            row["window_start"] = win_start
            rows.append(row)

        win_start += stride_sec

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: worker function (runs in a subprocess)
# ─────────────────────────────────────────────────────────────────────────────

def process_pcap_worker(args: tuple) -> list[dict]:
    """
    Top-level function (must be picklable → module-level).
    args = (pcap_path, label, source, window_sec, stride_sec, min_packets, per_ip)
    """
    pcap_path, label, source, window_sec, stride_sec, min_packets, per_ip = args

    packets = pcap_to_packet_list(pcap_path)
    if not packets:
        return []

    packets.sort(key=lambda p: p["timestamp"])
    rows = []

    if per_ip:
        # Group by source IP → separate window per client (more realistic)
        by_ip: dict[str, list] = {}
        for p in packets:
            by_ip.setdefault(p["src_ip"], []).append(p)
        for ip, ip_packets in by_ip.items():
            for row in sliding_windows(ip_packets, window_sec, stride_sec, min_packets):
                row["src_ip"] = ip
                row["pcap_file"] = os.path.basename(pcap_path)
                row["source"]    = source
                row["label"]     = label
                rows.append(row)
    else:
        # Treat entire PCAP as one stream (simpler, still good)
        for row in sliding_windows(packets, window_sec, stride_sec, min_packets):
            row["src_ip"]    = "mixed"
            row["pcap_file"] = os.path.basename(pcap_path)
            row["source"]    = source
            row["label"]     = label
            rows.append(row)

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: orchestrator
# ─────────────────────────────────────────────────────────────────────────────

FOLDER_LABELS = {
    "normal":        0,
    "tunnel":        1,
    "unkownTunnel":  1,
    "unknownTunnel": 1,
    "crossEndPoint": 1,
    "wildcard":      2,
}

def find_pcaps(folder: Path) -> list[Path]:
    return list(folder.rglob("*.pcap")) + list(folder.rglob("*.pcapng"))


def build_dataset(root: str, output: str,
                  window_sec: float, stride_sec: float,
                  min_packets: int, n_workers: int,
                  per_ip: bool, wildcard_as_benign: bool,
                  only_tunnel: bool, exclude_tunnel: bool):

    root_path = Path(root)
    all_tasks = []

    for folder_name, label in FOLDER_LABELS.items():
        # Optionally restrict to / exclude tunnel-related folders (label == 1)
        if only_tunnel and label != 1:
            continue
        if exclude_tunnel and label == 1:
            continue
        folder = root_path / folder_name
        if not folder.exists():
            continue
        effective_label = 0 if (folder_name == "wildcard" and wildcard_as_benign) else label
        for pcap in find_pcaps(folder):
            all_tasks.append((str(pcap), effective_label, folder_name,
                               window_sec, stride_sec, min_packets, per_ip))

    print(f"Found {len(all_tasks)} PCAP files — running with {n_workers} workers")
    print(f"Window={window_sec}s  Stride={stride_sec}s  MinPackets={min_packets}  PerIP={per_ip}\n")

    all_rows = []
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        futures = {executor.submit(process_pcap_worker, task): task for task in all_tasks}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing PCAPs"):
            try:
                rows = future.result()
                all_rows.extend(rows)
            except Exception as e:
                print(f"  [ERROR] {futures[future][0]}: {e}")

    if not all_rows:
        print("No rows extracted. Check dataset path.")
        return

    df = pd.DataFrame(all_rows)

    # Reorder columns. NOTE: `source` is kept only as audit metadata — it is a
    # 1:1 string of the folder, hence of the label, and MUST NOT be passed
    # into a model's feature matrix. Same for pcap_file/src_ip/window_start
    # (these are grouping keys, not features).
    meta = ["pcap_file", "source", "src_ip", "window_start", "label"]
    feat = [c for c in df.columns if c not in meta]
    df   = df[meta + feat]

    df.to_csv(output, index=False)

    print(f"\n✓  {len(df)} rows × {len(df.columns)} columns  →  {output}")
    print("\nClass distribution:")
    mapping = {0: "benign", 1: "tunnel", 2: "wildcard"}
    print(df["label"].map(mapping).value_counts().to_string())
    print("\nRows per source folder:")
    print(df["source"].value_counts().to_string())


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Tunnel Feature Extractor v2 (Sliding Window + Parallel)")
    parser.add_argument("--root",    required=True,          help="Path to DNS-Tunnel-Datasets repo")
    parser.add_argument("--output",  default="dns_features.csv")
    parser.add_argument("--window",  type=float, default=10, help="Window size in seconds (default: 10)")
    parser.add_argument("--stride",  type=float, default=10, help="Stride in seconds (default: 10 = non-overlapping; "
                                                                  "use < window only for evaluation/streaming, never for training rows)")
    parser.add_argument("--min-packets", type=int, default=5,help="Min packets per window to keep row (default: 5)")
    parser.add_argument("--workers", type=int,   default=os.cpu_count(),
                                                              help="Parallel worker processes")
    parser.add_argument("--per-ip",  action="store_true",    help="Split windows per source IP (recommended)")
    parser.add_argument("--wildcard-as-benign", action="store_true")
    parser.add_argument("--only-tunnel", action="store_true",
                        help="Use only tunnel-related folders (exclude normal/wildcard)")
    parser.add_argument("--exclude-tunnel", action="store_true",
                        help="Use only non-tunnel folders (e.g. normal/wildcard)")
    args = parser.parse_args()

    build_dataset(
        root=args.root, output=args.output,
        window_sec=args.window, stride_sec=args.stride,
        min_packets=args.min_packets, n_workers=args.workers,
        per_ip=args.per_ip, wildcard_as_benign=args.wildcard_as_benign,
        only_tunnel=args.only_tunnel, exclude_tunnel=args.exclude_tunnel
    )