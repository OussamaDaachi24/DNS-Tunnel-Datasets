# DNS Tunneling Dataset - Feature Documentation

This document provides a detailed breakdown of the 37 features extracted from DNS traffic in the sliding window processing pipeline.

## 1. Traffic Volumetrics
These features describe the amount and rate of DNS traffic within the time window.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `n_packets` | Total count of DNS packets in the window. | Tunnels often generate a high volume of packets to transport data. | Sum of all DNS packets captured in the current time/stride window. |
| `duration_sec` | Actual time span (seconds) of the window. | Differentiates between short bursts and sustained traffic. | `max(timestamp) - min(timestamp)` of packets in the window. |
| `query_rate` | Packets per second. | Tunneling clients typically have a higher and more consistent query rate than human browsing. | `n_packets / duration_sec`. |

## 2. Uniqueness & Entropy
These features focus on the novelty and "randomness" of the query strings, which is high in tunneling.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `unique_qnames` | Count of distinct full query names. | Tunneling uses unique subdomains for every packet to avoid caching and convey data. | Count of unique strings in the `qname` column within the window. |
| `unique_subdomains` | Count of distinct subdomains. | Encoded data resides in subdomains; many unique subdomains indicate data transfer. | Count of unique strings extracted as subdomains. |
| `unique_qname_ratio` | Ratio of unique queries to total queries. | High ratio (close to 1.0) is a strong indicator of tunneling. | `unique_qnames / n_packets`. |
| `entropy_mean` | Average Shannon Entropy of query names. | Encoded data (Base64/Hex) has higher entropy than natural language domains. | Mean of Shannon entropy calculated for each `qname`. |
| `entropy_std` | Standard deviation of query name entropy. | Sustained tunneling shows low variance in high entropy. | Standard deviation of entropy across queries in the window. |
| `subdomain_entropy_mean` | Average Shannon Entropy of subdomains. | Focuses entropy calculation where the data payload is most likely to be. | Mean Shannon entropy of just the subdomain part. |

## 3. Timing (Inter-Arrival Time - IAT)
Analyzes the temporal gaps between packets.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `iat_mean` | Average time gap between consecutive packets. | Periodic heartbeats or rapid bursts in tunnels have specific IAT signatures. | Average of differences between sorted packet timestamps. |
| `iat_std` | Variation in IATS. | Machine-generated traffic (tunnels) often has lower IAT jitter than human traffic. | Standard deviation of the inter-arrival times. |
| `iat_min` | Shortest time gap observed. | Identifies high-speed data exfiltration. | Minimum value in the list of IATs. |
| `iat_max` | Longest time gap observed. | Helps identify idle periods or heartbeat intervals. | Maximum value in the list of IATs. |

## 4. Packet Payloads
Measures the size of the DNS packets.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `payload_mean` | Average size of the DNS payload. | Tunnels maximize packet size to increase throughput. | Mean of the `dns_payload_size` (size of the DNS layer in bytes). |
| `payload_std` | Std Dev of payload sizes. | Tunnels often use consistent, large packet sizes. | Standard deviation of payload sizes in the window. |
| `payload_max` | Largest payload in the window. | Detects attempts to push the limits of DNS packet sizes (max ~512 bytes for UDP). | Maximum payload size observed. |

## 5. DNS Query Types
Distribution of the specific types of DNS records requested.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `txt_frac` | Fraction of TXT record queries. | TXT records are preferred by tunnels as they allow large, arbitrary data responses. | `count(qtype=16) / n_packets`. |
| `null_frac` | Fraction of NULL record queries. | NULL records are purely for data and rarely used in normal traffic. | `count(qtype=10) / n_packets`. |
| `aaaa_frac` | Fraction of AAAA (IPv6) queries. | Some tunnels use AAAA records to hide data in IPv6 addresses. | `count(qtype=28) / n_packets`. |
| `a_frac` | Fraction of A (IPv4) queries. | Standard queries; a low fraction of A records relative to others is suspicious. | `count(qtype=1) / n_packets`. |
| `any_frac` | Fraction of ANY queries. | Used by some tools to discover server capabilities or exfiltrate via various records. | `count(qtype=255) / n_packets`. |
| `tunnel_type_frac` | Combined fraction of TXT, NULL, AAAA, ANY, and SOA. | Aggregate metric for high-capacity or unusual tunnel record types. | `sum(packets with favoured types) / n_packets`. |

## 6. String Composition (Linguistic Features)
Detailed analysis of the character distributions in subdomains.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `avg_qname_len` | Average length (chars) of full query names. | Tunnels use very long domains to pack data. | Average of `len(qname)` across the window. |
| `avg_subdomain_len` | Average length of just the subdomain. | Isolates the length of the data-carrying portion. | Average of `len(subdomain)`. |
| `avg_label_count` | Average number of labels (parts between dots). | More labels can indicate complex data structures or sub-channeling. | Average of dots count + 1 in the qname. |
| `avg_max_label_len` | Average of the longest label in each query. | Tunnels push individual labels to the 63-character limit. | Average of the length of the longest part of each `qname`. |
| `avg_b64_ratio` | Ratio of Base64 characters in subdomain. | High ratio of A-Z, a-z, 0-9, +, / indicates Base64 encoding. | Mean of (Base64 chars count / total chars) per subdomain. |
| `avg_hex_ratio` | Ratio of Hexadecimal characters in subdomain. | Identifies data encoded in hexadecimal. | Mean of (Hex chars [0-9a-f] count / total chars) per subdomain. |
| `avg_numeric_ratio` | Ratio of digits in subdomain. | Encoded data often has a higher digit density than standard domains. | Mean of (Digits count / total chars) per subdomain. |
| `avg_consonant_ratio`| Ratio of consonants in alphabetical chars. | Encoded strings lack the vowel distribution of natural language names. | Mean of (Consonants / alpha chars) per subdomain. |
| `avg_unique_char_ratio`| Ratio of unique chars to total length. | Encoded strings use a variety of characters to maximize data per byte. | Mean of (unique chars count / length) per subdomain. |

## 7. DNS Protocol Context
Features related to the transport and server responses.

| Feature | Meaning | Why chosen (How it helps) | Calculation Method |
| :--- | :--- | :--- | :--- |
| `top_base_frac` | Fraction of queries going to the most frequent second-level domain. | Tunneling traffic is almost exclusively directed to a single command-and-control (C2) domain. | `count(most_freq_domain) / n_packets`. |
| `tcp_frac` | Fraction of packets using TCP. | Large DNS answers can trigger a switch to TCP; some tunnels use TCP exclusively. | `count(packets using TCP) / n_packets`. |
| `n_responses` | Number of DNS response packets. | High response count confirms bidirectional communication. | Sum of packets where DNS `qr` flag is 1. |
| `avg_answer_count` | Average number of answers in responses. | Large answer counts are typical when downloading data via DNS. | Mean of `ancount` field in DNS responses. |
| `avg_rdata_len` | Average length of the data in the query answer. | Direct measure of the amount of data being received by the client. | Mean sum of length of all RDATA fields in the responses. |
| `nxdomain_frac` | Fraction of "Non-Existent Domain" responses. | High NXDOMAIN rates can indicate DGA (Domain Generation Algorithms) or mistyped tunnel endpoints. | `count(rcode=3) / n_packets`. |
