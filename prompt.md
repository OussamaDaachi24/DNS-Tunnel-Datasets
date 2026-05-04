You are given a subset of a DNS tunneling dataset:

Two additional files exist (dns_features_tunnel/nontunnel.csv ) but are large. You may sample from them only if necessary, and must minimize total data loading and token usage.

Objective

Create a Jupyter notebook that performs a rigorous investigation of potential data leakage in the dataset and proposes concrete fixes at the data pipeline level.

1. Data Loading Strategy

If additional data is required for validation, load small, controlled samples from the other files (e.g., stratified or random sampling).
Explicitly justify any additional data usage. 2. Leakage Analysis (Core Task)

Define and test for multiple forms of leakage, not just correlations:

a. Target Leakage
Identify features that may directly or indirectly encode the label.
Check for:
Post-event features (computed after classification decision)
Aggregations that include future information
Encodings derived from labels

b. Temporal Leakage
If timestamps exist:
Verify whether features use future data
Check ordering assumptions
Simulate a time-based split and compare with random split performance

d. Statistical Red Flags
Extremely high feature–target correlation
Near-perfect separability
Features with suspicious distributions (e.g., binary flags that align too well with labels)
e. Duplicate / Near-Duplicate Samples
Identify duplicates or near-duplicates across rows
Quantify their impact on model performance 3. Empirical Validation
Train a baseline model (e.g., logistic regression or light gradient boosting)
Compare performance under:
Random split
Time-based split (if applicable)
Group-based split

Large performance drops → strong indicator of leakage.

4. Root Cause Analysis

For each suspected leakage source:

Explain why it leaks information
Trace it back to the feature extraction process
Identify whether it comes from:
Aggregation logic
Windowing strategy
Label construction
Data joins 5. Remediation Strategy (Critical)

Propose concrete fixes, not generic advice:

Redefine feature computation to ensure causality
Adjust aggregation windows (e.g., strictly past-only)
Remove or redesign problematic features
Introduce proper data splitting strategy:
Time-aware split
Group-aware split
Suggest modifications to the feature extraction pipeline (pseudo-code is acceptable) 6. Output Requirements
Deliver a clean, well-structured notebook with:
Clear sectioning
Reproducible code
Concise but technical explanations
Avoid unnecessary verbosity
Focus on diagnostic depth over breadth 7. Constraints
Minimize data loading and memory usage
Do not assume dataset cleanliness
Do not rely on superficial correlation checks alone
Prioritize methodological correctness over speed
