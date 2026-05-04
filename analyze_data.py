import os
import pandas as pd
from pathlib import Path

def analyze():
    project_root = Path(r"c:\Users\acer\Desktop\CNS_Projects\DNS-Tunnel-Datasets")
    csv_files = ["dns_features_nontunnel.csv", "dns_features_tunnel.csv"]
    
    # 1. PCAP Analysis
    pcap_folders = ["normal", "tunnel", "unkownTunnel", "crossEndPoint", "wildcard"]
    pcap_info = {}
    
    print("--- PCAP File Analysis ---")
    for folder in pcap_folders:
        folder_path = project_root / folder
        if folder_path.exists():
            pcaps = list(folder_path.rglob("*.pcap")) + list(folder_path.rglob("*.pcapng"))
            total_size = sum(p.stat().st_size for p in pcaps)
            pcap_info[folder] = {"count": len(pcaps), "size_mb": total_size / (1024 * 1024)}
            print(f"Folder '{folder}': {len(pcaps)} files, {total_size / (1024 * 1024):.2f} MB")
        else:
            print(f"Folder '{folder}': Not found")
            
    # 2. CSV Analysis
    print("\n--- CSV Dataset Analysis ---")
    all_dfs = []
    for csv in csv_files:
        csv_path = project_root / csv
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            print(f"\nFile: {csv}")
            print(f"  Rows: {len(df)}")
            print(f"  Columns: {len(df.columns)}")
            print(f"  Memory Usage: {df.memory_usage(deep=True).sum() / (1024 * 1024):.2f} MB")
            
            # Check for nulls
            null_counts = df.isnull().sum().sum()
            print(f"  Null values: {null_counts}")
            
            # Class distribution if 'label' exists
            if 'label' in df.columns:
                print("  Labels:")
                print(df['label'].value_counts())
                
            # Sources in this CSV
            if 'source' in df.columns:
                print("  Sources:")
                print(df['source'].value_counts().head(5))
                
            # Check unique PCAP files covered
            if 'pcap_file' in df.columns:
                unique_pcaps = df['pcap_file'].nunique()
                print(f"  Unique PCAP files referenced: {unique_pcaps}")
                
            all_dfs.append(df)
        else:
            print(f"File: {csv} - NOT FOUND")

    if all_dfs:
        merged_df = pd.concat(all_dfs, ignore_index=True)
        print("\n--- Summary of Combined Dataset ---")
        print(f"Total Rows: {len(merged_df)}")
        print(f"Overall Class Balance:")
        if 'label' in merged_df.columns:
            print(merged_df['label'].value_counts(normalize=True))
            
        print("\nFeatures Statistics (Selection):")
        features = [c for c in merged_df.columns if c not in ['pcap_file', 'source', 'src_ip', 'window_start', 'label']]
        print(f"Number of numeric features: {len(features)}")
        stats = merged_df[features].describe().transpose()
        print(stats[['mean', 'std', 'min', 'max']].head(15))
        
        # Check label consistency
        print("\nLabel naming check:")
        mapping = {0: "benign", 1: "tunnel", 2: "wildcard"}
        print(merged_df['label'].map(mapping).value_counts())

if __name__ == "__main__":
    analyze()
