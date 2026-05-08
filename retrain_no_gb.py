"""Retrain ensemble without GB: only LR + RF + SVM."""
import warnings, json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import GroupKFold, train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import roc_auc_score, accuracy_score, f1_score, classification_report, confusion_matrix
warnings.filterwarnings('ignore')

ROOT = Path(__file__).resolve().parent
tun = pd.read_csv(ROOT / 'dns_features_tunnel.csv')
ben = pd.read_csv(ROOT / 'dns_features_nontunnel.csv')
df = pd.concat([tun, ben], ignore_index=True)
print('raw rows:', len(df), '| label dist:', df['label'].value_counts().to_dict())

df['y'] = (df['label'] == 1).astype(int)
DROP_FROM_X = {'pcap_file', 'source', 'src_ip', 'window_start', 'label', 'y', 'top_base_frac'}
FEATS = [c for c in df.columns if c not in DROP_FROM_X]

df_sorted = df.sort_values(['pcap_file', 'src_ip', 'window_start']).reset_index(drop=True)
df_sorted['rank'] = df_sorted.groupby(['pcap_file', 'src_ip']).cumcount()
clean = df_sorted[df_sorted['rank'] % 2 == 0].drop(columns='rank').reset_index(drop=True)
clean = clean.drop_duplicates(subset=FEATS, keep='first').reset_index(drop=True)
print(f'clean rows: {len(clean)} | features: {len(FEATS)}')

pcap_label = clean.groupby('pcap_file')['y'].agg(lambda s: int(s.mode().iloc[0]))
pcaps = pcap_label.index.values
labels = pcap_label.values
tr_pcaps, te_pcaps = train_test_split(pcaps, test_size=0.2, random_state=0, stratify=labels)
tr = clean[clean['pcap_file'].isin(tr_pcaps)].reset_index(drop=True)
te = clean[clean['pcap_file'].isin(te_pcaps)].reset_index(drop=True)
print('train rows:', len(tr), '| test rows:', len(te))

def make_ensemble(seed=0):
    lr = Pipeline([('s', StandardScaler()),
                   ('m', LogisticRegression(max_iter=2000, C=1.0, random_state=seed))])
    rf = RandomForestClassifier(n_estimators=300, max_depth=None,
                                min_samples_leaf=2, n_jobs=-1, random_state=seed)
    svm = Pipeline([('s', StandardScaler()),
                    ('m', SVC(kernel='rbf', C=10.0, gamma='scale',
                              probability=True, random_state=seed))])
    return VotingClassifier(
        estimators=[('lr', lr), ('rf', rf), ('svm', svm)],
        voting='soft',
        weights=[1, 2, 1],
        n_jobs=None,
    )

def score(y_true, p):
    yhat = (p >= 0.5).astype(int)
    return dict(
        auc=float(roc_auc_score(y_true, p)) if len(set(y_true)) > 1 else float('nan'),
        acc=float(accuracy_score(y_true, yhat)),
        f1=float(f1_score(y_true, yhat, zero_division=0)),
    )

Xtr = tr[FEATS].fillna(0); ytr = tr['y'].astype(int); groups_tr = tr['pcap_file']
Xte = te[FEATS].fillna(0); yte = te['y'].astype(int)

print('Fitting final ensemble (LR + RF + SVM)...')
model = make_ensemble(seed=0).fit(Xtr, ytr)
p_te = model.predict_proba(Xte)[:, 1]
ens = score(yte, p_te)
print('held-out (unseen pcaps), ensemble:', ens)
for name, est in model.named_estimators_.items():
    p = est.predict_proba(Xte)[:, 1]
    print(f'  {name:>4}: {score(yte, p)}')
print('Confusion matrix:')
print(confusion_matrix(yte, (p_te >= 0.5).astype(int)))
print(classification_report(yte, (p_te >= 0.5).astype(int), digits=3))

out_path = ROOT / 'dns_tunnel_classifier.joblib'
joblib.dump({'model': model, 'features': FEATS}, out_path)
summary = {
    'version': 'v3_no_gb_ensemble',
    'base_learners': ['lr×1', 'rf×2', 'svm×1'],
    'heldout_unseen_pcaps': ens,
    'n_features': len(FEATS),
    'train_rows': int(len(tr)),
    'test_rows': int(len(te)),
}
(ROOT / 'classifier_metrics.json').write_text(json.dumps(summary, indent=2))
print(f'Saved: {out_path}')
print(json.dumps(summary, indent=2))
