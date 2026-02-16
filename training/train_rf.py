"""
Retrain Random Forest + TF-IDF for SQL Injection Detection.

Uses the same pipeline as SQLInjectionEnsemble._predict_rf():
    - TF-IDF on preprocessed text (char n-grams 2-5)
    - 5 numeric features: length, digits, specials, quotes, keywords
    - Concatenated via scipy.sparse.hstack
    - RandomForestClassifier with class_weight='balanced'

Output:
    rf_sql_model.pkl      — Random Forest model
    tfidf_vectorizer.pkl  — TF-IDF vectorizer

Usage:
    python training/train_rf.py
"""

import re
import sys
import json
import time
import urllib.parse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

PROJECT_ROOT = Path(__file__).parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "dataset.csv"
EXTENDED_DATASET_PATH = PROJECT_ROOT / "SQL_Dataset_Extended.csv"
RF_SAVE_PATH = PROJECT_ROOT / "rf_sql_model.pkl"
TFIDF_SAVE_PATH = PROJECT_ROOT / "tfidf_vectorizer.pkl"
LOG_PATH = PROJECT_ROOT / "training" / "rf_training_log.json"


def preprocess(text: str) -> str:
    """Same as SQLInjectionEnsemble.preprocess()."""
    text = str(text).lower()
    text = urllib.parse.unquote(text)
    text = re.sub(r'/\*.*?\*/', ' ', text)
    text = re.sub(r'--.*$', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def extract_features(text: str) -> list:
    """Same as SQLInjectionEnsemble.extract_features()."""
    clean = preprocess(text)
    return [
        len(clean),
        sum(c.isdigit() for c in clean),
        sum(not c.isalnum() and not c.isspace() for c in clean),
        clean.count("'") + clean.count('"'),
        len(re.findall(
            r'\b(select|union|or|and|drop|sleep|where|from|insert|update|delete|having|group)\b',
            clean
        ))
    ]


def main():
    print("=" * 70)
    print("Random Forest Training — SQL Injection Detection")
    print("=" * 70)

    # Load data
    print(f"\nLoading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"  Synthetic: {len(df)} samples")

    if EXTENDED_DATASET_PATH.exists():
        print(f"Loading extended dataset from {EXTENDED_DATASET_PATH}...")
        df_ext = pd.read_csv(EXTENDED_DATASET_PATH)
        if 'Query' in df_ext.columns and 'Label' in df_ext.columns:
            df_ext = df_ext.rename(columns={'Query': 'text', 'Label': 'label'})
        df = pd.concat([df, df_ext], ignore_index=True)
        print(f"  Extended: {len(df_ext)} samples")

    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str)
    df['label'] = df['label'].astype(int)
    df = df.drop_duplicates(subset=['text'])
    print(f"  Total after merge+dedup: {len(df)}")
    print(f"  Injection: {(df['label']==1).sum()}, Safe: {(df['label']==0).sum()}")

    # Preprocess
    print("\nPreprocessing texts...")
    texts = df['text'].tolist()
    labels = df['label'].values
    cleaned = [preprocess(t) for t in texts]

    # Split
    X_train_t, X_test_t, y_train, y_test, idx_train, idx_test = train_test_split(
        cleaned, labels, range(len(labels)),
        test_size=0.20, random_state=42, stratify=labels
    )

    print(f"  Train: {len(X_train_t)}, Test: {len(X_test_t)}")

    # TF-IDF
    print("\nFitting TF-IDF (char n-grams 2-5)...")
    tfidf = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 5),
        max_features=50000,
        sublinear_tf=True,
    )
    X_train_tfidf = tfidf.fit_transform(X_train_t)
    X_test_tfidf = tfidf.transform(X_test_t)

    # Numeric features
    print("Extracting numeric features...")
    raw_train = [texts[i] for i in idx_train]
    raw_test = [texts[i] for i in idx_test]
    X_train_extra = np.array([extract_features(t) for t in raw_train])
    X_test_extra = np.array([extract_features(t) for t in raw_test])

    X_train = hstack([X_train_tfidf, X_train_extra])
    X_test = hstack([X_test_tfidf, X_test_extra])

    # Train RF
    print("\nTraining Random Forest...")
    start = time.time()
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    train_time = time.time() - start
    print(f"  Training time: {train_time:.1f}s")

    # Evaluate
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    print(f"\n{'='*70}")
    print("Test Results:")
    print(f"{'='*70}")
    print(f"  Accuracy:  {acc:.6f}")
    print(f"  Precision: {prec:.6f}")
    print(f"  Recall:    {rec:.6f}")
    print(f"  F1:        {f1:.6f}")
    print(f"  ROC-AUC:   {auc:.6f}")
    print(f"  FPR:       {fpr:.6f}")
    print(f"  FNR:       {fnr:.6f}")

    # Save
    joblib.dump(rf, RF_SAVE_PATH)
    joblib.dump(tfidf, TFIDF_SAVE_PATH)
    print(f"\nModel: {RF_SAVE_PATH}")
    print(f"TF-IDF: {TFIDF_SAVE_PATH}")

    # Log
    log = {
        'model': 'RandomForest',
        'config': {
            'n_estimators': 200,
            'max_depth': 30,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'class_weight': 'balanced',
            'tfidf_analyzer': 'char_wb',
            'tfidf_ngram_range': [2, 5],
            'tfidf_max_features': 50000,
        },
        'data': {
            'train_size': len(X_train_t),
            'test_size': len(X_test_t),
        },
        'test_metrics': {
            'accuracy': round(acc, 6),
            'precision': round(prec, 6),
            'recall': round(rec, 6),
            'f1': round(f1, 6),
            'roc_auc': round(auc, 6),
            'fpr': round(fpr, 6),
            'fnr': round(fnr, 6),
        },
        'training_time_s': round(train_time, 1),
    }
    with open(LOG_PATH, 'w') as f:
        json.dump(log, f, indent=2)
    print(f"Log: {LOG_PATH}")

    print(f"\n{'='*70}")
    print(f"[OK] Random Forest Training Complete!")
    print(f"{'='*70}")

    return log


if __name__ == '__main__':
    main()
