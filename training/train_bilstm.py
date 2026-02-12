"""
Train Character-level BiLSTM for SQL Injection Detection.

Usage:
    python training/train_bilstm.py

Output:
    models/char_bilstm_detector.pt — PyTorch model checkpoint
"""

import sys
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models.char_tokenizer import CharTokenizer
from models.char_bilstm_model import CharBiLSTM

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

DATASET_PATH = PROJECT_ROOT / "data" / "dataset.csv"
MODEL_SAVE_PATH = PROJECT_ROOT / "models" / "char_bilstm_detector.pt"
TOKENIZER_SAVE_PATH = PROJECT_ROOT / "models" / "char_tokenizer.json"
LOG_PATH = PROJECT_ROOT / "training" / "bilstm_training_log.json"

EXTENDED_DATASET_PATH = PROJECT_ROOT / "SQL_Dataset_Extended.csv"
USE_EXTENDED_DATASET = True  # Set to True to include SQL_Dataset_Extended.csv

# Hyperparameters
MAX_LENGTH = 200
EMBED_DIM = 32
HIDDEN_DIM = 64
NUM_LAYERS = 2
FC_DIM = 64
DROPOUT = 0.3

BATCH_SIZE = 128
LEARNING_RATE = 3e-4
WEIGHT_DECAY = 1e-5
MAX_GRAD_NORM = 1.0
MAX_EPOCHS = 6
PATIENCE = 2

DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'


# ═══════════════════════════════════════════════════════════════════
# DATASET
# ═══════════════════════════════════════════════════════════════════

class SQLiDataset(Dataset):
    def __init__(self, encoded: np.ndarray, labels: np.ndarray):
        self.encoded = torch.LongTensor(encoded)
        self.labels = torch.FloatTensor(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.encoded[idx], self.labels[idx]


# ═══════════════════════════════════════════════════════════════════
# TRAINING
# ═══════════════════════════════════════════════════════════════════

def load_data(tokenizer: CharTokenizer):
    """Load and encode dataset."""
    print(f"Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"  Synthetic dataset: {len(df)} samples")

    if USE_EXTENDED_DATASET and EXTENDED_DATASET_PATH.exists():
        print(f"Loading extended dataset from {EXTENDED_DATASET_PATH}...")
        try:
            df_ext = pd.read_csv(EXTENDED_DATASET_PATH)
            if 'Query' in df_ext.columns and 'Label' in df_ext.columns:
                df_ext = df_ext.rename(columns={'Query': 'text', 'Label': 'label'})
                df = pd.concat([df, df_ext], ignore_index=True)
                print(f"  Extended dataset added: {len(df_ext)} samples")
        except Exception as e:
            print(f"  Warning: Could not load extended dataset: {e}")

    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str)
    df['label'] = df['label'].astype(int)
    df = df.drop_duplicates(subset=['text'])
    print(f"  Total after merge + dedup: {len(df)}")

    n_inj = (df['label'] == 1).sum()
    n_safe = (df['label'] == 0).sum()
    print(f"  Injection: {n_inj}, Safe: {n_safe}")

    texts = df['text'].tolist()
    labels = df['label'].values

    print("Encoding texts as character sequences...")
    encoded = tokenizer.encode_batch(texts)
    print(f"  Encoded shape: {encoded.shape}")

    return encoded, labels


def train_epoch(model, dataloader, criterion, optimizer, device, max_grad_norm):
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    for batch_x, batch_y in dataloader:
        batch_x = batch_x.to(device)
        batch_y = batch_y.to(device)

        optimizer.zero_grad()
        output = model(batch_x).squeeze(-1)
        loss = criterion(output, batch_y)
        loss.backward()

        # Gradient clipping for LSTM stability
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)

        optimizer.step()

        total_loss += loss.item() * len(batch_y)
        all_preds.extend((output > 0.5).cpu().detach().numpy())
        all_labels.extend(batch_y.cpu().numpy())

    avg_loss = total_loss / len(all_labels)
    acc = accuracy_score(all_labels, all_preds)
    return avg_loss, acc


def evaluate(model, dataloader, criterion, device):
    model.eval()
    total_loss = 0
    all_preds = []
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for batch_x, batch_y in dataloader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)

            output = model(batch_x).squeeze(-1)
            loss = criterion(output, batch_y)

            total_loss += loss.item() * len(batch_y)
            all_probs.extend(output.cpu().numpy())
            all_preds.extend((output > 0.5).cpu().numpy())
            all_labels.extend(batch_y.cpu().numpy())

    avg_loss = total_loss / len(all_labels)
    metrics = compute_metrics(all_labels, all_preds, all_probs)
    metrics['loss'] = avg_loss
    return metrics


def compute_metrics(labels, preds, probs=None):
    m = {
        'accuracy': accuracy_score(labels, preds),
        'precision': precision_score(labels, preds, zero_division=0),
        'recall': recall_score(labels, preds, zero_division=0),
        'f1': f1_score(labels, preds, zero_division=0),
    }
    if probs is not None:
        try:
            m['roc_auc'] = roc_auc_score(labels, probs)
        except ValueError:
            m['roc_auc'] = 0.0
    cm = confusion_matrix(labels, preds)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        m['fpr'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        m['fnr'] = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return m


def main():
    print("=" * 60)
    print("CharBiLSTM Training — SQL Injection Detection")
    print(f"Device: {DEVICE}")
    print("=" * 60)

    tokenizer = CharTokenizer(max_length=MAX_LENGTH)
    print(f"Tokenizer: {tokenizer}")

    encoded, labels = load_data(tokenizer)

    X_train, X_temp, y_train, y_temp = train_test_split(
        encoded, labels, test_size=0.30, random_state=42, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\nSplit sizes:")
    print(f"  Train: {len(X_train)}")
    print(f"  Val:   {len(X_val)}")
    print(f"  Test:  {len(X_test)}")

    train_loader = DataLoader(SQLiDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(SQLiDataset(X_val, y_val), batch_size=BATCH_SIZE)
    test_loader = DataLoader(SQLiDataset(X_test, y_test), batch_size=BATCH_SIZE)

    model_config = {
        'vocab_size': tokenizer.vocab_size,
        'embed_dim': EMBED_DIM,
        'hidden_dim': HIDDEN_DIM,
        'num_layers': NUM_LAYERS,
        'fc_dim': FC_DIM,
        'dropout': DROPOUT,
    }

    model = CharBiLSTM(**model_config).to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel parameters: {total_params:,}")
    print(model)

    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', patience=3, factor=0.5
    )

    print("\n" + "=" * 60)
    print("Training...")
    print("=" * 60)

    best_val_f1 = 0.0
    patience_counter = 0
    training_log = []

    for epoch in range(1, MAX_EPOCHS + 1):
        start_time = time.time()

        train_loss, train_acc = train_epoch(
            model, train_loader, criterion, optimizer, DEVICE, MAX_GRAD_NORM
        )
        val_metrics = evaluate(model, val_loader, criterion, DEVICE)

        epoch_time = time.time() - start_time
        scheduler.step(val_metrics['loss'])

        log_entry = {
            'epoch': epoch,
            'train_loss': round(train_loss, 4),
            'train_acc': round(train_acc, 4),
            'val_loss': round(val_metrics['loss'], 4),
            'val_accuracy': round(val_metrics['accuracy'], 4),
            'val_precision': round(val_metrics['precision'], 4),
            'val_recall': round(val_metrics['recall'], 4),
            'val_f1': round(val_metrics['f1'], 4),
            'val_roc_auc': round(val_metrics.get('roc_auc', 0), 4),
            'val_fpr': round(val_metrics.get('fpr', 0), 4),
            'lr': optimizer.param_groups[0]['lr'],
            'time_s': round(epoch_time, 1),
        }
        training_log.append(log_entry)

        print(f"Epoch {epoch:2d}/{MAX_EPOCHS} | "
              f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} | "
              f"Val Loss: {val_metrics['loss']:.4f} "
              f"F1: {val_metrics['f1']:.4f} "
              f"AUC: {val_metrics.get('roc_auc', 0):.4f} | "
              f"{epoch_time:.1f}s", flush=True)

        if val_metrics['f1'] > best_val_f1:
            best_val_f1 = val_metrics['f1']
            patience_counter = 0
            model.save_checkpoint(str(MODEL_SAVE_PATH), model_config)
            print(f"  -> New best F1: {best_val_f1:.4f} — model saved")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"\nEarly stopping at epoch {epoch}")
                break

    # ─── Test Evaluation ───
    print("\n" + "=" * 60)
    print("Test Set Evaluation")
    print("=" * 60)

    best_model = CharBiLSTM.load_from_checkpoint(str(MODEL_SAVE_PATH), device=DEVICE)
    best_model = best_model.to(DEVICE)

    test_metrics = evaluate(best_model, test_loader, criterion, DEVICE)

    print(f"\nTest Results:")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1:        {test_metrics['f1']:.4f}")
    print(f"  ROC-AUC:   {test_metrics.get('roc_auc', 0):.4f}")
    print(f"  FPR:       {test_metrics.get('fpr', 0):.4f}")
    print(f"  FNR:       {test_metrics.get('fnr', 0):.4f}")

    # Save tokenizer if not already saved
    if not TOKENIZER_SAVE_PATH.exists():
        tokenizer.save(str(TOKENIZER_SAVE_PATH))

    # Save training log
    with open(LOG_PATH, 'w') as f:
        json.dump({
            'config': {
                'max_length': MAX_LENGTH,
                'embed_dim': EMBED_DIM,
                'hidden_dim': HIDDEN_DIM,
                'num_layers': NUM_LAYERS,
                'batch_size': BATCH_SIZE,
                'learning_rate': LEARNING_RATE,
                'device': DEVICE,
            },
            'epochs': training_log,
            'test_metrics': {k: round(v, 4) for k, v in test_metrics.items()},
        }, f, indent=2)

    print(f"\nModel saved to: {MODEL_SAVE_PATH}")
    print(f"Log saved to:   {LOG_PATH}")
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
