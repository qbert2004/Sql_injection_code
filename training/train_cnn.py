"""
Train Character-level CNN for SQL Injection Detection.

Usage:
    python training/train_cnn.py

Output:
    models/char_cnn_detector.pt   — PyTorch model checkpoint
    models/char_tokenizer.json    — Tokenizer configuration
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
    roc_auc_score, confusion_matrix, classification_report,
)

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models.char_tokenizer import CharTokenizer
from models.char_cnn_model import CharCNN

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

DATASET_PATH = PROJECT_ROOT / "data" / "dataset.csv"
MODEL_SAVE_PATH = PROJECT_ROOT / "models" / "char_cnn_detector.pt"
TOKENIZER_SAVE_PATH = PROJECT_ROOT / "models" / "char_tokenizer.json"
LOG_PATH = PROJECT_ROOT / "training" / "cnn_training_log.json"

# Extended dataset (set to None to skip for faster training)
EXTENDED_DATASET_PATH = PROJECT_ROOT / "SQL_Dataset_Extended.csv"
USE_EXTENDED_DATASET = True  # Set to True to include SQL_Dataset_Extended.csv

# Hyperparameters
MAX_LENGTH = 200
EMBED_DIM = 32
NUM_FILTERS_1 = 64
NUM_FILTERS_2 = 128
NUM_FILTERS_3 = 128
KERNEL_SIZE = 3
HIDDEN_DIM = 64
DROPOUT = 0.3

BATCH_SIZE = 256
LEARNING_RATE = 1e-3
WEIGHT_DECAY = 1e-5
MAX_EPOCHS = 10
PATIENCE = 3  # Early stopping patience

DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'


# ═══════════════════════════════════════════════════════════════════
# DATASET
# ═══════════════════════════════════════════════════════════════════

class SQLiDataset(Dataset):
    """PyTorch Dataset for SQL injection samples."""

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

    # Optionally load extended dataset
    if USE_EXTENDED_DATASET and EXTENDED_DATASET_PATH.exists():
        print(f"Loading extended dataset from {EXTENDED_DATASET_PATH}...")
        try:
            df_ext = pd.read_csv(EXTENDED_DATASET_PATH)
            # Rename columns to match: Query -> text, Label -> label
            if 'Query' in df_ext.columns and 'Label' in df_ext.columns:
                df_ext = df_ext.rename(columns={'Query': 'text', 'Label': 'label'})
                df = pd.concat([df, df_ext], ignore_index=True)
                print(f"  Extended dataset added: {len(df_ext)} samples")
        except Exception as e:
            print(f"  Warning: Could not load extended dataset: {e}")

    # Clean up
    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str)
    df['label'] = df['label'].astype(int)
    df = df.drop_duplicates(subset=['text'])
    print(f"  Total after merge + dedup: {len(df)}")

    # Label distribution
    n_inj = (df['label'] == 1).sum()
    n_safe = (df['label'] == 0).sum()
    print(f"  Injection: {n_inj}, Safe: {n_safe}, Ratio: {n_inj / len(df):.2%}")

    texts = df['text'].tolist()
    labels = df['label'].values

    # Encode
    print("Encoding texts as character sequences...")
    encoded = tokenizer.encode_batch(texts)
    print(f"  Encoded shape: {encoded.shape}")

    return encoded, labels


def train_epoch(model, dataloader, criterion, optimizer, device):
    """Train for one epoch."""
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
        optimizer.step()

        total_loss += loss.item() * len(batch_y)
        all_preds.extend((output > 0.5).cpu().numpy())
        all_labels.extend(batch_y.cpu().numpy())

    avg_loss = total_loss / len(all_labels)
    acc = accuracy_score(all_labels, all_preds)
    return avg_loss, acc


def evaluate(model, dataloader, criterion, device):
    """Evaluate model on a dataset."""
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
    """Compute classification metrics."""
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
    print("CharCNN Training — SQL Injection Detection")
    print(f"Device: {DEVICE}")
    print("=" * 60)

    # Initialize tokenizer
    tokenizer = CharTokenizer(max_length=MAX_LENGTH)
    print(f"Tokenizer: {tokenizer}")

    # Load data
    encoded, labels = load_data(tokenizer)

    # Split: 70% train, 15% val, 15% test (stratified)
    X_train, X_temp, y_train, y_temp = train_test_split(
        encoded, labels, test_size=0.30, random_state=42, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\nSplit sizes:")
    print(f"  Train: {len(X_train)} (inj: {y_train.sum()}, safe: {(y_train == 0).sum()})")
    print(f"  Val:   {len(X_val)} (inj: {y_val.sum()}, safe: {(y_val == 0).sum()})")
    print(f"  Test:  {len(X_test)} (inj: {y_test.sum()}, safe: {(y_test == 0).sum()})")

    # Create dataloaders
    train_dataset = SQLiDataset(X_train, y_train)
    val_dataset = SQLiDataset(X_val, y_val)
    test_dataset = SQLiDataset(X_test, y_test)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)

    # Compute class weights for imbalanced data
    n_pos = y_train.sum()
    n_neg = len(y_train) - n_pos
    pos_weight = torch.FloatTensor([n_neg / n_pos]).to(DEVICE)
    print(f"\nClass weight (pos_weight): {pos_weight.item():.3f}")

    # Initialize model
    model_config = {
        'vocab_size': tokenizer.vocab_size,
        'embed_dim': EMBED_DIM,
        'num_filters_1': NUM_FILTERS_1,
        'num_filters_2': NUM_FILTERS_2,
        'num_filters_3': NUM_FILTERS_3,
        'kernel_size': KERNEL_SIZE,
        'hidden_dim': HIDDEN_DIM,
        'dropout': DROPOUT,
    }

    model = CharCNN(**model_config).to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel parameters: {total_params:,}")
    print(model)

    # Loss, optimizer, scheduler
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    # Since we use BCEWithLogitsLoss, we need to remove the sigmoid from the model
    # Actually, let's use BCELoss with the sigmoid already in the model
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', patience=3, factor=0.5
    )

    # Training loop
    print("\n" + "=" * 60)
    print("Training...")
    print("=" * 60)

    best_val_f1 = 0.0
    patience_counter = 0
    training_log = []

    for epoch in range(1, MAX_EPOCHS + 1):
        start_time = time.time()

        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, DEVICE)
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
              f"{epoch_time:.1f}s")

        # Early stopping on val F1
        if val_metrics['f1'] > best_val_f1:
            best_val_f1 = val_metrics['f1']
            patience_counter = 0
            # Save best model
            model.save_checkpoint(str(MODEL_SAVE_PATH), model_config)
            print(f"  -> New best F1: {best_val_f1:.4f} — model saved")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"\nEarly stopping at epoch {epoch} (no improvement for {PATIENCE} epochs)")
                break

    # ─── Final Evaluation on Test Set ───
    print("\n" + "=" * 60)
    print("Test Set Evaluation")
    print("=" * 60)

    # Load best model
    best_model = CharCNN.load_from_checkpoint(str(MODEL_SAVE_PATH), device=DEVICE)
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

    # Save tokenizer
    tokenizer.save(str(TOKENIZER_SAVE_PATH))
    print(f"\nTokenizer saved to: {TOKENIZER_SAVE_PATH}")
    print(f"Model saved to:     {MODEL_SAVE_PATH}")

    # Save training log
    with open(LOG_PATH, 'w') as f:
        json.dump({
            'config': {
                'max_length': MAX_LENGTH,
                'embed_dim': EMBED_DIM,
                'batch_size': BATCH_SIZE,
                'learning_rate': LEARNING_RATE,
                'device': DEVICE,
            },
            'epochs': training_log,
            'test_metrics': {k: round(v, 4) for k, v in test_metrics.items()},
        }, f, indent=2)
    print(f"Training log saved to: {LOG_PATH}")

    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)

    return test_metrics


if __name__ == '__main__':
    main()
