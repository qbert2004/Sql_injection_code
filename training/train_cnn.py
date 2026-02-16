"""
Train VDCNN (Very Deep CNN) for SQL Injection Detection.

Based on: Conneau et al. 2017 — "Very Deep Convolutional Networks for Text Classification"

Key changes from previous training pipeline:
    - VDCNN architecture with residual connections (depth 9/17/29)
    - SGD optimizer with momentum 0.9 (per VDCNN paper)
    - Learning rate 0.01 with StepLR decay
    - Gradient clipping max_norm=7.0
    - Mixed precision (AMP) for CUDA acceleration
    - Online data augmentation for injection samples
    - Kaiming (He) weight initialization
    - Label smoothing 0.05

Usage:
    python training/train_cnn.py
    python training/train_cnn.py --depth 17
    python training/train_cnn.py --depth 29 --epochs 50

Output:
    models/char_cnn_detector.pt   — PyTorch model checkpoint
    models/char_tokenizer.json    — Tokenizer configuration
    training/cnn_training_log.json — Per-epoch metrics
"""

import sys
import json
import time
import random
import argparse
from pathlib import Path
from urllib.parse import quote as url_quote

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
from models.char_cnn_model import CharCNN


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

DATASET_PATH = PROJECT_ROOT / "data" / "dataset.csv"
MODEL_SAVE_PATH = PROJECT_ROOT / "models" / "char_cnn_detector.pt"
TOKENIZER_SAVE_PATH = PROJECT_ROOT / "models" / "char_tokenizer.json"
LOG_PATH = PROJECT_ROOT / "training" / "cnn_training_log.json"

# Extended dataset
EXTENDED_DATASET_PATH = PROJECT_ROOT / "SQL_Dataset_Extended.csv"
USE_EXTENDED_DATASET = True

# VDCNN Model hyperparameters
MAX_LENGTH = 200
EMBED_DIM = 16          # VDCNN standard: 16-dim embeddings
DEPTH = 9               # VDCNN depth: 9, 17, 29, or 49
K_MAX = 8               # k-max pooling
FC_DIM = 1024           # Fully connected hidden dimension (reduced for our dataset)

# Training hyperparameters (tuned for our dataset)
BATCH_SIZE = 128        # VDCNN paper standard
LEARNING_RATE = 0.001   # Lower LR for stable convergence (was 0.01)
MOMENTUM = 0.9          # SGD momentum
WEIGHT_DECAY = 1e-4     # L2 regularization
MAX_EPOCHS = 50         # More epochs with early stopping
PATIENCE = 10           # Early stopping patience (increased from 7)
GRAD_CLIP_NORM = 5.0    # Gradient clipping (reduced from 7.0)
LR_DECAY_STEP = 5       # Decay LR every N epochs (was 3)
LR_DECAY_GAMMA = 0.5    # LR decay factor (more aggressive)
LABEL_SMOOTHING = 0.05  # Prevent overconfidence
AUGMENT_PROB = 0.3      # Augmentation probability for injection samples

DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'


# ═══════════════════════════════════════════════════════════════════
# DATA AUGMENTATION
# ═══════════════════════════════════════════════════════════════════

class SQLiAugmenter:
    """Online data augmentation for SQL injection samples.

    Applies random transformations to injection payloads to improve
    model robustness against obfuscation techniques.

    Augmentations (applied with probability `prob`):
        1. Random case swap: 'UNION' → 'uNiOn'
        2. Random whitespace: 'OR' → 'O R', '  OR'
        3. Comment insertion: 'OR' → 'O/**/R'
        4. URL encoding: random chars → %HH
    """

    def __init__(self, prob: float = 0.3):
        self.prob = prob

    def augment(self, text: str, is_injection: bool) -> str:
        """Augment text. Only injection samples are augmented."""
        if not is_injection or random.random() > self.prob:
            return text

        # Choose one augmentation randomly
        aug_type = random.choice(['case', 'whitespace', 'comment', 'url_encode'])

        if aug_type == 'case':
            return self._random_case(text)
        elif aug_type == 'whitespace':
            return self._random_whitespace(text)
        elif aug_type == 'comment':
            return self._comment_insert(text)
        elif aug_type == 'url_encode':
            return self._url_encode_random(text)
        return text

    @staticmethod
    def _random_case(text: str) -> str:
        """Randomly swap character case."""
        result = []
        for c in text:
            if c.isalpha() and random.random() < 0.3:
                c = c.swapcase()
            result.append(c)
        return ''.join(result)

    @staticmethod
    def _random_whitespace(text: str) -> str:
        """Insert random whitespace between characters."""
        result = []
        for c in text:
            result.append(c)
            if c == ' ' and random.random() < 0.2:
                result.append(' ')
            elif c.isalpha() and random.random() < 0.05:
                result.append(' ')
        return ''.join(result)

    @staticmethod
    def _comment_insert(text: str) -> str:
        """Insert SQL comments between keywords."""
        # Simple: replace some spaces with /**/
        if ' ' in text and random.random() < 0.5:
            parts = text.split(' ')
            idx = random.randint(0, len(parts) - 2)
            parts[idx] = parts[idx] + '/**/'
            return ' '.join(parts)
        return text

    @staticmethod
    def _url_encode_random(text: str) -> str:
        """URL-encode random characters."""
        result = []
        for c in text:
            if c.isalpha() and random.random() < 0.15:
                result.append(f'%{ord(c):02X}')
            else:
                result.append(c)
        return ''.join(result)


# ═══════════════════════════════════════════════════════════════════
# DATASET
# ═══════════════════════════════════════════════════════════════════

class SQLiDataset(Dataset):
    """PyTorch Dataset for SQL injection samples with optional augmentation."""

    def __init__(self, texts: list, labels: np.ndarray,
                 tokenizer: CharTokenizer, augmenter: SQLiAugmenter = None):
        self.texts = texts
        self.labels = torch.FloatTensor(labels)
        self.tokenizer = tokenizer
        self.augmenter = augmenter

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]

        # Apply augmentation during training
        if self.augmenter is not None:
            text = self.augmenter.augment(text, is_injection=bool(label > 0.5))

        # Encode with padding/truncation to fixed length
        tokens = self.tokenizer.encode(text)
        max_len = self.tokenizer.max_length
        if len(tokens) > max_len:
            tokens = tokens[:max_len]
        elif len(tokens) < max_len:
            tokens = tokens + [0] * (max_len - len(tokens))

        return torch.LongTensor(tokens), label


class SQLiDatasetPreEncoded(Dataset):
    """Pre-encoded dataset for faster validation/test."""

    def __init__(self, encoded: np.ndarray, labels: np.ndarray):
        self.encoded = torch.LongTensor(encoded)
        self.labels = torch.FloatTensor(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.encoded[idx], self.labels[idx]


# ═══════════════════════════════════════════════════════════════════
# LABEL SMOOTHING BCE LOSS
# ═══════════════════════════════════════════════════════════════════

class LabelSmoothingBCEWithLogitsLoss(nn.Module):
    """Binary Cross-Entropy with Logits and label smoothing.

    Accepts raw logits (before sigmoid) for numerical stability,
    especially critical under mixed precision (AMP) where float16
    sigmoid saturates to 0/1 causing -log(0) = inf in BCELoss.

    Replaces hard targets (0, 1) with soft targets
    (smoothing/2, 1 - smoothing/2) to prevent overconfidence.
    """

    def __init__(self, smoothing: float = 0.05):
        super().__init__()
        self.smoothing = smoothing
        self.bce_logits = nn.BCEWithLogitsLoss()

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        target_smooth = target * (1.0 - self.smoothing) + 0.5 * self.smoothing
        return self.bce_logits(logits, target_smooth)


# ═══════════════════════════════════════════════════════════════════
# TRAINING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def load_data(tokenizer: CharTokenizer):
    """Load dataset, return texts and labels."""
    print(f"Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"  Synthetic dataset: {len(df)} samples")

    # Optionally load extended dataset
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

    return texts, labels


def train_epoch(model, dataloader, criterion, optimizer, device, scaler=None):
    """Train for one epoch with optional mixed precision.

    Model returns raw logits; criterion is BCEWithLogitsLoss.
    Predictions use logits > 0.0 (equivalent to sigmoid > 0.5).
    """
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    for batch_x, batch_y in dataloader:
        batch_x = batch_x.to(device)
        batch_y = batch_y.to(device)

        optimizer.zero_grad()

        if scaler is not None:
            # Mixed precision: forward + loss BOTH inside autocast
            # BCEWithLogitsLoss is safe under autocast (log-sum-exp, no log(0))
            with torch.amp.autocast('cuda'):
                logits = model(batch_x).squeeze(-1)
                loss = criterion(logits, batch_y)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_NORM)
            scaler.step(optimizer)
            scaler.update()
        else:
            logits = model(batch_x).squeeze(-1)
            loss = criterion(logits, batch_y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP_NORM)
            optimizer.step()

        total_loss += loss.item() * len(batch_y)
        # logits > 0.0 == sigmoid(logits) > 0.5
        all_preds.extend((logits.detach() > 0.0).cpu().numpy())
        all_labels.extend(batch_y.cpu().numpy())

    avg_loss = total_loss / len(all_labels)
    acc = accuracy_score(all_labels, all_preds)
    return avg_loss, acc


def evaluate(model, dataloader, criterion, device):
    """Evaluate model on a dataset.

    Model returns logits; we apply sigmoid for ROC-AUC (needs probabilities).
    Predictions use logits > 0.0 (equivalent to sigmoid > 0.5).
    """
    model.eval()
    total_loss = 0
    all_preds = []
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for batch_x, batch_y in dataloader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)

            logits = model(batch_x).squeeze(-1)
            loss = criterion(logits, batch_y)

            # Convert logits -> probabilities for ROC-AUC
            probs = torch.sigmoid(logits)

            total_loss += loss.item() * len(batch_y)
            all_probs.extend(probs.cpu().numpy())
            all_preds.extend((logits > 0.0).cpu().numpy())
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


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(description='Train VDCNN for SQL Injection Detection')
    parser.add_argument('--depth', type=int, default=DEPTH,
                        choices=[9, 17, 29, 49],
                        help='VDCNN depth (9/17/29/49)')
    parser.add_argument('--epochs', type=int, default=MAX_EPOCHS,
                        help='Maximum training epochs')
    parser.add_argument('--batch-size', type=int, default=BATCH_SIZE,
                        help='Training batch size')
    parser.add_argument('--lr', type=float, default=LEARNING_RATE,
                        help='Initial learning rate')
    parser.add_argument('--no-augment', action='store_true',
                        help='Disable data augmentation')
    parser.add_argument('--no-amp', action='store_true',
                        help='Disable mixed precision (AMP)')
    return parser.parse_args()


def main():
    args = parse_args()

    depth = args.depth
    max_epochs = args.epochs
    batch_size = args.batch_size
    lr = args.lr
    use_augment = not args.no_augment
    use_amp = not args.no_amp and DEVICE == 'cuda'

    print("=" * 70)
    print("VDCNN Training -- SQL Injection Detection")
    print(f"  Architecture: VDCNN-{depth}")
    print(f"  Device: {DEVICE}")
    print(f"  Mixed Precision (AMP): {use_amp}")
    print(f"  Data Augmentation: {use_augment}")
    print(f"  Batch size: {batch_size}")
    print(f"  Learning rate: {lr}")
    print(f"  Gradient clipping: {GRAD_CLIP_NORM}")
    print(f"  Label smoothing: {LABEL_SMOOTHING}")
    print("=" * 70)

    # Initialize tokenizer
    tokenizer = CharTokenizer(max_length=MAX_LENGTH)
    print(f"\nTokenizer: vocab={tokenizer.vocab_size}, max_len={tokenizer.max_length}")

    # Load data
    texts, labels = load_data(tokenizer)

    # Split: 70% train, 15% val, 15% test (stratified)
    texts_train, texts_temp, y_train, y_temp = train_test_split(
        texts, labels, test_size=0.30, random_state=42, stratify=labels
    )
    texts_val, texts_test, y_val, y_test = train_test_split(
        texts_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\nData split:")
    print(f"  Train: {len(texts_train):,} (inj: {y_train.sum():,}, safe: {(y_train == 0).sum():,})")
    print(f"  Val:   {len(texts_val):,} (inj: {y_val.sum():,}, safe: {(y_val == 0).sum():,})")
    print(f"  Test:  {len(texts_test):,} (inj: {y_test.sum():,}, safe: {(y_test == 0).sum():,})")

    # Create augmenter
    augmenter = SQLiAugmenter(prob=AUGMENT_PROB) if use_augment else None

    # Create datasets
    # Train: augmented, tokenized on-the-fly
    train_dataset = SQLiDataset(texts_train, y_train, tokenizer, augmenter=augmenter)
    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True,
        num_workers=0, pin_memory=(DEVICE == 'cuda')
    )

    # Val/Test: pre-encoded for speed
    val_encoded = tokenizer.encode_batch(texts_val)
    test_encoded = tokenizer.encode_batch(texts_test)
    val_dataset = SQLiDatasetPreEncoded(val_encoded, y_val)
    test_dataset = SQLiDatasetPreEncoded(test_encoded, y_test)
    val_loader = DataLoader(val_dataset, batch_size=batch_size * 2,
                            pin_memory=(DEVICE == 'cuda'))
    test_loader = DataLoader(test_dataset, batch_size=batch_size * 2,
                             pin_memory=(DEVICE == 'cuda'))

    # ─── Initialize Model ───
    model_config = {
        'vocab_size': tokenizer.vocab_size,
        'embed_dim': EMBED_DIM,
        'depth': depth,
        'k_max': K_MAX,
        'fc_dim': FC_DIM,
        'num_classes': 1,
        'shortcut': True,
    }

    model = CharCNN(**model_config).to(DEVICE)
    print(f"\nModel: {repr(model)}")
    print(f"Parameters: {model.count_parameters():,}")

    # ─── Loss, Optimizer, Scheduler ───
    # BCEWithLogitsLoss = sigmoid + BCE in one numerically stable op.
    # Critical fix: BCELoss fails under AMP because float16 sigmoid
    # saturates to 0/1, causing -log(0) = inf → loss ≈ 54, model stuck.
    criterion = nn.BCEWithLogitsLoss()

    # AdamW optimizer (more stable than SGD for our dataset size)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=lr,
        weight_decay=WEIGHT_DECAY,
    )

    # CosineAnnealing scheduler — smooth LR decay
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=max_epochs, eta_min=1e-6
    )

    # Mixed precision scaler
    scaler = torch.amp.GradScaler('cuda') if use_amp else None

    # ─── Training Loop ───
    print("\n" + "=" * 70)
    print("Training...")
    print("=" * 70)

    best_val_f1 = 0.0
    patience_counter = 0
    training_log = []
    total_start = time.time()

    for epoch in range(1, max_epochs + 1):
        epoch_start = time.time()

        # Train
        train_loss, train_acc = train_epoch(
            model, train_loader, criterion, optimizer, DEVICE, scaler
        )

        # Validate
        val_metrics = evaluate(model, val_loader, criterion, DEVICE)

        # Step scheduler
        scheduler.step()

        epoch_time = time.time() - epoch_start
        current_lr = optimizer.param_groups[0]['lr']

        # Log
        log_entry = {
            'epoch': epoch,
            'train_loss': round(train_loss, 6),
            'train_acc': round(train_acc, 4),
            'val_loss': round(val_metrics['loss'], 6),
            'val_accuracy': round(val_metrics['accuracy'], 4),
            'val_precision': round(val_metrics['precision'], 4),
            'val_recall': round(val_metrics['recall'], 4),
            'val_f1': round(val_metrics['f1'], 4),
            'val_roc_auc': round(val_metrics.get('roc_auc', 0), 4),
            'val_fpr': round(val_metrics.get('fpr', 0), 6),
            'val_fnr': round(val_metrics.get('fnr', 0), 6),
            'lr': current_lr,
            'time_s': round(epoch_time, 1),
        }
        training_log.append(log_entry)

        # Print progress
        print(
            f"Epoch {epoch:3d}/{max_epochs} | "
            f"Loss: {train_loss:.4f}/{val_metrics['loss']:.4f} | "
            f"Acc: {train_acc:.4f}/{val_metrics['accuracy']:.4f} | "
            f"F1: {val_metrics['f1']:.4f} | "
            f"AUC: {val_metrics.get('roc_auc', 0):.4f} | "
            f"FPR: {val_metrics.get('fpr', 0):.4f} | "
            f"LR: {current_lr:.6f} | "
            f"{epoch_time:.1f}s"
        )

        # Early stopping on val F1
        if val_metrics['f1'] > best_val_f1:
            best_val_f1 = val_metrics['f1']
            patience_counter = 0
            model.save_checkpoint(str(MODEL_SAVE_PATH), model_config)
            print(f"  * New best F1: {best_val_f1:.4f} -- checkpoint saved")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"\n[STOP] Early stopping at epoch {epoch} "
                      f"(no improvement for {PATIENCE} epochs)")
                break

    total_time = time.time() - total_start
    print(f"\nTotal training time: {total_time:.1f}s ({total_time / 60:.1f} min)")

    # ─── Final Evaluation on Test Set ───
    print("\n" + "=" * 70)
    print("Test Set Evaluation (Best Model)")
    print("=" * 70)

    best_model = CharCNN.load_from_checkpoint(str(MODEL_SAVE_PATH), device=DEVICE)
    best_model = best_model.to(DEVICE)

    test_metrics = evaluate(best_model, test_loader, criterion, DEVICE)

    print(f"\n  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1:        {test_metrics['f1']:.4f}")
    print(f"  ROC-AUC:   {test_metrics.get('roc_auc', 0):.4f}")
    print(f"  FPR:       {test_metrics.get('fpr', 0):.6f}")
    print(f"  FNR:       {test_metrics.get('fnr', 0):.6f}")
    print(f"  Loss:      {test_metrics['loss']:.6f}")

    # Save tokenizer
    tokenizer.save(str(TOKENIZER_SAVE_PATH))
    print(f"\nTokenizer: {TOKENIZER_SAVE_PATH}")
    print(f"Model:     {MODEL_SAVE_PATH}")

    # Save training log
    final_log = {
        'architecture': f'VDCNN-{depth}',
        'paper': 'Conneau et al. 2017 — Very Deep Convolutional Networks for Text Classification',
        'config': {
            'depth': depth,
            'max_length': MAX_LENGTH,
            'embed_dim': EMBED_DIM,
            'k_max': K_MAX,
            'fc_dim': FC_DIM,
            'batch_size': batch_size,
            'learning_rate': lr,
            'optimizer': 'AdamW',
            'momentum': MOMENTUM,
            'weight_decay': WEIGHT_DECAY,
            'grad_clip_norm': GRAD_CLIP_NORM,
            'criterion': 'BCEWithLogitsLoss',
            'label_smoothing': LABEL_SMOOTHING,
            'augmentation': use_augment,
            'augment_prob': AUGMENT_PROB,
            'mixed_precision': use_amp,
            'device': DEVICE,
            'total_params': model.count_parameters(),
        },
        'data': {
            'train_size': len(texts_train),
            'val_size': len(texts_val),
            'test_size': len(texts_test),
        },
        'epochs': training_log,
        'best_val_f1': round(best_val_f1, 4),
        'test_metrics': {k: round(v, 6) for k, v in test_metrics.items()},
        'total_training_time_s': round(total_time, 1),
    }

    with open(LOG_PATH, 'w') as f:
        json.dump(final_log, f, indent=2)
    print(f"Log:       {LOG_PATH}")

    print("\n" + "=" * 70)
    print(f"[OK] VDCNN-{depth} Training Complete!")
    print(f"  Best val F1: {best_val_f1:.4f}")
    print(f"  Test accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  Test FPR: {test_metrics.get('fpr', 0):.6f}")
    print("=" * 70)

    return test_metrics


if __name__ == '__main__':
    main()
