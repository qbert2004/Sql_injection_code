"""
CUDA Benchmark for VDCNN SQL Injection Detector.

Tests ONLY the CNN model (not ensemble) on the 100k+ massive test dataset.
Uses CUDA for inference if available, falls back to CPU.

Outputs:
    - Accuracy, F1, FPR, FNR
    - Per-category breakdown
    - Confusion matrix
    - Throughput (samples/sec)
    - Misclassified samples → benchmark_results.json

Usage:
    python tests/benchmark_cnn_cuda.py
    python tests/benchmark_cnn_cuda.py --batch-size 2048
    python tests/benchmark_cnn_cuda.py --threshold 0.5

Criteria:
    | Metric     | Minimum | Target |
    |------------|---------|--------|
    | Accuracy   | ≥90%    | ≥95%   |
    | FP Rate    | ≤10%    | ≤5%    |
    | FN Rate    | ≤10%    | ≤5%    |
    | Throughput  | ≥10k/s | ≥50k/s |
"""

import sys
import json
import time
import argparse
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models.char_tokenizer import CharTokenizer
from models.char_cnn_model import CharCNN


# ═══════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════

MODEL_PATH = PROJECT_ROOT / "models" / "char_cnn_detector.pt"
TOKENIZER_PATH = PROJECT_ROOT / "models" / "char_tokenizer.json"
TEST_DATA_PATH = PROJECT_ROOT / "data" / "massive_test_100k.csv"
RESULTS_PATH = PROJECT_ROOT / "benchmark_results.json"
MISCLASSIFIED_PATH = PROJECT_ROOT / "benchmark_misclassified.csv"


# ═══════════════════════════════════════════════════════════════════
# DATASET
# ═══════════════════════════════════════════════════════════════════

class BenchmarkDataset(Dataset):
    """Pre-encoded dataset for fast benchmark inference."""

    def __init__(self, encoded: np.ndarray, labels: np.ndarray):
        self.encoded = torch.LongTensor(encoded)
        self.labels = torch.FloatTensor(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.encoded[idx], self.labels[idx]


# ═══════════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════════

def compute_metrics(labels, preds, probs=None):
    """Compute comprehensive classification metrics."""
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix, matthews_corrcoef,
    )

    m = {
        'accuracy': accuracy_score(labels, preds),
        'precision': precision_score(labels, preds, zero_division=0),
        'recall': recall_score(labels, preds, zero_division=0),
        'f1': f1_score(labels, preds, zero_division=0),
        'mcc': matthews_corrcoef(labels, preds),
    }

    if probs is not None:
        try:
            m['roc_auc'] = roc_auc_score(labels, probs)
        except ValueError:
            m['roc_auc'] = 0.0

    cm = confusion_matrix(labels, preds)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        m['true_positive'] = int(tp)
        m['true_negative'] = int(tn)
        m['false_positive'] = int(fp)
        m['false_negative'] = int(fn)
        m['fpr'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        m['fnr'] = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        m['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    return m


def per_category_metrics(texts, labels, preds, probs, categories):
    """Compute metrics per injection/safe category."""
    cat_data = defaultdict(lambda: {'labels': [], 'preds': [], 'probs': [], 'texts': []})

    for text, label, pred, prob, cat in zip(texts, labels, preds, probs, categories):
        cat_data[cat]['labels'].append(label)
        cat_data[cat]['preds'].append(pred)
        cat_data[cat]['probs'].append(prob)
        cat_data[cat]['texts'].append(text)

    results = {}
    for cat, data in sorted(cat_data.items()):
        y = np.array(data['labels'])
        p = np.array(data['preds'])
        total = len(y)
        correct = (y == p).sum()
        acc = correct / total if total > 0 else 0

        # For injection categories: FN = missed attacks
        # For safe categories: FP = false alarms
        if y.mean() > 0.5:  # Mostly injection
            fn = ((y == 1) & (p == 0)).sum()
            results[cat] = {
                'total': total,
                'correct': int(correct),
                'accuracy': round(acc, 4),
                'missed (FN)': int(fn),
                'miss_rate': round(fn / total, 4) if total > 0 else 0,
            }
        else:  # Mostly safe
            fp = ((y == 0) & (p == 1)).sum()
            results[cat] = {
                'total': total,
                'correct': int(correct),
                'accuracy': round(acc, 4),
                'false_alarms (FP)': int(fp),
                'false_alarm_rate': round(fp / total, 4) if total > 0 else 0,
            }

    return results


# ═══════════════════════════════════════════════════════════════════
# INFERENCE
# ═══════════════════════════════════════════════════════════════════

@torch.no_grad()
def run_inference(model, dataloader, device):
    """Run inference on full dataset. Returns predictions, probabilities."""
    model.eval()
    all_probs = []

    for batch_x, _ in dataloader:
        batch_x = batch_x.to(device)
        output = model.predict(batch_x).squeeze(-1)
        all_probs.extend(output.cpu().numpy())

    return np.array(all_probs)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(description='VDCNN CUDA Benchmark')
    parser.add_argument('--batch-size', type=int, default=2048,
                        help='Inference batch size (default: 2048)')
    parser.add_argument('--threshold', type=float, default=0.5,
                        help='Classification threshold (default: 0.5)')
    parser.add_argument('--model-path', type=str, default=str(MODEL_PATH),
                        help='Path to model checkpoint')
    parser.add_argument('--test-data', type=str, default=str(TEST_DATA_PATH),
                        help='Path to test data CSV')
    parser.add_argument('--save-misclassified', action='store_true', default=True,
                        help='Save misclassified samples to CSV')
    parser.add_argument('--max-misclassified', type=int, default=5000,
                        help='Max misclassified samples to save (default: 5000)')
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 70)
    print("VDCNN CUDA Benchmark — SQL Injection Detection")
    print("=" * 70)

    # ─── Device ───
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Device: {device}")
    if device == 'cuda':
        print(f"  GPU: {torch.cuda.get_device_name(0)}")
        print(f"  VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")

    # ─── Load Model ───
    print(f"\nLoading model from {args.model_path}...")
    if not Path(args.model_path).exists():
        print(f"ERROR: Model file not found: {args.model_path}")
        print("Train the model first: python training/train_cnn.py")
        sys.exit(1)

    model = CharCNN.load_from_checkpoint(args.model_path, device=device)
    model = model.to(device)
    model.eval()
    print(f"  Model: {repr(model)}")

    # ─── Load Tokenizer ───
    tokenizer = CharTokenizer(max_length=200)
    if Path(str(TOKENIZER_PATH)).exists():
        tokenizer = CharTokenizer.load(str(TOKENIZER_PATH))
    print(f"  Tokenizer: vocab={tokenizer.vocab_size}, max_len={tokenizer.max_length}")

    # ─── Load Test Data ───
    print(f"\nLoading test data from {args.test_data}...")
    if not Path(args.test_data).exists():
        print(f"ERROR: Test data not found: {args.test_data}")
        print("Generate test data first: python tests/generate_massive_test.py")
        sys.exit(1)

    df = pd.read_csv(args.test_data)
    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str)
    df['label'] = df['label'].astype(int)

    texts = df['text'].tolist()
    labels = df['label'].values
    categories = df['category'].tolist() if 'category' in df.columns else ['unknown'] * len(texts)

    n_inj = (labels == 1).sum()
    n_safe = (labels == 0).sum()
    print(f"  Total samples: {len(texts):,}")
    print(f"  Injection: {n_inj:,} | Safe: {n_safe:,}")

    # ─── Encode ───
    print("\nEncoding texts...")
    encode_start = time.time()
    encoded = tokenizer.encode_batch(texts)
    encode_time = time.time() - encode_start
    print(f"  Encoding time: {encode_time:.1f}s ({len(texts) / encode_time:,.0f} samples/sec)")

    dataset = BenchmarkDataset(encoded, labels)
    dataloader = DataLoader(
        dataset, batch_size=args.batch_size,
        shuffle=False, pin_memory=(device == 'cuda'),
        num_workers=0,
    )

    # ─── Warmup (for CUDA) ───
    if device == 'cuda':
        print("\nCUDA warmup...")
        dummy = torch.zeros(1, 200, dtype=torch.long).to(device)
        for _ in range(3):
            _ = model(dummy)
        torch.cuda.synchronize()

    # ─── Inference ───
    print(f"\nRunning inference (batch_size={args.batch_size})...")
    infer_start = time.time()

    probs = run_inference(model, dataloader, device)

    if device == 'cuda':
        torch.cuda.synchronize()
    infer_time = time.time() - infer_start
    throughput = len(texts) / infer_time

    preds = (probs > args.threshold).astype(int)

    print(f"  Inference time: {infer_time:.2f}s")
    print(f"  Throughput: {throughput:,.0f} samples/sec")

    # ─── Overall Metrics ───
    print("\n" + "=" * 70)
    print("OVERALL METRICS")
    print("=" * 70)

    metrics = compute_metrics(labels, preds, probs)

    print(f"  Accuracy:    {metrics['accuracy']:.4f}")
    print(f"  Precision:   {metrics['precision']:.4f}")
    print(f"  Recall:      {metrics['recall']:.4f}")
    print(f"  F1:          {metrics['f1']:.4f}")
    print(f"  ROC-AUC:     {metrics.get('roc_auc', 0):.4f}")
    print(f"  MCC:         {metrics['mcc']:.4f}")
    print(f"  Specificity: {metrics.get('specificity', 0):.4f}")
    print(f"  FPR:         {metrics.get('fpr', 0):.4f} (target: ≤0.05)")
    print(f"  FNR:         {metrics.get('fnr', 0):.4f} (target: ≤0.05)")
    print(f"\n  Confusion Matrix:")
    print(f"    TP: {metrics.get('true_positive', 0):,}  FP: {metrics.get('false_positive', 0):,}")
    print(f"    FN: {metrics.get('false_negative', 0):,}  TN: {metrics.get('true_negative', 0):,}")

    # ─── Per-Category Metrics ───
    print("\n" + "=" * 70)
    print("PER-CATEGORY BREAKDOWN")
    print("=" * 70)

    cat_metrics = per_category_metrics(texts, labels, preds, probs, categories)

    print(f"\n{'Category':<25} {'Total':>7} {'Correct':>8} {'Acc':>7} {'Errors':>8} {'Rate':>7}")
    print("-" * 70)

    for cat, m in sorted(cat_metrics.items()):
        if 'missed (FN)' in m:
            errors = m['missed (FN)']
            rate = m['miss_rate']
            label = 'FN'
        else:
            errors = m['false_alarms (FP)']
            rate = m['false_alarm_rate']
            label = 'FP'
        print(f"  {cat:<23} {m['total']:>7,} {m['correct']:>8,} {m['accuracy']:>6.2%} "
              f"{errors:>6} {label} {rate:>6.2%}")

    # ─── Criteria Check ───
    print("\n" + "=" * 70)
    print("CRITERIA CHECK")
    print("=" * 70)

    criteria = [
        ('Accuracy ≥ 90%', metrics['accuracy'] >= 0.90),
        ('Accuracy ≥ 95% (target)', metrics['accuracy'] >= 0.95),
        ('FPR ≤ 10%', metrics.get('fpr', 1.0) <= 0.10),
        ('FPR ≤ 5% (target)', metrics.get('fpr', 1.0) <= 0.05),
        ('FNR ≤ 10%', metrics.get('fnr', 1.0) <= 0.10),
        ('FNR ≤ 5% (target)', metrics.get('fnr', 1.0) <= 0.05),
        ('Throughput ≥ 10k/sec', throughput >= 10000),
        ('Throughput ≥ 50k/sec (target)', throughput >= 50000),
    ]

    all_minimum = True
    for name, passed in criteria:
        status = "PASS" if passed else "FAIL"
        icon = "+" if passed else "x"
        print(f"  [{icon}] {name}: {status}")
        if 'target' not in name and not passed:
            all_minimum = False

    if all_minimum:
        print("\n  ✓ ALL MINIMUM CRITERIA PASSED")
    else:
        print("\n  ✗ SOME MINIMUM CRITERIA FAILED — needs retraining")

    # ─── Save Misclassified ───
    if args.save_misclassified:
        misclassified = []
        for i in range(len(texts)):
            if preds[i] != labels[i]:
                misclassified.append({
                    'text': texts[i],
                    'true_label': int(labels[i]),
                    'predicted': int(preds[i]),
                    'probability': round(float(probs[i]), 6),
                    'category': categories[i],
                    'error_type': 'FP' if labels[i] == 0 else 'FN',
                })

        # Save top misclassified (sorted by confidence)
        misclassified.sort(key=lambda x: abs(x['probability'] - 0.5), reverse=True)
        mis_to_save = misclassified[:args.max_misclassified]

        if mis_to_save:
            mis_df = pd.DataFrame(mis_to_save)
            mis_df.to_csv(MISCLASSIFIED_PATH, index=False)
            print(f"\nMisclassified samples saved: {MISCLASSIFIED_PATH}")
            print(f"  Total misclassified: {len(misclassified):,}")
            print(f"  Saved (top {args.max_misclassified}): {len(mis_to_save):,}")

            # Error type breakdown
            fp_count = sum(1 for m in misclassified if m['error_type'] == 'FP')
            fn_count = sum(1 for m in misclassified if m['error_type'] == 'FN')
            print(f"  False Positives (safe flagged as injection): {fp_count:,}")
            print(f"  False Negatives (injection missed): {fn_count:,}")

    # ─── Save Results ───
    results = {
        'benchmark_info': {
            'model_path': str(args.model_path),
            'test_data': str(args.test_data),
            'total_samples': len(texts),
            'injection_samples': int(n_inj),
            'safe_samples': int(n_safe),
            'device': device,
            'gpu': torch.cuda.get_device_name(0) if device == 'cuda' else 'N/A',
            'batch_size': args.batch_size,
            'threshold': args.threshold,
            'pytorch_version': torch.__version__,
        },
        'performance': {
            'encoding_time_s': round(encode_time, 2),
            'inference_time_s': round(infer_time, 2),
            'total_time_s': round(encode_time + infer_time, 2),
            'throughput_samples_per_sec': round(throughput, 0),
        },
        'overall_metrics': {k: round(v, 6) if isinstance(v, float) else v
                            for k, v in metrics.items()},
        'per_category': {k: {kk: round(vv, 6) if isinstance(vv, float) else vv
                              for kk, vv in v.items()}
                         for k, v in cat_metrics.items()},
        'criteria_results': {name: passed for name, passed in criteria},
        'all_minimum_passed': all_minimum,
        'total_misclassified': len(misclassified) if args.save_misclassified else 0,
    }

    with open(RESULTS_PATH, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved: {RESULTS_PATH}")

    print("\n" + "=" * 70)
    verdict = "PASSED" if all_minimum else "NEEDS RETRAINING"
    print(f"BENCHMARK VERDICT: {verdict}")
    print(f"  Accuracy: {metrics['accuracy']:.2%} | F1: {metrics['f1']:.4f} | "
          f"FPR: {metrics.get('fpr', 0):.2%} | FNR: {metrics.get('fnr', 0):.2%}")
    print(f"  Throughput: {throughput:,.0f} samples/sec")
    print("=" * 70)

    return results


if __name__ == '__main__':
    main()
