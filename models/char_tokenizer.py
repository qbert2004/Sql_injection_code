"""
Character-level tokenizer for SQL injection detection.

Replaces the Keras word-level Tokenizer with a deterministic
character-level tokenizer. No fitting required — the vocabulary
is fixed to all printable ASCII characters.

Usage:
    tokenizer = CharTokenizer(max_length=200)
    encoded = tokenizer.encode_batch(["' OR '1'='1", "hello"])
    # encoded.shape == (2, 200)
"""

import json
import numpy as np
from typing import List, Dict, Any


class CharTokenizer:
    """Deterministic character-level tokenizer with fixed ASCII vocabulary."""

    PAD_IDX = 0
    UNK_IDX = 1
    VOCAB_START = 2

    def __init__(self, max_length: int = 200):
        self.max_length = max_length

        # Build vocabulary: printable ASCII 32 (space) through 126 (~)
        self.char_to_idx: Dict[str, int] = {}
        self.idx_to_char: Dict[int, str] = {
            self.PAD_IDX: '<PAD>',
            self.UNK_IDX: '<UNK>',
        }

        idx = self.VOCAB_START
        for code in range(32, 127):  # 95 printable ASCII characters
            ch = chr(code)
            self.char_to_idx[ch] = idx
            self.idx_to_char[idx] = ch
            idx += 1

        self.vocab_size = idx  # PAD + UNK + 95 = 97

    def encode(self, text: str) -> List[int]:
        """Convert a string to a list of character indices."""
        return [self.char_to_idx.get(ch, self.UNK_IDX) for ch in text]

    def encode_batch(self, texts: List[str]) -> np.ndarray:
        """
        Convert a list of strings to a padded 2D numpy array.

        Returns:
            np.ndarray of shape (batch_size, max_length) with dtype int64.
            Sequences shorter than max_length are post-padded with PAD_IDX.
            Sequences longer than max_length are post-truncated.
        """
        batch = np.full((len(texts), self.max_length), self.PAD_IDX, dtype=np.int64)

        for i, text in enumerate(texts):
            indices = self.encode(text)
            length = min(len(indices), self.max_length)
            batch[i, :length] = indices[:length]

        return batch

    def decode(self, indices: List[int]) -> str:
        """Convert indices back to a string (for debugging)."""
        chars = []
        for idx in indices:
            if idx == self.PAD_IDX:
                break
            chars.append(self.idx_to_char.get(idx, '?'))
        return ''.join(chars)

    def save(self, path: str) -> None:
        """Save tokenizer configuration to JSON."""
        config = {
            'max_length': self.max_length,
            'vocab_size': self.vocab_size,
            'pad_idx': self.PAD_IDX,
            'unk_idx': self.UNK_IDX,
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'CharTokenizer':
        """Load tokenizer from JSON configuration."""
        with open(path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return cls(max_length=config['max_length'])

    def __repr__(self) -> str:
        return f"CharTokenizer(vocab_size={self.vocab_size}, max_length={self.max_length})"
