"""
PyTorch Character-level BiLSTM for SQL Injection Detection.

Architecture:
    Embedding(vocab_size, 32)
    -> BiLSTM(32, hidden=64, 2 layers, dropout=0.2)
    -> Concat final forward + backward hidden states -> (B, 128)
    -> Linear(128, 64) + ReLU + Dropout
    -> Linear(64, 1) + Sigmoid

Output: probability of SQL injection in [0, 1].
"""

import torch
import torch.nn as nn


class CharBiLSTM(nn.Module):
    """Character-level Bidirectional LSTM for binary SQL injection classification."""

    def __init__(
        self,
        vocab_size: int = 97,
        embed_dim: int = 32,
        hidden_dim: int = 64,
        num_layers: int = 2,
        fc_dim: int = 64,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        self.bilstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        # BiLSTM outputs 2 * hidden_dim (forward + backward)
        self.fc1 = nn.Linear(hidden_dim * 2, fc_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(fc_dim, 1)

        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.LongTensor) -> torch.FloatTensor:
        """
        Forward pass.

        Args:
            x: (batch_size, seq_length) integer character indices.

        Returns:
            (batch_size, 1) probability of SQL injection.
        """
        # Embedding: (B, L) -> (B, L, E)
        x = self.embedding(x)

        # BiLSTM: h_n shape is (num_layers * 2, B, hidden_dim)
        _, (h_n, _) = self.bilstm(x)

        # Concatenate final forward and backward hidden states
        h_fwd = h_n[-2]  # Last layer, forward direction
        h_bwd = h_n[-1]  # Last layer, backward direction
        h_cat = torch.cat([h_fwd, h_bwd], dim=1)  # (B, hidden_dim * 2)

        x = self.dropout(self.relu(self.fc1(h_cat)))
        x = self.sigmoid(self.fc2(x))

        return x

    def save_checkpoint(self, path: str, config: dict) -> None:
        """Save model with configuration for reconstruction."""
        torch.save({
            'model_config': config,
            'model_state_dict': self.state_dict(),
        }, path)

    @classmethod
    def load_from_checkpoint(cls, path: str, device: str = 'cpu') -> 'CharBiLSTM':
        """Load model from checkpoint file."""
        checkpoint = torch.load(path, map_location=device, weights_only=False)
        model = cls(**checkpoint['model_config'])
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        return model
