"""
PyTorch Character-level CNN for SQL Injection Detection.

Architecture:
    Embedding(vocab_size, 32)
    -> Conv1d(32, 64, kernel=3) + ReLU + BatchNorm
    -> Conv1d(64, 128, kernel=3) + ReLU + BatchNorm
    -> Conv1d(128, 128, kernel=3) + ReLU + BatchNorm
    -> AdaptiveMaxPool1d(1)
    -> Linear(128, 64) + ReLU + Dropout
    -> Linear(64, 1) + Sigmoid

Output: probability of SQL injection in [0, 1].
"""

import torch
import torch.nn as nn


class CharCNN(nn.Module):
    """Character-level CNN for binary SQL injection classification."""

    def __init__(
        self,
        vocab_size: int = 97,
        embed_dim: int = 32,
        num_filters_1: int = 64,
        num_filters_2: int = 128,
        num_filters_3: int = 128,
        kernel_size: int = 3,
        hidden_dim: int = 64,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        self.conv1 = nn.Conv1d(embed_dim, num_filters_1, kernel_size, padding=1)
        self.bn1 = nn.BatchNorm1d(num_filters_1)

        self.conv2 = nn.Conv1d(num_filters_1, num_filters_2, kernel_size, padding=1)
        self.bn2 = nn.BatchNorm1d(num_filters_2)

        self.conv3 = nn.Conv1d(num_filters_2, num_filters_3, kernel_size, padding=1)
        self.bn3 = nn.BatchNorm1d(num_filters_3)

        self.pool = nn.AdaptiveMaxPool1d(1)

        self.fc1 = nn.Linear(num_filters_3, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(hidden_dim, 1)

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
        # Conv1d expects (B, C, L) — channels first
        x = x.permute(0, 2, 1)

        x = self.relu(self.bn1(self.conv1(x)))
        x = self.relu(self.bn2(self.conv2(x)))
        x = self.relu(self.bn3(self.conv3(x)))

        # Global max pooling: (B, C, L) -> (B, C, 1) -> (B, C)
        x = self.pool(x).squeeze(-1)

        x = self.dropout(self.relu(self.fc1(x)))
        x = self.sigmoid(self.fc2(x))

        return x

    def save_checkpoint(self, path: str, config: dict) -> None:
        """Save model with configuration for reconstruction."""
        torch.save({
            'model_config': config,
            'model_state_dict': self.state_dict(),
        }, path)

    @classmethod
    def load_from_checkpoint(cls, path: str, device: str = 'cpu') -> 'CharCNN':
        """Load model from checkpoint file."""
        checkpoint = torch.load(path, map_location=device, weights_only=False)
        model = cls(**checkpoint['model_config'])
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        return model
