"""
VDCNN — Very Deep Convolutional Neural Network for SQL Injection Detection.

Based on: Conneau et al. 2017 "Very Deep Convolutional Networks for Text Classification"
           https://arxiv.org/abs/1606.01781

Architecture (depth=9, n_blocks=(1,1,1,1)):
    Embedding(vocab_size=97, embed_dim=16)
    -> Conv1d(16, 64, kernel=3)                    [initial convolution]
    -> Stage 1: ConvBlock(64)  × 1 + MaxPool       [64 filters]
    -> Stage 2: ConvBlock(128) × 1 + MaxPool       [128 filters]
    -> Stage 3: ConvBlock(256) × 1 + MaxPool       [256 filters]
    -> Stage 4: ConvBlock(512) × 1                 [512 filters]
    -> KMaxPool1d(k=8) -> flatten(4096)
    -> FC(4096, 2048) + ReLU
    -> FC(2048, 2048) + ReLU
    -> FC(2048, 1)

ConvBlock = Conv1d -> BN -> ReLU -> Conv1d -> BN + Residual -> ReLU

Depth variants:
    depth=9:  (1,1,1,1)  ~2.2M params
    depth=17: (2,2,2,2)  ~4.4M params
    depth=29: (5,5,2,2)  ~8.8M params

Forward returns raw logits for numerically stable training with BCEWithLogitsLoss.
Use predict() for inference — it applies sigmoid to return probabilities in [0, 1].
"""

import torch
import torch.nn as nn


class KMaxPool1d(nn.Module):
    """Select top-k maximum values from each channel.

    Extracts the k highest activations along the temporal dimension,
    preserving their relative order. This captures the most salient
    features regardless of their position in the sequence.
    """

    def __init__(self, k: int = 8):
        super().__init__()
        self.k = k

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, channels, length)
        k = min(self.k, x.size(2))
        top_k, _ = x.topk(k, dim=2, sorted=True)
        return top_k


class ConvBlock(nn.Module):
    """Residual convolutional block for VDCNN.

    Structure: Conv1d -> BN -> ReLU -> Conv1d -> BN + Shortcut -> ReLU

    Uses identity shortcut when input/output channels match,
    1x1 convolution projection when channels differ (stage transitions).
    """

    def __init__(self, in_channels: int, out_channels: int,
                 kernel_size: int = 3, shortcut: bool = True):
        super().__init__()
        padding = kernel_size // 2

        self.conv1 = nn.Conv1d(in_channels, out_channels,
                               kernel_size, padding=padding)
        self.bn1 = nn.BatchNorm1d(out_channels)

        self.conv2 = nn.Conv1d(out_channels, out_channels,
                               kernel_size, padding=padding)
        self.bn2 = nn.BatchNorm1d(out_channels)

        self.relu = nn.ReLU(inplace=True)

        # Residual shortcut
        self.shortcut = None
        if shortcut and in_channels != out_channels:
            self.shortcut = nn.Sequential(
                nn.Conv1d(in_channels, out_channels, kernel_size=1, bias=False),
                nn.BatchNorm1d(out_channels),
            )

        self.use_shortcut = shortcut

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x

        out = self.relu(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))

        if self.use_shortcut:
            if self.shortcut is not None:
                residual = self.shortcut(residual)
            out = out + residual

        out = self.relu(out)
        return out


# Depth configurations: (stage1_blocks, stage2_blocks, stage3_blocks, stage4_blocks)
DEPTH_CONFIG = {
    9:  (1, 1, 1, 1),
    17: (2, 2, 2, 2),
    29: (5, 5, 2, 2),
    49: (8, 8, 5, 3),
}

# Filter progression per stage
STAGE_FILTERS = (64, 128, 256, 512)


class CharCNN(nn.Module):
    """VDCNN — Very Deep Character-level CNN for SQL injection detection.

    Implements the architecture from Conneau et al. 2017 with residual
    convolutional blocks, progressive filter expansion (64->512),
    and k-max pooling for position-invariant feature extraction.

    Args:
        vocab_size: Character vocabulary size (default: 97 for ASCII 32-126 + PAD + UNK).
        embed_dim: Character embedding dimension (default: 16, per VDCNN paper).
        depth: Network depth variant — 9, 17, 29, or 49 conv layers (default: 9).
        k_max: Number of top activations to keep in k-max pooling (default: 8).
        fc_dim: Hidden dimension of fully connected layers (default: 2048).
        num_classes: Output classes. 1 for binary with sigmoid (default: 1).
        shortcut: Use residual connections (default: True).
    """

    def __init__(
        self,
        vocab_size: int = 97,
        embed_dim: int = 16,
        depth: int = 9,
        k_max: int = 8,
        fc_dim: int = 2048,
        num_classes: int = 1,
        shortcut: bool = True,
    ):
        super().__init__()

        if depth not in DEPTH_CONFIG:
            raise ValueError(
                f"Unsupported depth {depth}. Choose from {list(DEPTH_CONFIG.keys())}"
            )

        self.depth = depth
        self.k_max = k_max
        n_blocks = DEPTH_CONFIG[depth]

        # --- Embedding ---
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)

        # --- Initial convolution ---
        self.initial_conv = nn.Conv1d(embed_dim, STAGE_FILTERS[0],
                                      kernel_size=3, padding=1)

        # --- Build stages ---
        self.stages = nn.ModuleList()
        self.pools = nn.ModuleList()

        in_channels = STAGE_FILTERS[0]
        for stage_idx, (n_blk, out_channels) in enumerate(
                zip(n_blocks, STAGE_FILTERS)):
            blocks = []
            for blk_idx in range(n_blk):
                # First block of each stage handles channel change
                blk_in = in_channels if blk_idx == 0 else out_channels
                blocks.append(
                    ConvBlock(blk_in, out_channels, kernel_size=3,
                              shortcut=shortcut)
                )
            self.stages.append(nn.Sequential(*blocks))
            in_channels = out_channels

            # MaxPool after each stage except the last
            if stage_idx < len(STAGE_FILTERS) - 1:
                self.pools.append(nn.MaxPool1d(kernel_size=3, stride=2, padding=1))
            else:
                self.pools.append(nn.Identity())

        # --- K-max pooling ---
        self.kmax_pool = KMaxPool1d(k=k_max)

        # --- Classifier head ---
        classifier_input = STAGE_FILTERS[-1] * k_max  # 512 * 8 = 4096
        self.classifier = nn.Sequential(
            nn.Linear(classifier_input, fc_dim),
            nn.ReLU(inplace=True),
            nn.Linear(fc_dim, fc_dim),
            nn.ReLU(inplace=True),
            nn.Linear(fc_dim, num_classes),
        )

        self.sigmoid = nn.Sigmoid()

        # --- Weight initialization (He / Kaiming normal) ---
        self._init_weights()

    def _init_weights(self):
        """Initialize weights using Kaiming (He) normal initialization."""
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(
                    m.weight, mode='fan_out', nonlinearity='relu'
                )
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.constant_(m.weight, 1)
                nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity='relu')
                nn.init.constant_(m.bias, 0)

    def forward(self, x: torch.LongTensor) -> torch.FloatTensor:
        """
        Forward pass — returns raw logits (before sigmoid).

        Use this for training with BCEWithLogitsLoss (numerically stable).
        For inference probabilities, use predict() instead.

        Args:
            x: (batch_size, seq_length) integer character indices.

        Returns:
            (batch_size, 1) raw logits (NOT probabilities).
        """
        # Embedding: (B, L) -> (B, L, E)
        x = self.embedding(x)

        # Conv1d expects (B, C, L) — channels first
        x = x.permute(0, 2, 1)

        # Initial convolution: (B, E, L) -> (B, 64, L)
        x = self.initial_conv(x)

        # Pass through stages with pooling
        for stage, pool in zip(self.stages, self.pools):
            x = stage(x)
            x = pool(x)

        # K-max pooling: (B, 512, L') -> (B, 512, k)
        x = self.kmax_pool(x)

        # Flatten: (B, 512, k) -> (B, 512*k)
        x = x.view(x.size(0), -1)

        # Classifier: (B, 4096) -> (B, 1) — raw logits
        x = self.classifier(x)

        return x

    def predict(self, x: torch.LongTensor) -> torch.FloatTensor:
        """
        Inference — returns probabilities in [0, 1].

        Applies sigmoid to raw logits from forward().
        Use this for inference / deployment.

        Args:
            x: (batch_size, seq_length) integer character indices.

        Returns:
            (batch_size, 1) probability of SQL injection in [0, 1].
        """
        logits = self.forward(x)
        return self.sigmoid(logits)

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

    def count_parameters(self) -> int:
        """Count total trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)

    def __repr__(self) -> str:
        params = self.count_parameters()
        return (
            f"CharCNN(VDCNN-{self.depth}, "
            f"params={params:,}, "
            f"stages={DEPTH_CONFIG[self.depth]}, "
            f"filters={STAGE_FILTERS}, "
            f"k_max={self.k_max})"
        )
