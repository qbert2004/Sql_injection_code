"""Dataset management for training data."""

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class DatasetSample:
    """A single sample in the dataset."""

    text: str
    label: bool  # True = malicious, False = benign
    source: str = "unknown"
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DatasetVersion:
    """Metadata for a dataset version."""

    version: str
    created_at: datetime
    sample_count: int
    malicious_count: int
    benign_count: int
    sources: list[str]
    description: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "sample_count": self.sample_count,
            "malicious_count": self.malicious_count,
            "benign_count": self.benign_count,
            "sources": self.sources,
            "description": self.description,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatasetVersion":
        """Create from dictionary."""
        data = data.copy()
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)


class DatasetManager:
    """
    Manages training datasets with versioning.

    Features:
    - Dataset versioning
    - Train/test splitting
    - Export to various formats
    - Merging and augmentation
    """

    def __init__(self, base_path: str = "datasets"):
        """
        Initialize dataset manager.

        Args:
            base_path: Base directory for dataset storage
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._versions: dict[str, DatasetVersion] = {}
        self._current_samples: list[DatasetSample] = []
        self._load_versions()

    def _load_versions(self) -> None:
        """Load version metadata from disk."""
        manifest_path = self.base_path / "manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    data = json.load(f)
                    self._versions = {
                        k: DatasetVersion.from_dict(v)
                        for k, v in data.get("versions", {}).items()
                    }
            except Exception as e:
                logger.error(f"Failed to load dataset manifest: {e}")

    def _save_versions(self) -> None:
        """Save version metadata to disk."""
        manifest_path = self.base_path / "manifest.json"
        data = {
            "versions": {k: v.to_dict() for k, v in self._versions.items()},
            "updated_at": datetime.utcnow().isoformat(),
        }
        with open(manifest_path, "w") as f:
            json.dump(data, f, indent=2)

    def add_sample(
        self,
        text: str,
        label: bool,
        source: str = "collected",
        confidence: float = 1.0,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Add a sample to the current working dataset.

        Args:
            text: Sample text
            label: True = malicious, False = benign
            source: Source of the sample
            confidence: Label confidence
            metadata: Additional metadata
        """
        sample = DatasetSample(
            text=text,
            label=label,
            source=source,
            confidence=confidence,
            metadata=metadata or {},
        )
        self._current_samples.append(sample)

    def add_samples_from_collector(
        self,
        payloads: list[dict[str, Any]],
    ) -> int:
        """
        Add labeled samples from payload collector.

        Args:
            payloads: List of payload dictionaries

        Returns:
            Number of samples added
        """
        count = 0
        for payload in payloads:
            if payload.get("is_labeled") and payload.get("label") is not None:
                self.add_sample(
                    text=payload["payload"],
                    label=payload["label"],
                    source=payload.get("source", "collected"),
                    confidence=payload.get("confidence", 1.0),
                    metadata=payload.get("metadata", {}),
                )
                count += 1
        return count

    def create_version(
        self,
        version: str,
        description: str = "",
    ) -> DatasetVersion:
        """
        Create a new dataset version from current samples.

        Args:
            version: Version string
            description: Version description

        Returns:
            Created DatasetVersion
        """
        if not self._current_samples:
            raise ValueError("No samples to create version from")

        # Create version directory
        version_path = self.base_path / version
        version_path.mkdir(parents=True, exist_ok=True)

        # Count samples
        malicious_count = sum(1 for s in self._current_samples if s.label)
        benign_count = len(self._current_samples) - malicious_count
        sources = list(set(s.source for s in self._current_samples))

        # Save samples
        samples_path = version_path / "samples.jsonl"
        with open(samples_path, "w") as f:
            for sample in self._current_samples:
                f.write(json.dumps({
                    "text": sample.text,
                    "label": sample.label,
                    "source": sample.source,
                    "confidence": sample.confidence,
                    "metadata": sample.metadata,
                }) + "\n")

        # Create version metadata
        dataset_version = DatasetVersion(
            version=version,
            created_at=datetime.utcnow(),
            sample_count=len(self._current_samples),
            malicious_count=malicious_count,
            benign_count=benign_count,
            sources=sources,
            description=description,
            path=str(version_path),
        )

        self._versions[version] = dataset_version
        self._save_versions()

        logger.info(f"Created dataset version {version} with {len(self._current_samples)} samples")

        return dataset_version

    def load_version(self, version: str) -> list[DatasetSample]:
        """
        Load samples from a version.

        Args:
            version: Version string

        Returns:
            List of DatasetSamples
        """
        if version not in self._versions:
            raise ValueError(f"Version {version} not found")

        version_info = self._versions[version]
        samples_path = Path(version_info.path) / "samples.jsonl"

        samples = []
        with open(samples_path) as f:
            for line in f:
                data = json.loads(line.strip())
                samples.append(DatasetSample(**data))

        return samples

    def get_version(self, version: str) -> Optional[DatasetVersion]:
        """Get version metadata."""
        return self._versions.get(version)

    def list_versions(self) -> list[DatasetVersion]:
        """List all versions."""
        return sorted(
            self._versions.values(),
            key=lambda v: v.created_at,
            reverse=True,
        )

    def delete_version(self, version: str, delete_files: bool = True) -> bool:
        """
        Delete a version.

        Args:
            version: Version to delete
            delete_files: Also delete files

        Returns:
            True if deleted
        """
        if version not in self._versions:
            return False

        version_info = self._versions[version]

        if delete_files:
            version_path = Path(version_info.path)
            if version_path.exists():
                shutil.rmtree(version_path)

        del self._versions[version]
        self._save_versions()

        return True

    def split_train_test(
        self,
        version: str,
        test_ratio: float = 0.2,
        shuffle: bool = True,
        random_seed: int = 42,
    ) -> tuple[list[DatasetSample], list[DatasetSample]]:
        """
        Split a version into train and test sets.

        Args:
            version: Version to split
            test_ratio: Ratio of test samples
            shuffle: Whether to shuffle before splitting
            random_seed: Random seed for reproducibility

        Returns:
            Tuple of (train_samples, test_samples)
        """
        import random

        samples = self.load_version(version)

        if shuffle:
            random.seed(random_seed)
            random.shuffle(samples)

        split_idx = int(len(samples) * (1 - test_ratio))
        train = samples[:split_idx]
        test = samples[split_idx:]

        return train, test

    def export_to_csv(self, version: str, output_path: str) -> None:
        """Export version to CSV format."""
        import csv

        samples = self.load_version(version)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["text", "label", "source", "confidence"])
            for sample in samples:
                writer.writerow([
                    sample.text,
                    1 if sample.label else 0,
                    sample.source,
                    sample.confidence,
                ])

    def export_to_jsonl(self, version: str, output_path: str) -> None:
        """Export version to JSONL format."""
        samples = self.load_version(version)

        with open(output_path, "w") as f:
            for sample in samples:
                f.write(json.dumps({
                    "text": sample.text,
                    "label": sample.label,
                    "source": sample.source,
                    "confidence": sample.confidence,
                }) + "\n")

    def merge_versions(
        self,
        versions: list[str],
        new_version: str,
        deduplicate: bool = True,
    ) -> DatasetVersion:
        """
        Merge multiple versions into a new version.

        Args:
            versions: Versions to merge
            new_version: New version name
            deduplicate: Remove duplicates

        Returns:
            New DatasetVersion
        """
        all_samples = []
        seen_texts = set()

        for version in versions:
            samples = self.load_version(version)
            for sample in samples:
                if deduplicate:
                    if sample.text in seen_texts:
                        continue
                    seen_texts.add(sample.text)
                all_samples.append(sample)

        # Set as current and create version
        self._current_samples = all_samples
        return self.create_version(new_version, f"Merged from: {', '.join(versions)}")

    def get_stats(self) -> dict[str, Any]:
        """Get overall dataset statistics."""
        total_samples = sum(v.sample_count for v in self._versions.values())
        total_malicious = sum(v.malicious_count for v in self._versions.values())
        total_benign = sum(v.benign_count for v in self._versions.values())

        return {
            "version_count": len(self._versions),
            "total_samples": total_samples,
            "total_malicious": total_malicious,
            "total_benign": total_benign,
            "current_working_samples": len(self._current_samples),
        }

    def clear_current(self) -> int:
        """Clear current working samples."""
        count = len(self._current_samples)
        self._current_samples = []
        return count
