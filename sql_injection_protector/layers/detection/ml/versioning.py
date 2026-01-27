"""Model version management for ML detectors."""

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class ModelVersion:
    """Represents a model version."""

    version: str
    model_type: str  # 'transformer' or 'tfidf'
    created_at: datetime
    path: str
    metrics: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    is_active: bool = False
    is_canary: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "model_type": self.model_type,
            "created_at": self.created_at.isoformat(),
            "path": self.path,
            "metrics": self.metrics,
            "metadata": self.metadata,
            "is_active": self.is_active,
            "is_canary": self.is_canary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelVersion":
        """Create from dictionary."""
        data = data.copy()
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)


class ModelVersionManager:
    """
    Manages multiple model versions for A/B testing and rollback.

    Features:
    - Version tracking and metadata storage
    - Active/canary model management
    - Rollback support
    - Metrics comparison
    """

    def __init__(self, base_path: str = "models"):
        """
        Initialize version manager.

        Args:
            base_path: Base directory for model storage
        """
        self.base_path = Path(base_path)
        self.manifest_path = self.base_path / "manifest.json"
        self._versions: dict[str, ModelVersion] = {}
        self._active_version: Optional[str] = None
        self._canary_version: Optional[str] = None
        self._load_manifest()

    def _load_manifest(self) -> None:
        """Load version manifest from disk."""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path) as f:
                    data = json.load(f)
                    self._versions = {
                        k: ModelVersion.from_dict(v)
                        for k, v in data.get("versions", {}).items()
                    }
                    self._active_version = data.get("active_version")
                    self._canary_version = data.get("canary_version")
            except Exception:
                self._versions = {}

    def _save_manifest(self) -> None:
        """Save version manifest to disk."""
        self.base_path.mkdir(parents=True, exist_ok=True)

        data = {
            "versions": {k: v.to_dict() for k, v in self._versions.items()},
            "active_version": self._active_version,
            "canary_version": self._canary_version,
            "updated_at": datetime.utcnow().isoformat(),
        }

        with open(self.manifest_path, "w") as f:
            json.dump(data, f, indent=2)

    def register_version(
        self,
        version: str,
        model_type: str,
        path: str,
        metrics: Optional[dict[str, float]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ModelVersion:
        """
        Register a new model version.

        Args:
            version: Version string (e.g., "1.0.0")
            model_type: Type of model ('transformer' or 'tfidf')
            path: Path to model files
            metrics: Training/validation metrics
            metadata: Additional metadata

        Returns:
            Created ModelVersion
        """
        model_version = ModelVersion(
            version=version,
            model_type=model_type,
            created_at=datetime.utcnow(),
            path=path,
            metrics=metrics or {},
            metadata=metadata or {},
        )

        self._versions[version] = model_version
        self._save_manifest()

        return model_version

    def get_version(self, version: str) -> Optional[ModelVersion]:
        """Get a specific version."""
        return self._versions.get(version)

    def get_active_version(self) -> Optional[ModelVersion]:
        """Get the currently active version."""
        if self._active_version:
            return self._versions.get(self._active_version)
        return None

    def get_canary_version(self) -> Optional[ModelVersion]:
        """Get the current canary version."""
        if self._canary_version:
            return self._versions.get(self._canary_version)
        return None

    def set_active(self, version: str) -> bool:
        """
        Set a version as active.

        Args:
            version: Version string to activate

        Returns:
            True if successful
        """
        if version not in self._versions:
            return False

        # Deactivate previous
        if self._active_version and self._active_version in self._versions:
            self._versions[self._active_version].is_active = False

        # Activate new
        self._versions[version].is_active = True
        self._active_version = version
        self._save_manifest()

        return True

    def set_canary(self, version: str) -> bool:
        """
        Set a version as canary (for A/B testing).

        Args:
            version: Version string for canary

        Returns:
            True if successful
        """
        if version not in self._versions:
            return False

        # Remove previous canary
        if self._canary_version and self._canary_version in self._versions:
            self._versions[self._canary_version].is_canary = False

        # Set new canary
        self._versions[version].is_canary = True
        self._canary_version = version
        self._save_manifest()

        return True

    def remove_canary(self) -> None:
        """Remove canary version (end A/B test)."""
        if self._canary_version and self._canary_version in self._versions:
            self._versions[self._canary_version].is_canary = False
        self._canary_version = None
        self._save_manifest()

    def promote_canary(self) -> bool:
        """
        Promote canary to active version.

        Returns:
            True if successful
        """
        if not self._canary_version:
            return False

        canary = self._canary_version
        self.remove_canary()
        return self.set_active(canary)

    def rollback(self, version: Optional[str] = None) -> bool:
        """
        Rollback to a previous version.

        Args:
            version: Specific version to rollback to, or None for previous

        Returns:
            True if successful
        """
        if version:
            return self.set_active(version)

        # Find previous version
        versions = sorted(
            self._versions.values(),
            key=lambda v: v.created_at,
            reverse=True,
        )

        for v in versions:
            if v.version != self._active_version:
                return self.set_active(v.version)

        return False

    def list_versions(self) -> list[ModelVersion]:
        """List all versions sorted by creation time."""
        return sorted(
            self._versions.values(),
            key=lambda v: v.created_at,
            reverse=True,
        )

    def delete_version(self, version: str, delete_files: bool = False) -> bool:
        """
        Delete a version.

        Args:
            version: Version to delete
            delete_files: Also delete model files

        Returns:
            True if successful
        """
        if version not in self._versions:
            return False

        if version == self._active_version:
            return False  # Cannot delete active version

        model_version = self._versions[version]

        if delete_files:
            path = Path(model_version.path)
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

        del self._versions[version]

        if version == self._canary_version:
            self._canary_version = None

        self._save_manifest()
        return True

    def update_metrics(self, version: str, metrics: dict[str, float]) -> bool:
        """
        Update metrics for a version.

        Args:
            version: Version to update
            metrics: New metrics to merge

        Returns:
            True if successful
        """
        if version not in self._versions:
            return False

        self._versions[version].metrics.update(metrics)
        self._save_manifest()
        return True

    def compare_versions(
        self,
        version1: str,
        version2: str,
    ) -> Optional[dict[str, Any]]:
        """
        Compare metrics between two versions.

        Returns:
            Comparison data or None if versions not found
        """
        v1 = self._versions.get(version1)
        v2 = self._versions.get(version2)

        if not v1 or not v2:
            return None

        all_metrics = set(v1.metrics.keys()) | set(v2.metrics.keys())

        comparison = {
            "version1": version1,
            "version2": version2,
            "metrics": {},
        }

        for metric in all_metrics:
            val1 = v1.metrics.get(metric)
            val2 = v2.metrics.get(metric)

            comparison["metrics"][metric] = {
                "v1": val1,
                "v2": val2,
                "diff": val2 - val1 if val1 is not None and val2 is not None else None,
            }

        return comparison

    def get_best_version(self, metric: str, higher_is_better: bool = True) -> Optional[ModelVersion]:
        """
        Get the version with best value for a metric.

        Args:
            metric: Metric name to compare
            higher_is_better: Whether higher values are better

        Returns:
            Best ModelVersion or None
        """
        candidates = [
            v for v in self._versions.values()
            if metric in v.metrics
        ]

        if not candidates:
            return None

        return max(candidates, key=lambda v: v.metrics[metric] * (1 if higher_is_better else -1))

    def should_use_canary(self, percentage: float = 0.1) -> bool:
        """
        Determine if canary should be used for a request.

        Args:
            percentage: Percentage of requests for canary (0-1)

        Returns:
            True if canary should be used
        """
        import random

        if not self._canary_version:
            return False

        return random.random() < percentage
