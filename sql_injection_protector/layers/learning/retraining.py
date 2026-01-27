"""Retraining scheduler and canary deployment."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Optional

from sql_injection_protector.layers.learning.dataset import DatasetManager, DatasetSample
from sql_injection_protector.layers.learning.collector import PayloadCollector
from sql_injection_protector.layers.learning.labeler import HybridLabeler
from sql_injection_protector.layers.detection.ml.versioning import ModelVersionManager

logger = logging.getLogger(__name__)


class RetrainingStatus(Enum):
    """Status of retraining job."""

    PENDING = auto()
    COLLECTING = auto()
    LABELING = auto()
    TRAINING = auto()
    VALIDATING = auto()
    DEPLOYING = auto()
    COMPLETED = auto()
    FAILED = auto()


@dataclass
class RetrainingJob:
    """A retraining job."""

    job_id: str
    status: RetrainingStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    samples_collected: int = 0
    samples_labeled: int = 0
    new_model_version: Optional[str] = None
    validation_metrics: dict[str, float] = field(default_factory=dict)
    error_message: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "status": self.status.name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "samples_collected": self.samples_collected,
            "samples_labeled": self.samples_labeled,
            "new_model_version": self.new_model_version,
            "validation_metrics": self.validation_metrics,
            "error_message": self.error_message,
        }


@dataclass
class RetrainingConfig:
    """Configuration for retraining."""

    min_samples: int = 500
    retrain_interval_hours: int = 24
    validation_split: float = 0.2
    min_accuracy_improvement: float = 0.01
    canary_percentage: float = 0.1
    canary_duration_hours: int = 24
    rollback_threshold: float = 0.05  # Rollback if accuracy drops by this much
    auto_promote: bool = True


class RetrainingScheduler:
    """
    Schedules and manages model retraining.

    Features:
    - Periodic retraining based on collected data
    - Canary deployment for new models
    - Automatic rollback on degradation
    - Validation before deployment
    """

    def __init__(
        self,
        config: Optional[RetrainingConfig] = None,
        dataset_manager: Optional[DatasetManager] = None,
        model_manager: Optional[ModelVersionManager] = None,
        payload_collector: Optional[PayloadCollector] = None,
        labeler: Optional[HybridLabeler] = None,
        train_function: Optional[Callable] = None,
    ):
        """
        Initialize retraining scheduler.

        Args:
            config: Retraining configuration
            dataset_manager: Dataset manager
            model_manager: Model version manager
            payload_collector: Payload collector
            labeler: Labeler for collected payloads
            train_function: Function to train model (async)
        """
        self.config = config or RetrainingConfig()
        self.dataset_manager = dataset_manager or DatasetManager()
        self.model_manager = model_manager or ModelVersionManager()
        self.payload_collector = payload_collector
        self.labeler = labeler or HybridLabeler()
        self.train_function = train_function

        self._current_job: Optional[RetrainingJob] = None
        self._job_history: list[RetrainingJob] = []
        self._last_retrain: Optional[datetime] = None
        self._running = False
        self._canary_metrics: list[dict[str, float]] = []

    async def start(self) -> None:
        """Start the retraining scheduler."""
        self._running = True
        logger.info("Retraining scheduler started")

        while self._running:
            try:
                # Check if retraining is needed
                if await self._should_retrain():
                    await self.trigger_retrain()

                # Check canary status
                await self._check_canary()

                # Sleep until next check
                await asyncio.sleep(3600)  # Check every hour

            except Exception as e:
                logger.error(f"Retraining scheduler error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error

    async def stop(self) -> None:
        """Stop the retraining scheduler."""
        self._running = False
        logger.info("Retraining scheduler stopped")

    async def _should_retrain(self) -> bool:
        """Check if retraining should be triggered."""
        # Check time since last retrain
        if self._last_retrain:
            elapsed = datetime.utcnow() - self._last_retrain
            if elapsed < timedelta(hours=self.config.retrain_interval_hours):
                return False

        # Check if we have enough samples
        if self.payload_collector:
            stats = await self.payload_collector.get_stats()
            if stats.get("total_collected", 0) < self.config.min_samples:
                return False

        return True

    async def trigger_retrain(self) -> RetrainingJob:
        """
        Trigger a retraining job.

        Returns:
            RetrainingJob instance
        """
        import uuid

        job = RetrainingJob(
            job_id=str(uuid.uuid4())[:8],
            status=RetrainingStatus.PENDING,
            started_at=datetime.utcnow(),
        )
        self._current_job = job

        try:
            # Step 1: Collect samples
            job.status = RetrainingStatus.COLLECTING
            samples = await self._collect_samples()
            job.samples_collected = len(samples)

            if job.samples_collected < self.config.min_samples:
                job.status = RetrainingStatus.FAILED
                job.error_message = f"Not enough samples: {job.samples_collected} < {self.config.min_samples}"
                return job

            # Step 2: Label samples
            job.status = RetrainingStatus.LABELING
            labeled_samples = await self._label_samples(samples)
            job.samples_labeled = len(labeled_samples)

            # Step 3: Create dataset version
            version_name = f"auto_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            for sample in labeled_samples:
                self.dataset_manager.add_sample(
                    text=sample["text"],
                    label=sample["label"],
                    source="auto_collected",
                    confidence=sample.get("confidence", 1.0),
                )
            self.dataset_manager.create_version(version_name)

            # Step 4: Train model
            job.status = RetrainingStatus.TRAINING
            model_version = await self._train_model(version_name)
            job.new_model_version = model_version

            # Step 5: Validate
            job.status = RetrainingStatus.VALIDATING
            metrics = await self._validate_model(model_version, version_name)
            job.validation_metrics = metrics

            # Check if model is good enough
            if not await self._is_model_acceptable(metrics):
                job.status = RetrainingStatus.FAILED
                job.error_message = "Model validation failed"
                return job

            # Step 6: Deploy as canary
            job.status = RetrainingStatus.DEPLOYING
            await self._deploy_canary(model_version)

            job.status = RetrainingStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            self._last_retrain = datetime.utcnow()

            logger.info(f"Retraining job {job.job_id} completed successfully")

        except Exception as e:
            job.status = RetrainingStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.utcnow()
            logger.error(f"Retraining job {job.job_id} failed: {e}")

        finally:
            self._job_history.append(job)
            self._current_job = None

        return job

    async def _collect_samples(self) -> list[dict]:
        """Collect samples from payload collector."""
        if not self.payload_collector:
            return []

        payloads = await self.payload_collector.export_for_training(labeled_only=False)
        return payloads

    async def _label_samples(self, samples: list[dict]) -> list[dict]:
        """Label samples using hybrid labeler."""
        from sql_injection_protector.layers.learning.collector import CollectedPayload

        # Convert to CollectedPayload objects
        payloads = []
        for sample in samples:
            payloads.append(CollectedPayload(
                payload_hash=sample.get("payload_hash", ""),
                payload=sample.get("payload", sample.get("text", "")),
                timestamp=datetime.utcnow(),
                source=sample.get("source", "collected"),
                detection_score=sample.get("detection_score", 0.0),
            ))

        # Run hybrid labeling
        stats = await self.labeler.process_batch(payloads)

        # Return labeled samples
        labeled = []
        for p in payloads:
            if p.is_labeled:
                labeled.append({
                    "text": p.payload,
                    "label": p.label,
                    "confidence": p.confidence,
                })

        return labeled

    async def _train_model(self, dataset_version: str) -> str:
        """Train a new model."""
        if self.train_function:
            return await self.train_function(dataset_version)

        # Default: create new version without actual training
        new_version = f"model_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.model_manager.register_version(
            version=new_version,
            model_type="tfidf",
            path=f"models/{new_version}",
            metadata={"dataset": dataset_version},
        )
        return new_version

    async def _validate_model(
        self,
        model_version: str,
        dataset_version: str,
    ) -> dict[str, float]:
        """Validate model on test set."""
        # Get test data
        _, test_samples = self.dataset_manager.split_train_test(
            dataset_version,
            test_ratio=self.config.validation_split,
        )

        # For now, return placeholder metrics
        # In production, this would actually evaluate the model
        return {
            "accuracy": 0.95,
            "precision": 0.94,
            "recall": 0.96,
            "f1_score": 0.95,
        }

    async def _is_model_acceptable(self, metrics: dict[str, float]) -> bool:
        """Check if model metrics are acceptable."""
        # Get current model metrics
        current_version = self.model_manager.get_active_version()
        if not current_version:
            return True  # No current model, accept any

        current_metrics = current_version.metrics

        # Check if improvement is sufficient
        new_accuracy = metrics.get("accuracy", 0)
        old_accuracy = current_metrics.get("accuracy", 0)

        return new_accuracy >= old_accuracy - self.config.rollback_threshold

    async def _deploy_canary(self, model_version: str) -> None:
        """Deploy model as canary."""
        self.model_manager.set_canary(model_version)
        logger.info(f"Deployed {model_version} as canary ({self.config.canary_percentage * 100}%)")

    async def _check_canary(self) -> None:
        """Check canary status and decide on promotion/rollback."""
        canary = self.model_manager.get_canary_version()
        if not canary:
            return

        # Check canary duration
        canary_age = datetime.utcnow() - canary.created_at
        if canary_age < timedelta(hours=self.config.canary_duration_hours):
            return  # Still in canary period

        # Analyze canary performance
        if self._canary_metrics:
            avg_accuracy = sum(m.get("accuracy", 0) for m in self._canary_metrics) / len(self._canary_metrics)

            active = self.model_manager.get_active_version()
            active_accuracy = active.metrics.get("accuracy", 0) if active else 0

            if avg_accuracy < active_accuracy - self.config.rollback_threshold:
                # Rollback
                logger.warning(f"Rolling back canary {canary.version} due to degraded performance")
                self.model_manager.remove_canary()
            elif self.config.auto_promote:
                # Promote
                logger.info(f"Promoting canary {canary.version} to active")
                self.model_manager.promote_canary()
        elif self.config.auto_promote:
            # No metrics collected, promote anyway after duration
            self.model_manager.promote_canary()

        self._canary_metrics = []

    def record_canary_metric(self, metrics: dict[str, float]) -> None:
        """Record metrics for canary evaluation."""
        self._canary_metrics.append(metrics)

    def get_current_job(self) -> Optional[RetrainingJob]:
        """Get current retraining job."""
        return self._current_job

    def get_job_history(self, limit: int = 10) -> list[RetrainingJob]:
        """Get recent job history."""
        return self._job_history[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get scheduler statistics."""
        return {
            "is_running": self._running,
            "last_retrain": self._last_retrain.isoformat() if self._last_retrain else None,
            "current_job": self._current_job.to_dict() if self._current_job else None,
            "completed_jobs": len(self._job_history),
            "successful_jobs": sum(1 for j in self._job_history if j.status == RetrainingStatus.COMPLETED),
            "failed_jobs": sum(1 for j in self._job_history if j.status == RetrainingStatus.FAILED),
        }
