"""Main SQL Injection Agent - orchestrates all protection layers."""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from sql_injection_protector.core.config import Settings, load_config
from sql_injection_protector.core.result import (
    Action,
    Decision,
    DetectionResult,
    DetectorType,
    ThreatLevel,
)
from sql_injection_protector.core.exceptions import (
    DetectionError,
    ModelLoadError,
    SQLIProtectorError,
)
from sql_injection_protector.layers.request.context import RequestContext


logger = logging.getLogger(__name__)


class SQLInjectionAgent:
    """
    Main SQL Injection Protection Agent.

    Orchestrates all protection layers:
    1. Preprocessing - Normalize and decode input
    2. Feature Extraction - Extract static and behavioral features
    3. Detection - Run signature, ML, and heuristic detection
    4. Decision - Determine action based on detection results
    5. Response - Execute action (block, challenge, sanitize, etc.)
    6. Learning - Collect payloads for retraining
    7. Observability - Log and export metrics

    Usage:
        agent = SQLInjectionAgent(settings=config)
        await agent.initialize()

        decision = await agent.analyze_request(context)
        if decision.should_block():
            return blocked_response
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        config_path: Optional[str] = None,
    ):
        """
        Initialize SQL Injection Agent.

        Args:
            settings: Pre-loaded settings object
            config_path: Path to YAML config file
        """
        if settings is not None:
            self.settings = settings
        elif config_path is not None:
            self.settings = load_config(config_path)
        else:
            self.settings = Settings()

        self._initialized = False

        # Layer components (lazy-loaded)
        self._preprocessing_pipeline = None
        self._feature_extractor = None
        self._signature_detector = None
        self._heuristic_detector = None
        self._ml_detector = None
        self._decision_engine = None
        self._rate_limiter = None
        self._session_manager = None
        self._honeypot_manager = None
        self._sanitizer = None
        self._payload_collector = None
        self._metrics_collector = None
        self._cef_formatter = None
        self._audit_logger = None
        self._redis_client = None

    async def initialize(self) -> None:
        """Initialize all components."""
        if self._initialized:
            return

        logger.info("Initializing SQL Injection Agent...")

        try:
            # Initialize Redis if enabled
            if self.settings.rate_limiting.enabled:
                await self._init_redis()

            # Initialize preprocessing
            await self._init_preprocessing()

            # Initialize feature extraction
            await self._init_features()

            # Initialize detectors
            await self._init_detectors()

            # Initialize decision engine
            await self._init_decision()

            # Initialize response components
            await self._init_response()

            # Initialize learning components
            await self._init_learning()

            # Initialize observability
            await self._init_observability()

            self._initialized = True
            logger.info("SQL Injection Agent initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize agent: {e}")
            raise SQLIProtectorError(f"Initialization failed: {e}") from e

    async def _init_redis(self) -> None:
        """Initialize Redis client."""
        from sql_injection_protector.storage.redis import RedisClient

        self._redis_client = RedisClient(
            url=self.settings.rate_limiting.redis_url,
            prefix="sqli:",
        )
        await self._redis_client.connect()
        logger.debug("Redis client initialized")

    async def _init_preprocessing(self) -> None:
        """Initialize preprocessing pipeline."""
        from sql_injection_protector.layers.preprocessing.pipeline import (
            PreprocessingPipeline,
        )

        self._preprocessing_pipeline = PreprocessingPipeline(
            max_decode_iterations=5,
            normalize_unicode=True,
            normalize_case=True,
            remove_comments=False,  # Keep for detection
        )
        logger.debug("Preprocessing pipeline initialized")

    async def _init_features(self) -> None:
        """Initialize feature extractors."""
        from sql_injection_protector.layers.features.static import (
            StaticFeatureExtractor,
        )
        from sql_injection_protector.layers.features.behavioral import (
            BehavioralFeatureExtractor,
        )
        from sql_injection_protector.layers.features.vector import (
            FeatureVectorBuilder,
        )

        static_extractor = StaticFeatureExtractor()
        behavioral_extractor = None

        if self._redis_client:
            behavioral_extractor = BehavioralFeatureExtractor(
                redis_client=self._redis_client,
            )

        self._feature_extractor = FeatureVectorBuilder(
            static_extractor=static_extractor,
            behavioral_extractor=behavioral_extractor,
        )
        logger.debug("Feature extractors initialized")

    async def _init_detectors(self) -> None:
        """Initialize detection components."""
        from sql_injection_protector.layers.detection.signature import (
            SignatureDetector,
        )
        from sql_injection_protector.layers.detection.heuristic import (
            HeuristicAnalyzer,
        )

        # Signature detector
        self._signature_detector = SignatureDetector()

        # Heuristic detector
        self._heuristic_detector = HeuristicAnalyzer()

        # ML detector (based on config)
        await self._init_ml_detector()

        logger.debug("Detectors initialized")

    async def _init_ml_detector(self) -> None:
        """Initialize ML detector based on configuration."""
        model_type = self.settings.detection.model_type
        model_path = self.settings.detection.model_path

        try:
            if model_type == "transformer":
                from sql_injection_protector.layers.detection.ml.transformer import (
                    TransformerDetector,
                    LightweightTransformerDetector,
                )

                try:
                    self._ml_detector = TransformerDetector(model_path=model_path)
                    await self._ml_detector.load()
                except Exception as e:
                    logger.warning(f"Failed to load Transformer model: {e}")
                    logger.info("Falling back to lightweight model")
                    self._ml_detector = LightweightTransformerDetector()
                    await self._ml_detector.load()
            else:
                # Default to TF-IDF
                from sql_injection_protector.layers.detection.ml.tfidf import (
                    TFIDFDetector,
                )

                self._ml_detector = TFIDFDetector(model_path=model_path)
                await self._ml_detector.load()

        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")
            logger.info("ML detection will be disabled")
            self._ml_detector = None

    async def _init_decision(self) -> None:
        """Initialize decision engine."""
        from sql_injection_protector.layers.decision.engine import DecisionEngine
        from sql_injection_protector.layers.decision.policies import (
            DecisionPolicy,
            PolicyMode,
            ThresholdConfig,
            DetectorWeights,
        )

        # Build policy from settings
        mode = PolicyMode.STRICT if self.settings.decision.strict_mode else PolicyMode.BALANCED
        if self.settings.decision.learning_mode:
            mode = PolicyMode.LEARNING

        policy = DecisionPolicy(
            mode=mode,
            thresholds=ThresholdConfig(
                block=self.settings.decision.block_threshold,
                challenge=self.settings.decision.challenge_threshold,
                alert=self.settings.decision.alert_threshold,
                sanitize=self.settings.decision.sanitize_threshold,
            ),
            weights=DetectorWeights(
                signature=self.settings.detection.signature_weight,
                ml=self.settings.detection.ml_weight,
                heuristic=self.settings.detection.heuristic_weight,
            ),
        )

        self._decision_engine = DecisionEngine(policy=policy)
        logger.debug("Decision engine initialized")

    async def _init_response(self) -> None:
        """Initialize response components."""
        # Rate limiter
        if self.settings.rate_limiting.enabled and self._redis_client:
            from sql_injection_protector.layers.response.rate_limiter import (
                AdaptiveRateLimiter,
            )

            self._rate_limiter = AdaptiveRateLimiter(
                redis_client=self._redis_client,
                base_rpm=self.settings.rate_limiting.requests_per_minute,
                base_rph=self.settings.rate_limiting.requests_per_hour,
            )

        # Session manager
        if self._redis_client:
            from sql_injection_protector.layers.response.session import (
                SessionManager,
            )

            self._session_manager = SessionManager(
                redis_client=self._redis_client,
            )

        # Honeypot
        if self.settings.honeypot.enabled:
            from sql_injection_protector.layers.response.honeypot import (
                HoneypotManager,
            )

            self._honeypot_manager = HoneypotManager(
                endpoints=self.settings.honeypot.endpoints,
            )

        # Sanitizer
        from sql_injection_protector.layers.response.sanitizer import (
            ContextAwareSanitizer,
        )

        self._sanitizer = ContextAwareSanitizer()

        logger.debug("Response components initialized")

    async def _init_learning(self) -> None:
        """Initialize learning components."""
        if not self.settings.learning.collect_payloads:
            return

        from sql_injection_protector.layers.learning.collector import (
            PayloadCollector,
        )

        self._payload_collector = PayloadCollector(
            redis_client=self._redis_client,
            max_queue_size=10000,
        )
        logger.debug("Learning components initialized")

    async def _init_observability(self) -> None:
        """Initialize observability components."""
        # Metrics collector
        if self.settings.observability.prometheus_enabled:
            from sql_injection_protector.layers.observability.metrics import (
                MetricsCollector,
            )

            self._metrics_collector = MetricsCollector()

        # CEF formatter
        if self.settings.observability.cef_enabled:
            from sql_injection_protector.layers.observability.cef import (
                CEFFormatter,
            )

            self._cef_formatter = CEFFormatter(
                device_vendor="SQLInjectionProtector",
                device_product="AI-Agent",
                device_version="1.0.0",
            )

        # Audit logger
        from sql_injection_protector.layers.observability.persistence import (
            AuditLogger,
        )

        self._audit_logger = AuditLogger()

        logger.debug("Observability components initialized")

    async def analyze_request(
        self,
        context: RequestContext,
    ) -> Decision:
        """
        Analyze a request for SQL injection.

        This is the main entry point for request analysis.

        Args:
            context: Request context with all relevant data

        Returns:
            Decision object with action and metadata
        """
        if not self._initialized:
            await self.initialize()

        start_time = asyncio.get_event_loop().time()

        try:
            # Check honeypot first
            if self._honeypot_manager:
                if self._honeypot_manager.is_honeypot(context.path):
                    await self._handle_honeypot(context)
                    return Decision(
                        action=Action.BLOCK,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=1.0,
                        reason="Honeypot endpoint accessed",
                        response_code=403,
                        response_body="Forbidden",
                    )

            # Check rate limiting
            if self._rate_limiter:
                rate_result = await self._rate_limiter.check(
                    context.client_ip,
                    context.path,
                )
                if rate_result.blocked:
                    return Decision(
                        action=Action.RATE_LIMIT,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=1.0,
                        reason="Rate limit exceeded",
                        response_code=429,
                        response_body="Too Many Requests",
                        response_headers={
                            "Retry-After": str(rate_result.retry_after),
                        },
                    )

            # Extract all input data
            inputs = self._extract_inputs(context)

            # Run analysis pipeline
            detection_results = await self._analyze_inputs(inputs, context)

            # Make decision
            decision = await self._decision_engine.decide(
                results=detection_results,
                context=context,
            )

            # Post-processing
            await self._post_process(context, decision, detection_results)

            # Record metrics
            elapsed = asyncio.get_event_loop().time() - start_time
            await self._record_metrics(context, decision, elapsed)

            return decision

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            # Fail open - allow request on error
            return Decision(
                action=Action.ALLOW,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.0,
                reason=f"Analysis error: {e}",
            )

    def _extract_inputs(self, context: RequestContext) -> Dict[str, str]:
        """Extract all inputs to analyze from context."""
        inputs = {}

        # Query parameters
        for key, value in context.query_params.items():
            if isinstance(value, list):
                for i, v in enumerate(value):
                    inputs[f"query.{key}[{i}]"] = str(v)
            else:
                inputs[f"query.{key}"] = str(value)

        # Full query string
        if context.query_string:
            inputs["query_string"] = context.query_string

        # Body
        if context.body_text:
            inputs["body"] = context.body_text

        # Cookies
        for key, value in context.cookies.items():
            inputs[f"cookie.{key}"] = str(value)

        # Specific headers
        for header in ["User-Agent", "Referer", "X-Forwarded-For"]:
            value = context.headers.get(header.lower()) or context.headers.get(header)
            if value:
                inputs[f"header.{header}"] = value

        # Path
        inputs["path"] = context.path

        return inputs

    async def _analyze_inputs(
        self,
        inputs: Dict[str, str],
        context: RequestContext,
    ) -> List[DetectionResult]:
        """Analyze all inputs through detection pipeline."""
        results = []

        for input_name, input_value in inputs.items():
            if not input_value:
                continue

            # Preprocess
            processed = self._preprocessing_pipeline.process(input_value)

            # Extract features
            features = await self._feature_extractor.build(
                text=processed.normalized,
                tokens=processed.tokens,
                context=context,
            )

            # Run detectors in parallel
            detector_results = await asyncio.gather(
                self._run_signature_detection(processed.normalized, input_name),
                self._run_heuristic_detection(processed.normalized, features, input_name),
                self._run_ml_detection(processed.normalized, input_name),
                return_exceptions=True,
            )

            # Collect valid results
            for result in detector_results:
                if isinstance(result, DetectionResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Detector error: {result}")

        return results

    async def _run_signature_detection(
        self,
        text: str,
        input_name: str,
    ) -> Optional[DetectionResult]:
        """Run signature-based detection."""
        if not self._signature_detector:
            return None

        try:
            is_sqli, confidence, matched_rules = self._signature_detector.detect(text)

            return DetectionResult(
                is_injection=is_sqli,
                confidence=confidence,
                detector_type=DetectorType.SIGNATURE,
                threat_level=self._confidence_to_threat(confidence) if is_sqli else ThreatLevel.NONE,
                matched_patterns=matched_rules,
                input_field=input_name,
            )
        except Exception as e:
            logger.error(f"Signature detection error: {e}")
            return None

    async def _run_heuristic_detection(
        self,
        text: str,
        features: Dict[str, float],
        input_name: str,
    ) -> Optional[DetectionResult]:
        """Run heuristic detection."""
        if not self._heuristic_detector:
            return None

        try:
            is_sqli, confidence, reasons = self._heuristic_detector.analyze(
                text,
                features,
            )

            return DetectionResult(
                is_injection=is_sqli,
                confidence=confidence,
                detector_type=DetectorType.HEURISTIC,
                threat_level=self._confidence_to_threat(confidence) if is_sqli else ThreatLevel.NONE,
                matched_patterns=reasons,
                input_field=input_name,
            )
        except Exception as e:
            logger.error(f"Heuristic detection error: {e}")
            return None

    async def _run_ml_detection(
        self,
        text: str,
        input_name: str,
    ) -> Optional[DetectionResult]:
        """Run ML-based detection."""
        if not self._ml_detector:
            return None

        try:
            is_sqli, confidence = await self._ml_detector.predict(text)

            return DetectionResult(
                is_injection=is_sqli,
                confidence=confidence,
                detector_type=DetectorType.ML,
                threat_level=self._confidence_to_threat(confidence) if is_sqli else ThreatLevel.NONE,
                input_field=input_name,
            )
        except Exception as e:
            logger.error(f"ML detection error: {e}")
            return None

    def _confidence_to_threat(self, confidence: float) -> ThreatLevel:
        """Convert confidence score to threat level."""
        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        elif confidence >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.NONE

    async def _handle_honeypot(self, context: RequestContext) -> None:
        """Handle honeypot access."""
        if self._honeypot_manager:
            await self._honeypot_manager.record_access(
                ip=context.client_ip,
                path=context.path,
                user_agent=context.user_agent,
            )

        # Collect payload
        if self._payload_collector:
            await self._payload_collector.collect(
                payload=context.full_url,
                source="honeypot",
                metadata={
                    "ip": context.client_ip,
                    "path": context.path,
                },
            )

    async def _post_process(
        self,
        context: RequestContext,
        decision: Decision,
        results: List[DetectionResult],
    ) -> None:
        """Post-process after decision."""
        # Update session trust
        if self._session_manager and context.session_id:
            if decision.action == Action.BLOCK:
                await self._session_manager.decrease_trust(
                    context.session_id,
                    amount=0.2,
                )
            elif decision.action == Action.ALLOW and decision.confidence < 0.3:
                await self._session_manager.increase_trust(
                    context.session_id,
                    amount=0.05,
                )

        # Collect blocked payloads for learning
        if decision.action == Action.BLOCK and self._payload_collector:
            inputs = self._extract_inputs(context)
            for input_name, input_value in inputs.items():
                if input_value:
                    await self._payload_collector.collect(
                        payload=input_value,
                        source="blocked",
                        is_malicious=True,
                        confidence=decision.confidence,
                        metadata={
                            "input_field": input_name,
                            "reason": decision.reason,
                        },
                    )

        # Log to audit
        if self._audit_logger:
            await self._audit_logger.log(
                context=context,
                decision=decision,
                results=results,
            )

        # Format CEF log
        if self._cef_formatter and decision.action in (Action.BLOCK, Action.ALERT):
            cef_log = self._cef_formatter.format(
                context=context,
                decision=decision,
            )
            logger.info(cef_log)

    async def _record_metrics(
        self,
        context: RequestContext,
        decision: Decision,
        elapsed: float,
    ) -> None:
        """Record metrics."""
        if not self._metrics_collector:
            return

        self._metrics_collector.record_request(
            action=decision.action.value,
            source=context.client_ip,
        )

        self._metrics_collector.record_confidence(decision.confidence)
        self._metrics_collector.record_latency(elapsed)

        if decision.action == Action.RATE_LIMIT:
            self._metrics_collector.record_rate_limit(context.client_ip)

    async def analyze_text(self, text: str) -> DetectionResult:
        """
        Simple text analysis without full request context.

        Args:
            text: Text to analyze

        Returns:
            DetectionResult with analysis outcome
        """
        if not self._initialized:
            await self.initialize()

        # Preprocess
        processed = self._preprocessing_pipeline.process(text)

        # Run all detectors
        results = await asyncio.gather(
            self._run_signature_detection(processed.normalized, "text"),
            self._run_ml_detection(processed.normalized, "text"),
            return_exceptions=True,
        )

        # Combine results
        is_sqli = False
        max_confidence = 0.0
        all_patterns = []

        for result in results:
            if isinstance(result, DetectionResult):
                if result.is_injection:
                    is_sqli = True
                    if result.confidence > max_confidence:
                        max_confidence = result.confidence
                    if result.matched_patterns:
                        all_patterns.extend(result.matched_patterns)

        return DetectionResult(
            is_injection=is_sqli,
            confidence=max_confidence,
            detector_type=DetectorType.ENSEMBLE,
            threat_level=self._confidence_to_threat(max_confidence) if is_sqli else ThreatLevel.NONE,
            matched_patterns=all_patterns,
        )

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources."""
        logger.info("Shutting down SQL Injection Agent...")

        if self._redis_client:
            await self._redis_client.close()

        self._initialized = False
        logger.info("SQL Injection Agent shutdown complete")

    def __del__(self):
        """Cleanup on deletion."""
        if self._initialized:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.shutdown())
                else:
                    loop.run_until_complete(self.shutdown())
            except Exception:
                pass
