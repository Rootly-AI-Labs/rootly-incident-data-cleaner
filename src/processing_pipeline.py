"""
PII Processing Pipeline
Professional orchestrator for PII detection, redaction, and validation
"""

import copy
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .policies.policy_manager import PIIPolicy
from .processing.deterministic_extractor import DeterministicExtractor
from .processing.llm_detector import LLMFinderProcessor
from .processing.llm_verifier import LLMJudgeProcessor
from .processing.arbitration_engine import ArbitrationProcessor
from .processing.quality_validator import ValidationProcessor
from .processing.llm_final_reviewer import LLMFinalReviewer
from .processing.allowlist import Allowlist, DEFAULT_ALLOWLIST_PATH
from config.llm_config import LLMConfigManager

logger = logging.getLogger(__name__)

OUTPUT_SCHEMA_VERSION = "1.1"

@dataclass
class ProcessingResult:
    """Complete result from PII processing pipeline"""
    original_text: str
    processed_text: str
    quality_metrics: Dict[str, Any]
    validation_issues: int
    critical_issues: int
    high_issues: int
    recommendations: list
    pseudonym_map: Dict[str, str]
    processing_stats: Dict[str, Any]
    audit_trail: Dict[str, Any]
    final_review: Optional[Dict[str, Any]] = None

class PIIProcessingPipeline:
    """Professional PII processing pipeline orchestrator"""
    
    def __init__(self, policy_path: Optional[str] = None, use_real_api: bool = False,
                 enable_final_review: bool = True,
                 allowlist_path: Optional[str] = DEFAULT_ALLOWLIST_PATH):
        """Initialize the processing pipeline with optional custom policy"""

        # Load policy
        if policy_path:
            self.policy = PIIPolicy.from_json(policy_path)
        else:
            self.policy = PIIPolicy()
            self.policy.load_default_policies()

        # Initialize LLM configuration
        self.config_manager = LLMConfigManager()
        if use_real_api:
            self.config_manager.config.enable_real_api = True

        # Load allowlist (None disables it, missing file silently no-ops)
        self.allowlist = Allowlist.from_file(allowlist_path) if allowlist_path else Allowlist.empty()

        # Initialize processing components
        self.deterministic_extractor = DeterministicExtractor(self.policy)
        self.llm_detector = LLMFinderProcessor(self.policy)
        self.llm_verifier = LLMJudgeProcessor(self.policy, self.config_manager)
        self.arbitration_engine = ArbitrationProcessor(self.policy, allowlist=self.allowlist)
        self.quality_validator = ValidationProcessor(self.policy)
        # Final LLM review only runs when real APIs are enabled — it is the
        # most expensive stage and exists to catch contextual leakage that
        # pattern-based validation cannot.
        self.final_reviewer = LLMFinalReviewer(
            self.config_manager,
            enabled=enable_final_review and use_real_api,
        )

        logger.info("PII Processing Pipeline initialized")
    
    async def process_text(self, text: str, output_dir: Optional[str] = None) -> ProcessingResult:
        """Process text through the complete PII processing pipeline"""

        processor = copy.copy(self)
        processor.deterministic_extractor = DeterministicExtractor(self.policy)
        processor.llm_detector = LLMFinderProcessor(self.policy)
        processor.llm_verifier = LLMJudgeProcessor(self.policy, self.config_manager)
        processor.arbitration_engine = ArbitrationProcessor(self.policy, allowlist=self.allowlist)
        processor.quality_validator = ValidationProcessor(self.policy)
        return await processor._process_text_once(text, output_dir)

    async def _process_text_once(self, text: str, output_dir: Optional[str] = None) -> ProcessingResult:
        """Run one incident with private detection and arbitration state."""
        
        logger.info("Starting PII processing pipeline")
        
        # Step 1: Deterministic Extraction
        logger.info("Step 1: Deterministic PII Extraction")
        deterministic_result = self.deterministic_extractor.extract_deterministic(text)
        
        # Step 2: LLM Detection
        logger.info("Step 2: LLM-based PII Detection")
        llm_detection_result = await self.llm_detector.find_llm_detections(deterministic_result)
        
        # Step 3: LLM Verification
        logger.info("Step 3: LLM Verification")
        llm_verification_result = await self.llm_verifier.judge_detections(llm_detection_result)
        
        # Step 4: Arbitration & Redaction
        logger.info("Step 4: Arbitration & Redaction")
        arbitration_result = self.arbitration_engine.arbitrate_and_redact(
            deterministic_result, llm_detection_result, llm_verification_result
        )
        
        # Step 5: Quality Validation
        logger.info("Step 5: Quality Validation")
        validation_result = self.quality_validator.validate_and_post_check(arbitration_result)

        # Step 6: LLM Final Review (only when real APIs enabled)
        logger.info("Step 6: LLM Final Review")
        final_review_result = await self.final_reviewer.review(validation_result.processed_text)

        # Prepare comprehensive results
        result = ProcessingResult(
            original_text=text,
            processed_text=validation_result.processed_text,
            quality_metrics={
                'overall_quality_score': validation_result.quality_metrics.overall_quality_score,
                'precision': validation_result.quality_metrics.precision,
                'recall': validation_result.quality_metrics.recall,
                'f1_score': validation_result.quality_metrics.f1_score,
                'residual_pii_count': validation_result.quality_metrics.residual_pii_count,
                'schema_violations': validation_result.quality_metrics.schema_violations
            },
            validation_issues=len(validation_result.validation_issues),
            critical_issues=len([i for i in validation_result.validation_issues if i.severity == 'critical']),
            high_issues=len([i for i in validation_result.validation_issues if i.severity == 'high']),
            recommendations=validation_result.recommendations,
            pseudonym_map=arbitration_result.pseudonym_map,
            processing_stats={
                'deterministic_entities': len(deterministic_result.detected_entities),
                'llm_detections': len(llm_detection_result.detected_spans),
                'llm_verifications': len(llm_verification_result.judge_decisions),
                'arbitration_decisions': len(arbitration_result.arbitration_decisions),
                'text_reduction_percentage': ((len(text) - len(validation_result.processed_text)) / len(text)) * 100 if text else 0.0
            },
            audit_trail={
                'deterministic_result': deterministic_result,
                'llm_detection_result': llm_detection_result,
                'llm_verification_result': llm_verification_result,
                'arbitration_result': arbitration_result,
                'validation_result': validation_result
            },
            final_review=final_review_result.to_dict()
        )
        
        # Save results if output directory specified
        if output_dir:
            self._save_results(result, output_dir)
        
        logger.info("PII processing pipeline completed")
        return result
    
    def _save_results(self, result: ProcessingResult, output_dir: str):
        """Save processing results to output directory"""
        import os
        import json
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save main results
        with open(output_path / "processing_results.json", "w") as f:
            json.dump({
                'schema_version': OUTPUT_SCHEMA_VERSION,
                'original_text': result.original_text,
                'processed_text': result.processed_text,
                'quality_metrics': result.quality_metrics,
                'validation_issues': result.validation_issues,
                'critical_issues': result.critical_issues,
                'high_issues': result.high_issues,
                'recommendations': result.recommendations,
                'pseudonym_map': result.pseudonym_map,
                'processing_stats': result.processing_stats,
                'final_review': result.final_review,
            }, f, indent=2)
        
        # Save detailed component results
        self.deterministic_extractor.save_results(result.audit_trail['deterministic_result'], str(output_path / "deterministic_extraction.json"))
        self.llm_detector.save_results(result.audit_trail['llm_detection_result'], str(output_path / "llm_detection.json"))
        self.llm_verifier.save_results(result.audit_trail['llm_verification_result'], str(output_path / "llm_verification.json"))
        self.arbitration_engine.save_results(result.audit_trail['arbitration_result'], str(output_path / "arbitration.json"))
        self.quality_validator.save_results(result.audit_trail['validation_result'], str(output_path / "quality_validation.json"))
        
        logger.info(f"Processing results saved to {output_path}")
