"""
Parallel PII Processing Pipeline
Enhanced orchestrator with parallel processing capabilities
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import time
import json
from datetime import datetime
from pathlib import Path

from .policies.policy_manager import PIIPolicy
from .processing.deterministic_extractor import DeterministicExtractor
from .processing.llm_detector import LLMFinderProcessor
from .processing.llm_verifier import LLMJudgeProcessor
from .processing.arbitration_engine import ArbitrationProcessor
from .processing.quality_validator import ValidationProcessor
from config.llm_config import LLMConfigManager

logger = logging.getLogger(__name__)

@dataclass
class ParallelProcessingResult:
    """Complete result from parallel PII processing pipeline"""
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
    parallel_stats: Dict[str, Any]

@dataclass
class ProcessingConfig:
    """Configuration for parallel processing"""
    max_concurrent_incidents: int = 5
    max_concurrent_llm_calls: int = 10
    enable_deterministic_parallel: bool = True
    enable_validation_parallel: bool = True
    chunk_size: int = 1000  # For large text processing
    timeout_seconds: int = 300

class ParallelPIIProcessingPipeline:
    """Enhanced PII processing pipeline with parallel execution capabilities"""
    
    def __init__(self, policy_path: Optional[str] = None, use_real_api: bool = False, 
                 config: Optional[ProcessingConfig] = None):
        """Initialize the parallel processing pipeline"""
        
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
        
        # Initialize processing components
        self.deterministic_extractor = DeterministicExtractor(self.policy)
        self.llm_detector = LLMFinderProcessor(self.policy)
        self.llm_verifier = LLMJudgeProcessor(self.policy, self.config_manager)
        self.arbitration_engine = ArbitrationProcessor(self.policy)
        self.quality_validator = ValidationProcessor(self.policy)
        
        # Parallel processing configuration
        self.config = config or ProcessingConfig()
        
        # Semaphores for controlling concurrency
        self.llm_semaphore = asyncio.Semaphore(self.config.max_concurrent_llm_calls)
        self.processing_semaphore = asyncio.Semaphore(self.config.max_concurrent_incidents)
        
        logger.info(f"Parallel PII Processing Pipeline initialized with config: {self.config}")
    
    async def process_text(self, text: str, output_dir: Optional[str] = None) -> ParallelProcessingResult:
        """Process text through the parallel PII processing pipeline"""
        
        start_time = time.time()
        logger.info(f"Starting parallel PII processing pipeline for text of length {len(text)}")
        
        # For very large texts, process in chunks
        if len(text) > self.config.chunk_size * 2:
            return await self._process_large_text(text, output_dir)
        
        # Parallel execution of independent stages
        try:
            # Step 1: Deterministic Extraction (can run in parallel with text preparation)
            logger.info("Step 1: Parallel Deterministic PII Extraction")
            deterministic_task = asyncio.create_task(
                self._run_deterministic_extraction(text)
            )
            
            # Wait for deterministic extraction to complete
            deterministic_result = await deterministic_task
            
            # Step 2 & 3: Parallel LLM Detection and Verification
            logger.info("Step 2-3: Parallel LLM Detection and Verification")
            llm_detection_task = asyncio.create_task(
                self._run_llm_detection_with_semaphore(deterministic_result)
            )
            
            # Wait for LLM detection
            llm_detection_result = await llm_detection_task
            
            # Step 3: LLM Verification (depends on detection)
            logger.info("Step 3: LLM Verification")
            llm_verification_result = await self._run_llm_verification_with_semaphore(llm_detection_result)
            
            # Step 4: Arbitration & Redaction (sequential, depends on all previous)
            logger.info("Step 4: Arbitration & Redaction")
            arbitration_result = await self._run_arbitration_parallel(
                deterministic_result, llm_detection_result, llm_verification_result
            )
            
            # Step 5: Quality Validation (can run in parallel with result preparation)
            logger.info("Step 5: Parallel Quality Validation")
            validation_task = asyncio.create_task(
                self._run_validation_parallel(arbitration_result)
            )
            
            # Prepare results while validation runs
            result_prep_task = asyncio.create_task(
                self._prepare_result_data(text, deterministic_result, llm_detection_result, 
                                       llm_verification_result, arbitration_result)
            )
            
            # Wait for both to complete
            validation_result, result_data = await asyncio.gather(validation_task, result_prep_task)
            
            # Calculate parallel processing statistics
            end_time = time.time()
            parallel_stats = self._calculate_parallel_stats(start_time, end_time, {
                'deterministic': deterministic_result,
                'llm_detection': llm_detection_result,
                'llm_verification': llm_verification_result,
                'arbitration': arbitration_result,
                'validation': validation_result
            })
            
            # Create final result
            result = ParallelProcessingResult(
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
                processing_stats=result_data['processing_stats'],
                audit_trail=result_data['audit_trail'],
                parallel_stats=parallel_stats
            )
            
            # Save results if output directory specified
            if output_dir:
                await self._save_results_parallel(result, output_dir)
            
            logger.info(f"Parallel PII processing pipeline completed in {end_time - start_time:.2f}s")
            return result
            
        except asyncio.TimeoutError:
            logger.error("Pipeline processing timed out")
            raise
        except Exception as e:
            logger.error(f"Error in parallel pipeline processing: {e}")
            raise
    
    async def _run_deterministic_extraction(self, text: str):
        """Run deterministic extraction in thread pool for CPU-bound work"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor, 
                self.deterministic_extractor.extract_deterministic, 
                text
            )
    
    async def _run_llm_detection_with_semaphore(self, deterministic_result):
        """Run LLM detection with semaphore control"""
        async with self.llm_semaphore:
            return await self.llm_detector.find_llm_detections(deterministic_result)
    
    async def _run_llm_verification_with_semaphore(self, llm_detection_result):
        """Run LLM verification with semaphore control"""
        async with self.llm_semaphore:
            return await self.llm_verifier.judge_detections(llm_detection_result)
    
    async def _run_arbitration_parallel(self, deterministic_result, llm_detection_result, llm_verification_result):
        """Run arbitration in thread pool for CPU-bound work"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor,
                self.arbitration_engine.arbitrate_and_redact,
                deterministic_result, llm_detection_result, llm_verification_result
            )
    
    async def _run_validation_parallel(self, arbitration_result):
        """Run validation in thread pool for CPU-bound work"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor,
                self.quality_validator.validate_and_post_check,
                arbitration_result
            )
    
    async def _prepare_result_data(self, text: str, deterministic_result, llm_detection_result, 
                                 llm_verification_result, arbitration_result):
        """Prepare result data in parallel"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor,
                self._build_result_data,
                text, deterministic_result, llm_detection_result, 
                llm_verification_result, arbitration_result
            )
    
    def _build_result_data(self, text: str, deterministic_result, llm_detection_result, 
                          llm_verification_result, arbitration_result):
        """Build result data structure"""
        return {
            'quality_metrics': {
                'overall_quality_score': 0.0,  # Will be updated by validation
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'residual_pii_count': 0,
                'schema_violations': 0
            },
            'processing_stats': {
                'deterministic_entities': len(deterministic_result.detected_entities),
                'llm_detections': len(llm_detection_result.detected_spans),
                'llm_verifications': len(llm_verification_result.judge_decisions),
                'arbitration_decisions': len(arbitration_result.arbitration_decisions),
                'text_reduction_percentage': ((len(text) - len(arbitration_result.processed_text)) / len(text)) * 100
            },
            'audit_trail': {
                'deterministic_result': deterministic_result,
                'llm_detection_result': llm_detection_result,
                'llm_verification_result': llm_verification_result,
                'arbitration_result': arbitration_result
            }
        }
    
    async def _process_large_text(self, text: str, output_dir: Optional[str] = None) -> ParallelProcessingResult:
        """Process large text by chunking and parallel processing"""
        logger.info(f"Processing large text ({len(text)} chars) in chunks of {self.config.chunk_size}")
        
        # Split text into chunks
        chunks = [text[i:i + self.config.chunk_size] for i in range(0, len(text), self.config.chunk_size)]
        
        # Process chunks in parallel
        chunk_tasks = []
        for i, chunk in enumerate(chunks):
            task = asyncio.create_task(self.process_text(chunk))
            chunk_tasks.append((i, task))
        
        # Wait for all chunks to complete
        chunk_results = []
        for i, task in chunk_tasks:
            try:
                result = await task
                chunk_results.append((i, result))
            except Exception as e:
                logger.error(f"Error processing chunk {i}: {e}")
                continue
        
        # Merge results
        return self._merge_chunk_results(chunk_results, text, output_dir)
    
    def _merge_chunk_results(self, chunk_results: List[Tuple[int, ParallelProcessingResult]], 
                           original_text: str, output_dir: Optional[str] = None) -> ParallelProcessingResult:
        """Merge results from multiple chunks"""
        # Sort by chunk index
        chunk_results.sort(key=lambda x: x[0])
        
        # Combine processed text
        processed_text = ''.join(result.processed_text for _, result in chunk_results)
        
        # Combine pseudonym maps
        combined_pseudonym_map = {}
        for _, result in chunk_results:
            combined_pseudonym_map.update(result.pseudonym_map)
        
        # Aggregate statistics
        total_validation_issues = sum(result.validation_issues for _, result in chunk_results)
        total_critical_issues = sum(result.critical_issues for _, result in chunk_results)
        total_high_issues = sum(result.high_issues for _, result in chunk_results)
        
        # Combine recommendations
        all_recommendations = []
        for _, result in chunk_results:
            all_recommendations.extend(result.recommendations)
        
        # Use the first chunk's structure as base
        base_result = chunk_results[0][1]
        
        return ParallelProcessingResult(
            original_text=original_text,
            processed_text=processed_text,
            quality_metrics=base_result.quality_metrics,
            validation_issues=total_validation_issues,
            critical_issues=total_critical_issues,
            high_issues=total_high_issues,
            recommendations=list(set(all_recommendations)),  # Remove duplicates
            pseudonym_map=combined_pseudonym_map,
            processing_stats=base_result.processing_stats,
            audit_trail=base_result.audit_trail,
            parallel_stats={
                'chunks_processed': len(chunk_results),
                'total_chunks': len(chunk_results),
                'chunk_processing_mode': True
            }
        )
    
    def _calculate_parallel_stats(self, start_time: float, end_time: float, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate parallel processing statistics"""
        total_time = end_time - start_time
        
        return {
            'total_processing_time': total_time,
            'parallel_efficiency': 1.0,  # Simplified calculation
            'concurrent_operations': self.config.max_concurrent_llm_calls,
            'stages_completed': len(results),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _save_results_parallel(self, result: ParallelProcessingResult, output_dir: str):
        """Save processing results in parallel"""
        import os
        import json
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save main results
        main_results = {
            'original_text': result.original_text,
            'processed_text': result.processed_text,
            'quality_metrics': result.quality_metrics,
            'validation_issues': result.validation_issues,
            'critical_issues': result.critical_issues,
            'high_issues': result.high_issues,
            'recommendations': result.recommendations,
            'pseudonym_map': result.pseudonym_map,
            'processing_stats': result.processing_stats,
            'parallel_stats': result.parallel_stats
        }
        
        # Save files in parallel
        save_tasks = []
        
        # Main results file
        save_tasks.append(asyncio.create_task(
            self._save_json_file(output_path / "processing_results.json", main_results)
        ))
        
        # Component results files - use the component's own save methods
        if 'deterministic_result' in result.audit_trail:
            save_tasks.append(asyncio.create_task(
                self._save_component_with_method(
                    self.deterministic_extractor.save_results,
                    result.audit_trail['deterministic_result'], 
                    output_path / "deterministic_extraction.json"
                )
            ))
        
        if 'llm_detection_result' in result.audit_trail:
            save_tasks.append(asyncio.create_task(
                self._save_component_with_method(
                    self.llm_detector.save_results,
                    result.audit_trail['llm_detection_result'], 
                    output_path / "llm_detection.json"
                )
            ))
        
        if 'llm_verification_result' in result.audit_trail:
            save_tasks.append(asyncio.create_task(
                self._save_component_with_method(
                    self.llm_verifier.save_results,
                    result.audit_trail['llm_verification_result'], 
                    output_path / "llm_verification.json"
                )
            ))
        
        if 'arbitration_result' in result.audit_trail:
            save_tasks.append(asyncio.create_task(
                self._save_component_with_method(
                    self.arbitration_engine.save_results,
                    result.audit_trail['arbitration_result'], 
                    output_path / "arbitration.json"
                )
            ))
        
        if 'validation_result' in result.audit_trail:
            save_tasks.append(asyncio.create_task(
                self._save_component_with_method(
                    self.quality_validator.save_results,
                    result.audit_trail['validation_result'], 
                    output_path / "quality_validation.json"
                )
            ))
        
        # Wait for all saves to complete
        await asyncio.gather(*save_tasks)
        
        logger.info(f"Parallel processing results saved to {output_path}")
    
    async def _save_json_file(self, file_path: Path, data: Dict[str, Any]):
        """Save JSON data to file asynchronously"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                self._write_json_file,
                file_path, data
            )
    
    def _write_json_file(self, file_path: Path, data: Dict[str, Any]):
        """Write JSON data to file"""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    async def _save_component_with_method(self, save_method, result, file_path: Path):
        """Save component result using the component's own save method"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                save_method,
                result, str(file_path)
            )
    
    async def _save_component_result(self, result, file_path: Path):
        """Save component result to file"""
        # Use the existing save methods from the components
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                self._write_component_file,
                file_path, result
            )
    
    def _write_component_file(self, file_path: Path, result):
        """Write component result to file"""
        # Try to use the component's own save method if available
        if hasattr(result, '__dict__'):
            # Convert dataclass/object to dict for JSON serialization
            try:
                if hasattr(result, '__dataclass_fields__'):
                    # It's a dataclass
                    data = {
                        field: getattr(result, field) 
                        for field in result.__dataclass_fields__
                    }
                else:
                    # Regular object
                    data = result.__dict__
                
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            except Exception as e:
                # Fallback to string representation
                with open(file_path, 'w') as f:
                    json.dump({'error': f'Could not serialize result: {str(e)}', 'type': str(type(result))}, f, indent=2)
        else:
            # Fallback for non-objects
            with open(file_path, 'w') as f:
                json.dump({'result': str(result), 'type': str(type(result))}, f, indent=2)

    async def process_multiple_incidents(self, incidents: List[Dict[str, Any]], 
                                       output_dir: Optional[str] = None) -> List[ParallelProcessingResult]:
        """Process multiple incidents in parallel"""
        
        logger.info(f"Processing {len(incidents)} incidents in parallel")
        
        # Create semaphore for incident processing
        incident_semaphore = asyncio.Semaphore(self.config.max_concurrent_incidents)
        
        async def process_single_incident(incident: Dict[str, Any], incident_id: str):
            """Process a single incident with semaphore control"""
            async with incident_semaphore:
                try:
                    # Extract text for processing
                    text_to_process = self._extract_text_from_incident(incident)
                    
                    # Create incident-specific output directory
                    incident_output_dir = None
                    if output_dir:
                        from pathlib import Path
                        incident_output_dir = str(Path(output_dir) / f"incident_{incident_id}")
                    
                    # Process through pipeline
                    result = await self.process_text(text_to_process, incident_output_dir)
                    
                    logger.info(f"Successfully processed incident {incident_id}")
                    return result
                    
                except Exception as e:
                    logger.error(f"Error processing incident {incident_id}: {e}")
                    raise
        
        # Create tasks for all incidents
        tasks = []
        for i, incident in enumerate(incidents):
            incident_id = self._extract_incident_id(incident)
            task = asyncio.create_task(process_single_incident(incident, incident_id))
            tasks.append(task)
        
        # Process all incidents in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return successful results
        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to process incident {i}: {result}")
            else:
                successful_results.append(result)
        
        logger.info(f"Successfully processed {len(successful_results)}/{len(incidents)} incidents")
        return successful_results
    
    def _extract_incident_id(self, incident: Dict[str, Any]) -> str:
        """Extract incident ID from incident data"""
        # Try common ID field names
        id_fields = ['id', 'incident_id', 'incidentId', 'incident-id', 'ticket_id', 'ticketId']
        
        for field in id_fields:
            if field in incident:
                return str(incident[field])
        
        # If no ID field found, generate one from title or use timestamp
        if 'title' in incident:
            title_id = ''.join(c for c in incident['title'][:20] if c.isalnum())
            return f"incident_{title_id}"
        
        return f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _extract_text_from_incident(self, incident: Dict[str, Any]) -> str:
        """Extract all text content from incident for processing"""
        text_parts = []
        
        # Add title
        if 'title' in incident:
            text_parts.append(f"Title: {incident['title']}")
        
        # Add summary
        if 'summary' in incident:
            text_parts.append(f"Summary: {incident['summary']}")
        
        # Add description
        if 'description' in incident:
            text_parts.append(f"Description: {incident['description']}")
        
        # Add participants info
        if 'participants' in incident:
            text_parts.append("Participants:")
            for participant in incident['participants']:
                if isinstance(participant, dict):
                    if 'name' in participant and 'email' in participant:
                        text_parts.append(f"- {participant['name']} ({participant['email']})")
                    elif 'email' in participant:
                        text_parts.append(f"- {participant['email']}")
        
        return "\n".join(text_parts)
