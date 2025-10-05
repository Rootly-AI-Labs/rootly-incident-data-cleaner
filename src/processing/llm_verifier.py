"""
Stage 5: LLM Verification (Judge)
Purpose: Validate flagged spans and decide whether to redact, pseudonymize, or keep.
Judge LLM uses focused snippets and strict policy prompts to return JSON 
{keep_redaction: bool, replacement_hint: string}.
Behavior: Secrets are always redacted; emails, names, or hostnames are pseudonymized 
or retained per policy.
"""

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from ..core.llm_clients import OpenAIClient, AnthropicClient, LLMClient
from config.llm_config import LLMConfigManager, LLMProvider, LLMModel
from ..policies.policy_manager import PIIPolicy, RedactionAction, DataCategory
from .llm_detector import LLMFinderResult, LLMDetection

logger = logging.getLogger(__name__)

@dataclass
class JudgeDecision:
    """Decision from LLM Judge"""
    entity_id: str
    original_text: str
    entity_type: str
    confidence_score: float
    
    # Judge decision
    keep_redaction: bool
    replacement_hint: Optional[str]
    final_action: RedactionAction
    decision_confidence: float
    reasoning: str
    
    # Compliance info
    policy_violation_level: str
    risk_factors: List[str]
    policy_alignment: bool
    
    # Metadata
    judge_model: str
    processing_time_ms: int
    timestamp: str

@dataclass
class JudgeResult:
    """Complete result from LLM Judge stage"""
    original_text: str
    input_detections: List[LLMDetection]
    judge_decisions: List[JudgeDecision]
    policy_summary: Dict[str, Any]
    processing_stats: Dict[str, Any]
    timestamp: str

class LLMJudgeProcessor:
    """Main processor for Stage 5: LLM Verification (Judge)"""
    
    def __init__(self, policy: PIIPolicy, config_manager: Optional[LLMConfigManager] = None):
        self.policy = policy
        self.config_manager = config_manager or LLMConfigManager()
        
        # Initialize LLM clients
        self.finder_client = self._init_client(self.config_manager.config.finder_model)
        self.judge_client = self._init_client(self.config_manager.config.judge_model)
        
        # Policy context for Judge
        self.policy_context = self._build_policy_context()
        
        # Processing statistics
        self.stats = {
            'total_judgements': 0,
            'redaction_decisions': 0,
            'pseudonymize_decisions': 0,
            'retain_decisions': 0,
            'api_calls_made': 0,
            'api_errors': 0,
            'avg_processing_time': 0.0
        }
    
    def _init_client(self, model: LLMModel) -> LLMClient:
        """Initialize appropriate LLM client"""
        if model.provider == LLMProvider.OPENAI:
            return OpenAIClient(model)
        elif model.provider == LLMProvider.ANTHROPIC:
            return AnthropicClient(model)
        else:
            raise ValueError(f"Unsupported provider: {model.provider}")
    
    def _build_policy_context(self) -> str:
        """Build policy context for Judge prompts"""
        context = "PII REDACTION POLICY:\n\n"
        
        context += "CRITICAL SENSITIVITY (Always REDACT):\n"
        context += "- Social Security Numbers (SSN)\n"
        context += "- Credit Card Numbers\n"
        context += "- API Keys and Secrets\n"
        context += "- Database URLs\n"
        context += "- Financial account numbers\n\n"
        
        context += "HIGH SENSITIVITY (Usually REDACT or PSEUDONYMIZE):\n"
        context += "- Email addresses (except public support emails)\n"
        context += "- Personal phone numbers\n"
        context += "- Addresses\n"
        context += "- Driver's license numbers\n\n"
        
        context += "MEDIUM SENSITIVITY (Usually PSEUDONYMIZE):\n"
        context += "- Person names (employee/contractor names)\n"
        context += "- Internal hostnames/servers\n"
        context += "- Customer IDs\n"
        context += "- JIRA ticket references\n\n"
        
        context += "LOW SENSITIVITY (Usually RETAIN):\n"
        context += "- Company names\n"
        context += "- General location mentions\n"
        context += "- Public URLs\n"
        context += "- Non-personal technical terms\n\n"
        
        context += "COMPLIANCE REQUIREMENTS:\n"
        context += "- GDPR: Minimize personal data processing\n"
        context += "- CCPA: Protect consumer privacy rights\n"
        context += "- SOX: Secure financial/internal communications\n"
        context += "- HIPAA: Protect healthcare information\n\n"
        
        context += "CONTEXTUAL FACTORS:\n"
        context += "- Include security incident reports (HIGH risk)\n"
        context += "- Employee discussions (MEDIUM risk)\n"
        context += "- Public documentation (LOW risk)\n"
        context += "- Customer support chats (HIGH risk)\n"
        
        return context
    
    async def judge_detections(self, finder_result: LLMFinderResult) -> JudgeResult:
        """Main method to perform LLM Judge verification"""
        logger.info(f"Starting LLM Judge verification for {len(finder_result.detected_spans)} detections")
        
        start_time = datetime.now()
        
        # Step 1: Prepare detections for judgement
        judgements_needed = self._filter_detections_for_judgement(finder_result.detected_spans)
        
        # Step 2: Process judgements in batches
        judge_decisions = []
        
        # Process in smaller batches to avoid rate limits
        batch_size = 5
        for i in range(0, len(judgements_needed), batch_size):
            batch = judgements_needed[i:i + batch_size]
            batch_decisions = await self._process_judgement_batch(
                finder_result.original_text, 
                batch
            )
            judge_decisions.extend(batch_decisions)
            
            # Small delay between batches
            if i + batch_size < len(judgements_needed):
                await asyncio.sleep(1)
        
        # Step 3: Generate processing statistics
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds() * 1000
        
        processing_stats = self._generate_processing_stats(
            finder_result, 
            judge_decisions, 
            processing_time
        )
        
        # Step 4: Generate policy compliance summary
        policy_summary = self._generate_policy_summary(judge_decisions)
        
        logger.info(f"LLM Judge complete: {len(judge_decisions)} decisions processed")
        
        return JudgeResult(
            original_text=finder_result.original_text,
            input_detections=finder_result.detected_spans,
            judge_decisions=judge_decisions,
            policy_summary=policy_summary,
            processing_stats=processing_stats,
            timestamp=datetime.now().isoformat()
        )
    
    def _filter_detections_for_judgement(self, detections: List[LLMDetection]) -> List[LLMDetection]:
        """Filter detections that need LLM Judge verification"""
        
        judgements_needed = []
        
        for detection in detections:
            # Skip very high confidence decisions unless they're secrets
            if detection.confidence_score >= 0.95 and 'secret' not in detection.entity_type.lower():
                # Auto-decide based on policy for very high confidence
                if 'email' in detection.entity_type.lower():
                    final_action = RedactionAction.REDACT
                elif 'person_name' in detection.entity_type.lower():
                    final_action = RedactionAction.PSEUDONYMIZE
                else:
                    final_action = RedactionAction.RETAIN
                
                decision = JudgeDecision(
                    entity_id=detection.span_id,
                    original_text=detection.detected_text,
                    entity_type=detection.entity_type,
                    confidence_score=detection.confidence_score,
                    keep_redaction=final_action != RedactionAction.RETAIN,
                    replacement_hint=None,
                    final_action=final_action,
                    decision_confidence=detection.confidence_score,
                    reasoning=f"Auto-decided based on high confidence ({detection.confidence_score:.2f}) and policy mapping",
                    policy_violation_level='MEDIUM',
                    risk_factors=['high_confidence'],
                    policy_alignment=True,
                    judge_model='policy_auto',
                    processing_time_ms=0,
                    timestamp=datetime.now().isoformat()
                )
                
                # Add to judgements_needed for summary, but bypass LLM
                continue
            
            # All other detections need LLM judgement
            judgements_needed.append(detection)
        
        logger.info(f"Require LLM judgement: {len(judgements_needed)}, Auto-decided: {len(detections) - len(judgements_needed)}")
        return judgements_needed
    
    async def _process_judgement_batch(self, text: str, detections: List[LLMDetection]) -> List[JudgeDecision]:
        """Process a batch of judgements"""
        decisions = []
        
        for detection in detections:
            try:
                start_time = datetime.now()
                
                # Use appropriate client (Finder for analysis, Judge for decisions)
                judgement_result = await self.judge_client.judge_redaction(
                    text=text,
                    detected_entity=asdict(detection),
                    policy_context=self.policy_context
                )
                
                end_time = datetime.now()
                processing_time = (end_time - start_time).total_seconds() * 1000
                
                # Create JudgeDecision
                decision = JudgeDecision(
                    entity_id=detection.span_id,
                    original_text=detection.detected_text,
                    entity_type=detection.entity_type,
                    confidence_score=detection.confidence_score,
                    keep_redaction=judgement_result['keep_redaction'],
                    replacement_hint=judgement_result.get('replacement_hint'),
                    final_action=self._map_decision_to_action(judgement_result['decision']),
                    decision_confidence=judgement_result['confidence'],
                    reasoning=judgement_result['reasoning'],
                    policy_violation_level=judgement_result['policy_violation_level'],
                    risk_factors=judgement_result.get('risk_factors', []),
                    policy_alignment=judgement_result.get('policy_alignment', True),
                    judge_model=judgement_result['llm_model'],
                    processing_time_ms=int(processing_time),
                    timestamp=datetime.now().isoformat()
                )
                
                decisions.append(decision)
                
                # Update stats
                self._update_stats(decision, processing_time)
                
            except Exception as e:
                logger.error(f"Failed to judge detection {detection.span_id}: {e}")
                self.stats['api_errors'] += 1
                
                # Fallback decision
                fallback_decision = self._create_fallback_decision(detection)
                decisions.append(fallback_decision)
        
        return decisions
    
    def _map_decision_to_action(self, decision: str) -> RedactionAction:
        """Map LLM decision string to RedactionAction enum"""
        decision_map = {
            'REDACT': RedactionAction.REDACT,
            'PSEUDONYMIZE': RedactionAction.PSEUDONYMIZE,
            'RETAIN': RedactionAction.RETAIN
        }
        
        return decision_map.get(decision.upper(), RedactionAction.RETAIN)
    
    def _create_fallback_decision(self, detection: LLMDetection) -> JudgeDecision:
        """Create fallback decision when LLM fails"""
        entity_type = detection.entity_type.lower()
        
        # Simple policy-based fallback
        if 'email' in entity_type or 'credit_card' in entity_type or 'ssn' in entity_type:
            action = RedactionAction.REDACT
        elif 'person_name' in entity_type:
            action = RedactionAction.PSEUDONYMIZE
        else:
            action = RedactionAction.RETAIN
        
        return JudgeDecision(
            entity_id=detection.span_id,
            original_text=detection.detected_text,
            entity_type=detection.entity_type,
            confidence_score=detection.confidence_score,
            keep_redaction=action != RedactionAction.RETAIN,
            replacement_hint=None,
            final_action=action,
            decision_confidence=0.6,  # Lower confidence for fallback
            reasoning=f"Fallback decision based on entity type '{detection.entity_type}' (LLM unavailable)",
            policy_violation_level='MEDIUM',
            risk_factors=['llm_unavailable'],
            policy_alignment=True,
            judge_model='fallback_policy',
            processing_time_ms=0,
            timestamp=datetime.now().isoformat()
        )
    
    def _update_stats(self, decision: JudgeDecision, processing_time: float):
        """Update processing statistics"""
        self.stats['total_judgements'] += 1
        self.stats['api_calls_made'] += 1
        
        if decision.final_action == RedactionAction.REDACT:
            self.stats['redaction_decisions'] += 1
        elif decision.final_action == RedactionAction.PSEUDONYMIZE:
            self.stats['pseudonymize_decisions'] += 1
        else:
            self.stats['retain_decisions'] += 1
        
        # Update average processing time
        total_time = self.stats['avg_processing_time'] * (self.stats['total_judgements'] - 1) + processing_time
        self.stats['avg_processing_time'] = total_time / self.stats['total_judgements']
    
    def _generate_processing_stats(self, finder_result: LLMFinderResult, 
                                 judge_decisions: List[JudgeDecision], 
                                 total_time_ms: float) -> Dict[str, Any]:
        """Generate processing statistics"""
        return {
            'input_detections': len(finder_result.detected_spans),
            'judgements_required': len(judge_decisions),
            'auto_decisions': len(finder_result.detected_spans) - len(judge_decisions),
            'total_processing_time_ms': total_time_ms,
            'avg_per_judgement_ms': total_time_ms / len(judge_decisions) if judge_decisions else 0,
            'redaction_decisions': self.stats['redaction_decisions'],
            'pseudonymize_decisions': self.stats['pseudonymize_decisions'],
            'retain_decisions': self.stats['retain_decisions'],
            'api_success_rate': (self.stats['api_calls_made'] - self.stats['api_errors']) / max(1, self.stats['api_calls_made']),
            'avg_decision_confidence': sum(d.decision_confidence for d in judge_decisions) / len(judge_decisions) if judge_decisions else 0,
            'models_used': [self.config_manager.config.judge_model.model_name, self.config_manager.config.finder_model.model_name]
        }
    
    def _generate_policy_summary(self, decisions: List[JudgeDecision]) -> Dict[str, Any]:
        """Generate policy compliance summary"""
        summary = {
            'total_decisions': len(decisions),
            'policy_compliance_rate': 0.0,
            'risk_distribution': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0},
            'action_distribution': {'REDACT': 0, 'PSEUDONYMIZE': 0, 'RETAIN': 0},
            'entity_type_decisions': {},
            'risk_factors': {},
            'models_used': set()
        }
        
        policy_aligned = 0
        
        for decision in decisions:
            # Policy alignment
            if decision.policy_alignment:
                policy_aligned += 1
            
            # Risk distribution
            summary['risk_distribution'][decision.policy_violation_level] += 1
            
            # Action distribution
            summary['action_distribution'][decision.final_action.value] += 1
            
            # Entity type decisions
            entity_type = decision.entity_type
            if entity_type not in summary['entity_type_decisions']:
                summary['entity_type_decisions'][entity_type] = {'REDACT': 0, 'PSEUDONYMIZE': 0, 'RETAIN': 0}
            summary['entity_type_decisions'][entity_type][decision.final_action.value] += 1
            
            # Risk factors
            for factor in decision.risk_factors:
                summary['risk_factors'][factor] = summary['risk_factors'].get(factor, 0) + 1
            
            # Models used
            summary['models_used'].add(decision.judge_model)
        
        summary['policy_compliance_rate'] = policy_aligned / len(decisions) if decisions else 0.0
        summary['models_used'] = list(summary['models_used'])
        
        return summary
    
    def save_results(self, result: JudgeResult, filepath: str):
        """Save Judge results"""
        # Convert to serializable format
        judge_decisions_data = []
        for decision in result.judge_decisions:
            decision_data = {
                'entity_id': decision.entity_id,
                'original_text': decision.original_text,
                'entity_type': decision.entity_type,
                'confidence_score': decision.confidence_score,
                'keep_redaction': decision.keep_redaction,
                'replacement_hint': decision.replacement_hint,
                'final_action': decision.final_action.value,  # Convert enum to string
                'decision_confidence': decision.decision_confidence,
                'reasoning': decision.reasoning,
                'policy_violation_level': decision.policy_violation_level,
                'risk_factors': decision.risk_factors,
                'policy_alignment': decision.policy_alignment,
                'judge_model': decision.judge_model,
                'processing_time_ms': decision.processing_time_ms,
                'timestamp': decision.timestamp
            }
            judge_decisions_data.append(decision_data)
        
        data = {
            'original_text': result.original_text,
            'input_detections': [asdict(detection) for detection in result.input_detections],
            'judge_decisions': judge_decisions_data,
            'policy_summary': result.policy_summary,
            'processing_stats': result.processing_stats,
            'timestamp': result.timestamp
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"LLM Judge results saved to {filepath}")

# Example usage and testing
if __name__ == "__main__":
    logger.info("Stage 5: LLM Verification (Judge) module loaded")
