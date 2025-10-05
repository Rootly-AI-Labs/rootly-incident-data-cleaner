"""
Stage 6: Arbitration & Redaction
Purpose: Combine deterministic, Finder, and Judge results into final decision logic.
Rules: Secrets are always hard redacted. Emails and phones are redacted; 
hostnames and IPs pseudonymized; names may be retained if contextually safe.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

from ..policies.policy_manager import PIIPolicy, RedactionAction, DataCategory
from .deterministic_extractor import DeterministicOutput, DeterministicResult
from .llm_detector import LLMFinderResult, LLMDetection
from .llm_verifier import JudgeResult, JudgeDecision

logger = logging.getLogger(__name__)

@dataclass
class ArbitrationDecision:
    """Final arbitration decision for an entity"""
    entity_id: str
    entity_type: str
    original_text: str
    start_pos: int
    end_pos: int
    
    # Final decision
    final_action: RedactionAction
    final_confidence: float
    
    # Decision sources
    deterministic_action: Optional[RedactionAction]
    llm_finder_action: Optional[RedactionAction]
    judge_action: Optional[RedactionAction]
    
    # Arbitration reasoning
    arbitration_reasoning: str
    decision_sources: List[str]  # Which stages contributed
    
    # Replacement data
    replacement_text: str
    pseudonym_map_key: Optional[str]
    redaction_type: str  # 'hard_redact', 'pseudonymize', 'contextual_retain'
    
    # Metadata
    processing_stage: str = "arbitration"
    timestamp: str = ""

@dataclass
class ArbitrationResult:
    """Complete result from Arbitration & Redaction stage"""
    original_text: str
    processed_text: str
    arbitration_decisions: List[ArbitrationDecision]
    pseudonym_map: Dict[str, str]
    processing_stats: Dict[str, Any]
    text_transformations: List[Dict[str, Any]]
    timestamp: str

class ConflictResolver:
    """Resolves conflicts between different stage recommendations"""
    
    def __init__(self, policy: PIIPolicy):
        self.policy = policy
        
        # Priority order: Judge > Finder > Deterministic
        self.stage_priorities = {
            'judge': 3,
            'llm_finder': 2, 
            'deterministic': 1
        }
        
        # Entity-specific rules
        self.entity_rules = {
            'email': {'default_action': RedactionAction.REDACT, 'force_rule': True},
            'phone': {'default_action': RedactionAction.REDACT, 'force_rule': True},
            'credit_card': {'default_action': RedactionAction.REDACT, 'force_rule': True},
            'ssn': {'default_action': RedactionAction.REDACT, 'force_rule': True},
            'api_key': {'default_action': RedactionAction.REDACT, 'force_rule': True},
            'person_name': {'default_action': RedactionAction.PSEUDONYMIZE, 'context_dependent': True},
            'hostname': {'default_action': RedactionAction.PSEUDONYMIZE, 'context_dependent': True},
            'ip_address': {'default_action': RedactionAction.PSEUDONYMIZE, 'context_dependent': True},
            'customer_id': {'default_action': RedactionAction.PSEUDONYMIZE, 'context_dependent': True}
        }
    
    def resolve_conflict(self, entity_type: str, stage_decisions: Dict[str, RedactionAction], 
                        context: str, entity_text: str) -> Tuple[RedactionAction, str]:
        """Resolve conflicts between stage recommendations"""
        
        # Check for force rules first
        if entity_type in self.entity_rules:
            rule = self.entity_rules[entity_type]
            if rule.get('force_rule', False):
                return rule['default_action'], f"Forced rule: {entity_type} entities are always {rule['default_action'].value}"
        
        # Collect weighted votes
        weighted_votes = {}
        vote_reasons = []
        
        for stage, action in stage_decisions.items():
            if action is not None:
                weight = self.stage_priorities.get(stage, 1)
                weighted_votes[action.value] = weighted_votes.get(action.value, 0) + weight
                vote_reasons.append(f"{stage}: {action.value} (weight: {weight})")
        
        if not weighted_votes:
            # No decisions from any stage - use policy default
            default_action = RedactionAction.RETAIN
            return default_action, "No stage decisions available, using policy default: RETAIN"
        
        # Find winning action
        winning_action_name = max(weighted_votes.items(), key=lambda x: x[1])[0]
        winning_action = RedactionAction(winning_action_name)
        
        # Context-dependent adjustments
        if entity_type in self.entity_rules and self.entity_rules[entity_type].get('context_dependent'):
            winning_action = self._apply_context_rules(entity_type, winning_action, context, entity_text)
            vote_reasons.append(f"Context-adjusted to: {winning_action.value}")
        
        reasoning = f"Arbitration result: {'; '.join(vote_reasons)}"
        return winning_action, reasoning
    
    def _apply_context_rules(self, entity_type: str, proposed_action: RedactionAction, 
                        context: str, entity_text: str) -> RedactionAction:
        """Apply context-dependent rules to proposed action"""
        
        context_lower = context.lower()
        
        # Public/safe contexts
        public_indicators = ['public', 'support@', 'noreply@', 'admin@company.com', 'team member jane', 'contact sales']
        if any(indicator in context_lower for indicator in public_indicators):
            return RedactionAction.RETAIN
        
        # Security incident contexts - more aggressive
        security_indicators = ['breach', 'security incident', 'unauthorized access', 'data leak', 'compromise']
        if any(indicator in context_lower for indicator in security_indicators):
            if proposed_action == RedactionAction.RETAIN:
                return RedactionAction.PSEUDONYMIZE
        
        # Internal discussion contexts - moderate
        internal_indicators = ['internal discussion', 'team meeting', 'employee review', 'confidential']
        if any(indicator in context_lower for indicator in internal_indicators):
            if proposed_action == RedactionAction.RETAIN and entity_type == 'person_name':
                return RedactionAction.PSEUDONYMIZE
        
        return proposed_action

class TextProcessor:
    """Handles actual text redaction and pseudonymization"""
    
    def __init__(self):
        self.pseudonym_cache: Dict[str, Dict[str, str]] = {}
        
        # Pseudonym generation patterns
        self.pseudonym_patterns = {
            'email': lambda orig: f"user_{self._hash_text(orig, 4)}@company.com",
            'person_name': lambda orig: f"Person_{self._hash_text(orig, 6)}",
            'hostname': lambda orig: f"server-{self._hash_text(orig, 3)}.internal",
            'ip_address': lambda orig: f"192.168.1.{int(self._hash_text(orig, 1), 16) % 254 + 1}",
            'phone': lambda orig: f"+1-555-{self._hash_text(orig, 3)}-{self._hash_text(orig, 4)}",
            'credit_card': lambda orig: f"CARD-****-****-****-{self._hash_text(orig, 4)}",
            'ssn': lambda orig: f"SSN-***-**-{self._hash_text(orig, 4)}",
            'customer_id': lambda orig: f"CUST_{self._hash_text(orig, 8)}",
            'api_key': lambda orig: f"API_{self._hash_text(orig, 12)}",
            'jira_ticket': lambda orig: f"REF-{self._hash_text(orig, 6)}",
            'slack_channel': lambda orig: f"#channel-{self._hash_text(orig, 4)}"
        }
        
        # Hard redaction patterns
        self.redaction_patterns = {
            'email': '[REDACTED_EMAIL]',
            'phone': '[REDACTED_PHONE]',
            'credit_card': '[REDACTED_CARD]',
            'ssn': '[REDACTED_SSN]',
            'api_key': '[REDACTED_KEY]',
            'person_name': '[REDACTED_NAME]',
            'hostname': '[REDACTED_HOST]',
            'ip_address': '[REDACTED_IP]'
        }
    
    def _hash_text(self, text: str, length: int) -> str:
        """Generate deterministic hash for pseudonymization"""
        import hashlib
        hash_obj = hashlib.md5(text.lower().encode('utf-8'))
        return hash_obj.hexdigest()[:length]
    
    def generate_replacement_text(self, entity_type: str, original_text: str, 
                                action: RedactionAction, document_id: str = "default") -> Tuple[str, Optional[str]]:
        """Generate replacement text based on action type"""
        
        if action == RedactionAction.REDACT:
            replacement = self.redaction_patterns.get(entity_type, '[REDACTED]')
            return replacement, None
        
        elif action == RedactionAction.PSEUDONYMIZE:
            # Ensure consistent pseudonyms within document
            if document_id not in self.pseudonym_cache:
                self.pseudonym_cache[document_id] = {}
            
            cache_key = f"{entity_type}:{original_text.lower()}"
            
            if cache_key in self.pseudonym_cache[document_id]:
                return self.pseudonym_cache[document_id][cache_key], cache_key
            
            # Generate new pseudonym
            pattern_func = self.pseudonym_patterns.get(entity_type)
            if pattern_func:
                pseudonym = pattern_func(original_text)
            else:
                pseudonym = f"[PSEUDONYM_{entity_type.upper()}]"
            
            self.pseudonym_cache[document_id][cache_key] = pseudonym
            return pseudonym, cache_key
        
        else:  # RETAIN
            return original_text, None
    
    def apply_redactions(self, text: str, decisions: List[ArbitrationDecision]) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply all redaction decisions to the text"""
        
        # Sort decisions by start position (process backwards to maintain positions)
        sorted_decisions = sorted(decisions, key=lambda x: x.start_pos, reverse=True)
        
        processed_text = text
        transformations = []
        
        for decision in sorted_decisions:
            original_start = decision.start_pos
            original_end = decision.end_pos
            
            # Verify the text matches
            expected_text = text[original_start:original_end]
            if expected_text.strip() != decision.original_text.strip():
                logger.warning(f"Text mismatch at {original_start}-{original_end}: expected '{expected_text}', got '{decision.original_text}'")
                # Try to find the text
                search_start = max(0, original_start - 10)
                search_end = min(len(text), original_end + 10)
                search_text = text[search_start:search_end]
                if decision.original_text.strip() in search_text:
                    adjusted_start = search_start + search_text.find(decision.original_text.strip())
                    adjusted_end = adjusted_start + len(decision.original_text.strip())
                    original_start, original_end = adjusted_start, adjusted_end
                else:
                    logger.error(f"Could not locate '{decision.original_text}' in context")
                    continue
            
            # Apply replacement
            before_replacement = text[original_start:original_end]
            text_before = processed_text[:original_start]
            text_after = processed_text[original_end:]
            processed_text = text_before + decision.replacement_text + text_after
            
            # Record transformation
            transformation = {
                'entity_id': decision.entity_id,
                'entity_type': decision.entity_type,
                'original_text': decision.original_text,
                'replacement_text': decision.replacement_text,
                'action': decision.final_action.value,
                'position': {'start': original_start, 'end': original_end},
                'redaction_type': decision.redaction_type,
                'timestamp': decision.timestamp
            }
            transformations.append(transformation)
            
            logger.info(f"Applied {decision.final_action.value.lower()} to '{decision.original_text}' -> '{decision.replacement_text}'")
        
        return processed_text, transformations

class ArbitrationProcessor:
    """Main processor for Stage 6: Arbitration & Redaction"""
    
    def __init__(self, policy: PIIPolicy):
        self.policy = policy
        self.conflict_resolver = ConflictResolver(policy)
        self.text_processor = TextProcessor()
        
        # Combined results from all stages
        self.all_detections: List[DeterministicResult] = []
        self.all_llm_detections: List[LLMDetection] = []
        self.all_judgements: List[JudgeDecision] = []
        
        # Processing statistics
        self.stats = {
            'total_entities_processed': 0,
            'conflicts_resolved': 0,
            'force_rules_applied': 0,
            'context_adjustments': 0,
            'redactions_applied': 0,
            'pseudonymizations_applied': 0,
            'retentions_applied': 0
        }
    
    def arbitrate_and_redact(self, deterministic_output: DeterministicOutput, 
                           finder_result: LLMFinderResult, 
                           judge_result: JudgeResult) -> ArbitrationResult:
        """Main method to perform arbitration and redaction"""
        
        logger.info("Starting Stage 6: Arbitration & Redaction")
        
        # Step 1: Collect all detections from all stages
        self._collect_all_detections(deterministic_output, finder_result, judge_result)
        
        # Step 2: Create unified entity mapping
        entity_map = self._create_entity_mapping()
        
        # Step 3: Resolve conflicts and make final decisions
        arbitration_decisions = self._resolve_all_conflicts(entity_map, deterministic_output.original_text)
        
        # Step 4: Generate pseudonym map
        pseudonym_map = self._generate_pseudonym_map(arbitration_decisions)
        
        # Step 5: Apply redactions to text
        processed_text, transformations = self.text_processor.apply_redactions(
            deterministic_output.original_text, arbitration_decisions
        )
        
        # Step 6: Generate processing statistics
        processing_stats = self._generate_processing_stats()
        
        logger.info(f"Arbitration complete: {len(arbitration_decisions)} decisions made, {len(transformations)} transformations applied")
        
        return ArbitrationResult(
            original_text=deterministic_output.original_text,
            processed_text=processed_text,
            arbitration_decisions=arbitration_decisions,
            pseudonym_map=pseudonym_map,
            processing_stats=processing_stats,
            text_transformations=transformations,
            timestamp=datetime.now().isoformat()
        )
    
    def _collect_all_detections(self, deterministic_output: DeterministicOutput, 
                              finder_result: LLMFinderResult, judge_result: JudgeResult):
        """Collect detections from all previous stages"""
        
        # Stage 3: Deterministic detections
        self.all_detections = deterministic_output.detected_entities.copy()
        
        # Stage 4: LLM Finder detections
        self.all_llm_detections = finder_result.detected_spans.copy()
        
        # Stage 5: Judge decisions
        self.all_judgements = judge_result.judge_decisions.copy()
        
        logger.info(f" Collected detections: Stage 3({len(self.all_detections)}) + Stage 4({len(self.all_llm_detections)}) + Stage 5({len(self.all_judgements)})")
    
    def _create_entity_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Create unified mapping of entities across all stages"""
        
        entity_map = {}
        
        # Add deterministic entities
        for entity in self.all_detections:
            map_key = f"{entity.start_pos}:{entity.end_pos}"
            entity_map[map_key] = {
                'position': (entity.start_pos, entity.end_pos),
                'text': entity.original_text,
                'entity_type': entity.entity_type,
                'deterministic_action': entity.suggested_action,
                'deterministic_confidence': entity.confidence,
                'stage_sources': ['deterministic'],
                'context_snippet': entity.context_snippet
            }
        
        # Add LLM Finder detections (may overlap with deterministic)
        for detection in self.all_llm_detections:
            map_key = f"{detection.start_pos}:{detection.end_pos}"
            
            if map_key in entity_map:
                entity_map[map_key]['stage_sources'].append('llm_finder')
                entity_map[map_key]['llm_finder_action'] = self._infer_action_from_llm_detection(detection)
                entity_map[map_key]['llm_finder_confidence'] = detection.confidence_score
            else:
                entity_map[map_key] = {
                    'position': (detection.start_pos, detection.end_pos),
                    'text': detection.detected_text,
                    'entity_type': detection.entity_type,
                    'llm_finder_action': self._infer_action_from_llm_detection(detection),
                    'llm_finder_confidence': detection.confidence_score,
                    'stage_sources': ['llm_finder'],
                    'context_snippet': detection.context_snippet
                }
        
        # Add Judge decisions (may overlap with others)
        for judgement in self.all_judgements:
            map_key = f"{judgement.start_pos}:{judgement.end_pos}" if hasattr(judgement, 'start_pos') else judgement.entity_id
            
            if map_key in entity_map:
                entity_map[map_key]['stage_sources'].append('judge')
                entity_map[map_key]['judge_action'] = judgement.final_action
                entity_map[map_key]['judge_confidence'] = judgement.decision_confidence
            else:
                # This might be a judgement without a corresponding detection
                logger.info(f"Judge decision without prior detection: {judgement.entity_id}")
        
        return entity_map
    
    def _infer_action_from_llm_detection(self, detection: LLMDetection) -> RedactionAction:
        """Infer redaction action from LLM detection"""
        
        # Map LLM entity types to actions
        entity_type_actions = {
            'email': RedactionAction.REDACT,
            'phone': RedactionAction.REDACT,
            'credit_card': RedactionAction.REDACT,
            'ssn': RedactionAction.REDACT,
            'person_name': RedactionAction.PSEUDONYMIZE,
            'hostname': RedactionAction.PSEUDONYMIZE,
            'ip_address': RedactionAction.PSEUDONYMIZE,
            'customer_id': RedactionAction.PSEUDONYMIZE
        }
        
        # Extract base entity type
        base_type = detection.entity_type.split('_')[-1] if '_' in detection.entity_type else detection.entity_type
        
        return entity_type_actions.get(base_type, RedactionAction.RETAIN)
    
    def _resolve_all_conflicts(self, entity_map: Dict[str, Dict[str, Any]], 
                             context_text: str) -> List[ArbitrationDecision]:
        """Resolve conflicts for all entities and create final decisions"""
        
        arbitration_decisions = []
        
        for map_key, entity_data in entity_map.items():
            start_pos, end_pos = entity_data['position']
            entity_type = entity_data['entity_type']
            original_text = entity_data['text']
            
            # Collect stage decisions
            stage_decisions = {}
            if 'deterministic_action' in entity_data:
                stage_decisions['deterministic'] = entity_data['deterministic_action']
            if 'llm_finder_action' in entity_data:
                stage_decisions['llm_finder'] = entity_data['llm_finder_action']
            if 'judge_action' in entity_data:
                stage_decisions['judge'] = entity_data['judge_action']
            
            # Resolve conflict
            final_action, reasoning = self.conflict_resolver.resolve_conflict(
                entity_type, stage_decisions, context_text, original_text
            )
            
            # Generate replacement text
            replacement_text, pseudonym_key = self.text_processor.generate_replacement_text(
                entity_type, original_text, final_action, "document"
            )
            
            # Determine redaction type
            redaction_type = self._determine_redaction_type(final_action)
            
            # Create decision
            decision = ArbitrationDecision(
                entity_id=f"arbitration_{len(arbitration_decisions)}",
                entity_type=entity_type,
                original_text=original_text,
                start_pos=start_pos,
                end_pos=end_pos,
                final_action=final_action,
                final_confidence=max(
                    entity_data.get('deterministic_confidence', 0),
                    entity_data.get('llm_finder_confidence', 0),
                    entity_data.get('judge_confidence', 0)
                ),
                deterministic_action=entity_data.get('deterministic_action'),
                llm_finder_action=entity_data.get('llm_finder_action'),
                judge_action=entity_data.get('judge_action'),
                arbitration_reasoning=reasoning,
                decision_sources=entity_data['stage_sources'],
                replacement_text=replacement_text,
                pseudonym_map_key=pseudonym_key,
                redaction_type=redaction_type,
                timestamp=datetime.now().isoformat()
            )
            
            arbitration_decisions.append(decision)
            
            # Update statistics
            self._update_stats(final_action, stage_decisions, reasoning)
        
        return arbitration_decisions
    
    def _determine_redaction_type(self, action: RedactionAction) -> str:
        """Determine the type of redaction based on action"""
        action_types = {
            RedactionAction.REDACT: 'hard_redact',
            RedactionAction.PSEUDONYMIZE: 'pseudonymize',
            RedactionAction.RETAIN: 'contextual_retain'
        }
        return action_types[action]
    
    def _update_stats(self, final_action: RedactionAction, 
                     stage_decisions: Dict[str, RedactionAction], reasoning: str):
        """Update processing statistics"""
        self.stats['total_entities_processed'] += 1
        
        # Count action types
        if final_action == RedactionAction.REDACT:
            self.stats['redactions_applied'] += 1
        elif final_action == RedactionAction.PSEUDONYMIZE:
            self.stats['pseudonymizations_applied'] += 1
        else:
            self.stats['retentions_applied'] += 1
        
        # Count conflict types
        if len(stage_decisions) > 1:
            self.stats['conflicts_resolved'] += 1
        
        if 'Forced rule' in reasoning:
            self.stats['force_rules_applied'] += 1
        
        if 'Context-adjusted' in reasoning:
            self.stats['context_adjustments'] += 1
    
    def _generate_pseudonym_map(self, decisions: List[ArbitrationDecision]) -> Dict[str, str]:
        """Generate pseudonym mapping dictionary"""
        pseudonym_map = {}
        
        for decision in decisions:
            if decision.pseudonym_map_key:
                pseudonym_map[decision.pseudonym_map_key] = decision.replacement_text
        
        return pseudonym_map
    
    def _generate_processing_stats(self) -> Dict[str, Any]:
        """Generate comprehensive processing statistics"""
        return {
            'arbitration_stats': self.stats,
            'total_arbitrations': len(self.all_detections) + len(self.all_llm_detections),
            'unique_entities': len(set(str(e.start_pos) + ':' + str(e.end_pos) for e in self.all_detections + self.all_llm_detections)),
            'decision_distribution': {
                'redact': self.stats['redactions_applied'],
                'pseudonymize': self.stats['pseudonymizations_applied'],
                'retain': self.stats['retentions_applied']
            },
            'conflict_analysis': {
                'conflicts_resolved': self.stats['conflicts_resolved'],
                'force_rules_applied': self.stats['force_rules_applied'],
                'context_adjustments': self.stats['context_adjustments']
            },
            'stage_contributions': {
                'deterministic_inputs': len(self.all_detections),
                'llm_finder_inputs': len(self.all_llm_detections),
                'judge_inputs': len(self.all_judgements)
            }
        }
    
    def save_results(self, result: ArbitrationResult, filepath: str):
        """Save arbitration results"""
        
        # Convert to serializable format
        decisions_data = []
        for decision in result.arbitration_decisions:
            decision_data = {
                'entity_id': decision.entity_id,
                'entity_type': decision.entity_type,
                'original_text': decision.original_text,
                'start_pos': decision.start_pos,
                'end_pos': decision.end_pos,
                'final_action': decision.final_action.value,
                'final_confidence': decision.final_confidence,
                'deterministic_action': decision.deterministic_action.value if decision.deterministic_action else None,
                'llm_finder_action': decision.llm_finder_action.value if decision.llm_finder_action else None,
                'judge_action': decision.judge_action.value if decision.judge_action else None,
                'arbitration_reasoning': decision.arbitration_reasoning,
                'decision_sources': decision.decision_sources,
                'replacement_text': decision.replacement_text,
                'pseudonym_map_key': decision.pseudonym_map_key,
                'redaction_type': decision.redaction_type,
                'processing_stage': decision.processing_stage,
                'timestamp': decision.timestamp
            }
            decisions_data.append(decision_data)
        
        data = {
            'original_text': result.original_text,
            'processed_text': result.processed_text,
            'arbitration_decisions': decisions_data,
            'pseudonym_map': result.pseudonym_map,
            'processing_stats': result.processing_stats,
            'text_transformations': result.text_transformations,
            'timestamp': result.timestamp
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Arbitration results saved to {filepath}")

# Example usage and testing
if __name__ == "__main__":
    logger.info("Stage 6: Arbitration & Redaction module loaded")
