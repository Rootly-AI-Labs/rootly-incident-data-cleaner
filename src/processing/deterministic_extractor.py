"""
Stage 3: Deterministic Extraction
Purpose: Perform fast, rule-based detection before invoking LLMs.
Methods: Use regex, Microsoft Presidio, or spaCy for name/entity detection.
Maintain a pseudonym map for consistency.
Outputs: Cleaned text with deterministic redactions and candidate spans for LLM verification.
"""

import re
import logging
import hashlib
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

# Import our existing components
from ..core.pii_detector import PIIDetector, PIIOccurrence
from ..core.pii_redactor import PIIRedactor
from ..policies.policy_manager import PIIPolicy, DataCategory, RedactionAction

logger = logging.getLogger(__name__)

@dataclass
class DeterministicResult:
    """Result from deterministic extraction"""
    entity_type: str
    original_text: str
    start_pos: int
    end_pos: int
    confidence: float
    detection_method: str  # 'presidio', 'regex', 'spacy', 'keyword'
    category: DataCategory
    suggested_action: RedactionAction
    pseudonym: Optional[str] = None
    context_snippet: Optional[str] = None

@dataclass
class DeterministicOutput:
    """Complete output from deterministic stage"""
    original_text: str
    processed_text: str
    detected_entities: List[DeterministicResult]
    pseudonym_map: Dict[str, str]  # original -> pseudonym mapping
    candidate_spans: List[Dict[str, Any]]  # spans for LLM verification
    processing_stats: Dict[str, Any]
    timestamp: str

class PseudonymGenerator:
    """Generates deterministic pseudonyms for consistency"""
    
    def __init__(self, seed: str = "pseudonym_seed"):
        self.seed = seed.encode('utf-8')
        self.mapping: Dict[str, str] = {}
        self.patterns = {
            'email': lambda orig: f"user{self._hash_to_number(orig)}@example.com",
            'phone': lambda orig: f"+1-555-{self._hash_to_number(orig):04d}",
            'person_name': lambda orig: self._generate_name(orig),
            'hostname': lambda orig: f"server{self._hash_to_number(orig):03d}.internal.com",
            'ip_address': lambda orig: f"192.168.{self._hash_to_number(orig) % 256}.{self._hash_to_number(orig) % 255}",
            'api_key': lambda orig: f"ak_redacted_{self._hash_to_number(orig):08d}",
            'customer_id': lambda orig: f"cust_{self._hash_to_number(orig):06d}"
        }
    
    def _hash_to_number(self, text: str) -> int:
        """Convert text to deterministic number"""
        hash_obj = hashlib.md5((text + self.seed.decode()).encode('utf-8'))
        return int(hash_obj.hexdigest(), 16) % 1000000
    
    def _generate_name(self, text: str) -> str:
        """Generate deterministic fake name"""
        number = self._hash_to_number(text)
        first_names = ["Alex", "Blake", "Casey", "Drew", "Emery", "Finley", "Gray", "Harley"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
        
        first_idx = number % len(first_names)
        last_idx = (number // len(first_names)) % len(last_names)
        
        return f"{first_names[first_idx]} {last_names[last_idx]}"
    
    def get_pseudonym(self, original_text: str, entity_type: str) -> str:
        """Get deterministic pseudonym for original text"""
        if original_text in self.mapping:
            return self.mapping[original_text]
        
        generator = self.patterns.get(entity_type, lambda x: f"[REDACTED_{entity_type}]")
        pseudonym = generator(original_text)
        self.mapping[original_text] = pseudonym
        return pseudonym
    
    def save_mapping(self, filepath: str):
        """Save pseudonym mapping to file"""
        with open(filepath, 'w') as f:
            json.dump(self.mapping, f, indent=2)
    
    def load_mapping(self, filepath: str):
        """Load pseudonym mapping from file"""
        try:
            with open(filepath, 'r') as f:
                self.mapping = json.load(f)
        except FileNotFoundError:
            self.mapping = {}

class DeterministicExtractor:
    """Main deterministic extraction engine"""
    
    def __init__(self, policy: PIIPolicy, pseudonym_file: Optional[str] = None):
        self.policy = policy
        self.pseudonym_generator = PseudonymGenerator()
        self.pii_detector = PIIDetector()
        self.pii_redactor = PIIRedactor()
        
        # Load existing pseudonym map if provided
        if pseudonym_file:
            self.pseudonym_generator.load_mapping(pseudonym_file)
        
        # Enhanced regex patterns for specific use cases
        self.custom_patterns = {
            'internal_url': re.compile(r'https?://internal-[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(\/.*)?', re.IGNORECASE),
            'jira_ticket': re.compile(r'[A-Z]{2,}-\d+', re.IGNORECASE),
            'aws_arn': re.compile(r'arn:aws:[a-zA-Z0-9]:[a-zA-Z0-9\-]+:[0-9]{12}:[a-zA-Z0-9\-_/:]+', re.IGNORECASE),
            'kubernetes_pod': re.compile(r'[a-z0-9\-]+-[a-z0-9]{8,10}-[a-z0-9]{5}', re.IGNORECASE),
            'slack_channel': re.compile(r'#[a-zA-Z0-9\-_]+', re.IGNORECASE),
            'docker_image': re.compile(r'[a-zA-Z0-9]+/[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_.]+', re.IGNORECASE)
        }
        
        # Keywords that suggest internal/potentially sensitive content
        self.internal_keywords = {
            'prod', 'production', 'staging', 'dev', 'development', 
            'internal', 'admin', 'root', 'backup', 'confidential',
            'private', 'secret', 'password', 'key', 'token'
        }
    
    def extract_deterministic(self, text: str) -> DeterministicOutput:
        """Main extraction method"""
        logger.info(f"Starting deterministic extraction on text of length {len(text)}")
        
        detected_entities = []
        candidate_spans = []
        processing_stats = {
            'total_characters': len(text),
            'presidio_matches': 0,
            'regex_matches': 0,
            'keyword_matches': 0,
            'total_matches': 0
        }
        
        try:
            # Step 1: Presidio-based detection
            presidio_results = self._extract_with_presidio(text)
            detected_entities.extend(presidio_results)
            processing_stats['presidio_matches'] += len(presidio_results)
            
            # Step 2: Custom regex patterns
            regex_results = self._extract_with_regex(text, detected_entities)
            detected_entities.extend(regex_results)
            processing_stats['regex_matches'] += len(regex_results)
            
            # Step 3: Keyword-based detection
            keyword_results = self._extract_with_keywords(text, detected_entities)
            detected_entities.extend(keyword_results)
            processing_stats['keyword_matches'] += len(keyword_results)
            
            processing_stats['total_matches'] = len(detected_entities)
            
            # Step 4: Sort by position and remove overlaps
            detected_entities = self._resolve_overlaps(detected_entities)
            
            # Step 5: Generate candidate spans for LLM verification
            candidate_spans = self._generate_candidate_spans(text, detected_entities)
            
            # Step 6: Process text with deterministic redactions
            processed_text = self._apply_deterministic_redactions(text, detected_entities)
            
            # Step 7: Update pseudonym mapping
            pseudonym_map = self._build_pseudonym_map(detected_entities)
            
            logger.info(f"Detection complete: {len(detected_entities)} entities, {len(candidate_spans)} candidate spans")
            
            return DeterministicOutput(
                original_text=text,
                processed_text=processed_text,
                detected_entities=detected_entities,
                pseudonym_map=pseudonym_map,
                candidate_spans=candidate_spans,
                processing_stats=processing_stats,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error in deterministic extraction: {e}")
            raise
    
    def _extract_with_presidio(self, text: str) -> List[DeterministicResult]:
        """Extract using Presidio analyzer"""
        results = []
        
        try:
            presidio_entities = self.pii_detector.detect_pii(text)
            
            for entity in presidio_entities:
                # Map Presidio entity type to our policy categories
                policy_pattern = self._find_policy_pattern_for_presidio_entity(entity.entity_type)
                if policy_pattern:
                    result = DeterministicResult(
                        entity_type=policy_pattern.name,
                        original_text=entity.text,
                        start_pos=entity.start,
                        end_pos=entity.end,
                        confidence=entity.score,
                        detection_method='presidio',
                        category=policy_pattern.category,
                        suggested_action=self.policy.get_action_for_pattern(policy_pattern.name),
                        context_snippet=self._extract_context(text, entity.start, entity.end)
                    )
                    results.append(result)
            
        except Exception as e:
            logger.warning(f"Presidio extraction failed: {e}")
        
        return results
    
    def _extract_with_regex(self, text: str, existing_entities: List[DeterministicResult]) -> List[DeterministicResult]:
        """Extract using custom regex patterns"""
        results = []
        
        # Get existing positions to avoid duplicates
        existing_positions = set()
        for entity in existing_entities:
            for pos in range(entity.start_pos, entity.end_pos):
                existing_positions.add(pos)
        
        for pattern_name, pattern_regex in self.custom_patterns.items():
            try:
                matches = pattern_regex.finditer(text)
                
                for match in matches:
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # Check for overlaps with existing entities
                    if any(pos in existing_positions for pos in range(start_pos, end_pos)):
                        continue
                    
                    # Determine category and action
                    category = self._categorize_pattern(pattern_name)
                    action = self._get_action_for_custom_pattern(pattern_name)
                    
                    result = DeterministicResult(
                        entity_type=f"custom_{pattern_name}",
                        original_text=match.group(),
                        start_pos=start_pos,
                        end_pos=end_pos,
                        confidence=0.8,  # High confidence for regex matches
                        detection_method='regex',
                        category=category,
                        suggested_action=action,
                                context_snippet=self._extract_context(text, start_pos, end_pos)
                    )
                    results.append(result)
                    
            except Exception as e:
                logger.warning(f"Regex pattern {pattern_name} failed: {e}")
        
        return results
    
    def _extract_with_keywords(self, text: str, existing_entities: List[DeterministicResult]) -> List[DeterministicResult]:
        """Extract using keyword analysis"""
        results = []
        
        # Check for keywords indicating internal/sensitive content
        text_lower = text.lower()
        
        for keyword in self.internal_keywords:
            if keyword in text_lower:
                # Look for patterns around keywords
                import re as regex_module
                pattern = f'\b[a-zA-Z0-9\-_./@]{{3,{{50}}}}\s*{regex_module.escape(keyword)}\b|\b{regex_module.escape(keyword)}\s*[a-zA-Z0-9\-_./@]{{3,{{50}}}}\b'
                
                matches = regex_module.finditer(pattern, text, regex_module.IGNORECASE)
                
                for match in matches:
                    # Simple check to avoid obvious duplicates
                    if any(entity.start_pos <= match.start() < match.end() <= entity.end_pos 
                           for entity in existing_entities):
                        continue
                    
                    result = DeterministicResult(
                        entity_type=f"internal_keyword_{keyword}",
                        original_text=match.group(),
                        start_pos=match.start(),
                        end_pos=match.end(),
                        confidence=0.3,  # Lower confidence for keyword matches
                        detection_method='keyword',
                        category=DataCategory.SECRETS,
                        suggested_action=RedactionAction.REDACT,
                        context_snippet=self._extract_context(text, match.start(), match.end())
                    )
                    results.append(result)
        
        return results
    
    def _find_policy_pattern_for_presidio_entity(self, presidio_type: str) -> Optional[Any]:
        """Find matching policy pattern for Presidio entity type"""
        presidio_to_pattern = {
            'EMAIL_ADDRESS': 'email',
            'PHONE_NUMBER': 'phone',
            'PERSON': 'person_name',
            'CREDIT_CARD': 'credit_card',
            'US_SSN': 'ssn',
            'LOCATION': 'address',
            'IP_ADDRESS': 'ip_address'
        }
        
        pattern_name = presidio_to_pattern.get(presidio_type)
        if pattern_name:
            return self.policy.patterns.get(pattern_name)
        return None
    
    def _resolve_overlaps(self, entities: List[DeterministicResult]) -> List[DeterministicResult]:
        """Remove overlapping entities, keeping highest confidence ones"""
        if not entities:
            return []
        
        # Sort by start position
        sorted_entities = sorted(entities, key=lambda x: x.start_pos)
        
        resolved = [sorted_entities[0]]
        
        for current in sorted_entities[1:]:
            last_resolved = resolved[-1]
            
            # Check for overlap
            if current.start_pos < last_resolved.end_pos:
                # Keep the one with higher confidence
                if current.confidence > last_resolved.confidence:
                    resolved[-1] = current
                # If same confidence, prefer shorter match (more specific)
                elif current.confidence == last_resolved.confidence and len(current.original_text) < len(last_resolved.original_text):
                    resolved[-1] = current
            else:
                resolved.append(current)
        
        return resolved
    
    def _generate_candidate_spans(self, text: str, entities: List[DeterministicResult]) -> List[Dict[str, Any]]:
        """Generate candidate spans for LLM verification"""
        candidates = []
        
        for entity in entities:
            candidate = {
                'span_id': f"span_{entity.start_pos}_{entity.end_pos}",
                'start_pos': entity.start_pos,
                'end_pos': entity.end_pos,
                'text': entity.original_text,
                'entity_type': entity.entity_type,
                'detection_method': entity.detection_method,
                'confidence': entity.confidence,
                'category': entity.category.value,
                'suggested_action': entity.suggested_action.value,
                'context_snippet': entity.context_snippet,
                'requires_llm_review': entity.confidence < 0.7 or entity.detection_method == 'keyword'
            }
            candidates.append(candidate)
        
        return candidates
    
    def _apply_deterministic_redactions(self, text: str, entities: List[DeterministicResult]) -> str:
        """Apply deterministic redactions based on high confidence matches"""
        processed_text = text
        
        # Sort entities by position (descending) to avoid position shifts
        entities_sorted = sorted(entities, key=lambda x: x.start_pos, reverse=True)
        
        for entity in entities_sorted:
            # Only apply redactions for high confidence matches
            if entity.confidence >= 0.8 and entity.suggested_action != RedactionAction.RETAIN:
                replacement = self._get_replacement_text(entity)
                processed_text = (processed_text[:entity.start_pos] + 
                                replacement + 
                                processed_text[entity.end_pos:])
        
        return processed_text
    
    def _get_replacement_text(self, entity: DeterministicResult) -> str:
        """Get replacement text for entity"""
        if entity.suggested_action == RedactionAction.REDACT:
            return f"[REDACTED_{entity.entity_type.upper()}]"
        elif entity.suggested_action == RedactionAction.PSEUDONYMIZE:
            pseudonym = self.pseudonym_generator.get_pseudonym(entity.original_text, entity.entity_type)
            return pseudonym
        else:
            return entity.original_text
    
    def _build_pseudonym_map(self, entities: List[DeterministicResult]) -> Dict[str, str]:
        """Build pseudonym mapping for LLM stage"""
        mapping = {}
        
        for entity in entities:
            if entity.suggested_action == RedactionAction.PSEUDONYMIZE:
                pseudonym = self.pseudonym_generator.get_pseudonym(entity.original_text, entity.entity_type)
                mapping[entity.original_text] = pseudonym
        
        return mapping
    
    def _categorize_pattern(self, pattern_name: str) -> DataCategory:
        """Categorize custom regex patterns"""
        category_map = {
            'internal_url': DataCategory.SECRETS,
            'jira_ticket': DataCategory.OPERATIONAL_IDENTIFIERS,
            'aws_arn': DataCategory.SECRETS,
            'kubernetes_pod': DataCategory.OPERATIONAL_IDENTIFIERS,
            'slack_channel': DataCategory.CUSTOMER_ORG_INFO,
            'docker_image': DataCategory.OPERATIONAL_IDENTIFIERS
        }
        
        return category_map.get(pattern_name, DataCategory.MISCELLANEOUS)
    
    def _get_action_for_custom_pattern(self, pattern_name: str) -> RedactionAction:
        """Get redaction action for custom patterns"""
        action_map = {
            'internal_url': RedactionAction.REDACT,
            'jira_ticket': RedactionAction.PSEUDONYMIZE,
            'aws_arn': RedactionAction.REDACT,
            'kubernetes_pod': RedactionAction.PSEUDONYMIZE,
            'slack_channel': RedactionAction.RETAIN,
            'docker_image': RedactionAction.PSEUDONYMIZE
        }
        
        return action_map.get(pattern_name, RedactionAction.RETAIN)
    
    def _extract_context(self, text: str, start: int, end: int, context_size: int = 50) -> str:
        """Extract context around detected entity"""
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        prefix = "..." if context_start > 0 else ""
        suffix = "..." if context_end < len(text) else ""
        
        return f"{prefix}{text[context_start:context_end]}{suffix}"
    
    def save_results(self, output: DeterministicOutput, filepath: str):
        """Save deterministic extraction results"""
        # Convert to serializable format
        serialized_entities = []
        for entity in output.detected_entities:
            serialized_entities.append({
                'entity_type': entity.entity_type,
                'original_text': entity.original_text,
                'start_pos': entity.start_pos,
                'end_pos': entity.end_pos,
                'confidence': entity.confidence,
                'detection_method': entity.detection_method,
                'category': entity.category.value,
                'suggested_action': entity.suggested_action.value,
                'pseudonym': entity.pseudonym,
                'context_snippet': entity.context_snippet
            })
        
        data = {
            'original_text': output.original_text,
            'processed_text': output.processed_text,
            'detected_entities': serialized_entities,
            'pseudonym_map': output.pseudonym_map,
            'candidate_spans': output.candidate_spans,
            'processing_stats': output.processing_stats,
            'timestamp': output.timestamp
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Deterministic extraction results saved to {filepath}")
