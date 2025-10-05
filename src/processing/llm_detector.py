"""
Stage 4: Primary LLM Detection (Finder)
Purpose: Identify additional or context-sensitive PII that deterministic methods might miss.
The Finder LLM only detects, never rewrites, and outputs JSON spans with start/end offsets and confidence scores.
"""

import json
import re
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

# For LLM integration, we'll simulate with rule-based approach initially
# In production, this would integrate with OpenAI, Anthropic, or local models
try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    openai = None

# Import previous stages
from .deterministic_extractor import DeterministicOutput
from ..policies.policy_manager import PIIPolicy, DataCategory, RedactionAction

logger = logging.getLogger(__name__)

@dataclass
class LLMDetection:
    """Result from LLM detection"""
    span_id: str
    entity_type: str
    detected_text: str
    start_pos: int
    end_pos: int
    confidence_score: float
    reasoning: str
    context_snippet: str
    llm_model: str = "simulated"
    detection_time: Optional[str] = None

@dataclass
class LLMFinderResult:
    """Complete result from LLM Finder stage"""
    original_text: str
    detected_spans: List[LLMDetection]
    candidate_spans_processed: List[Dict[str, Any]]
    additional_detections: List[LLMDetection]
    processing_stats: Dict[str, Any]
    timestamp: str

class ContextualPIIDetector:
    """Simulates LLM-based contextual PII detection using enhanced rules"""
    
    def __init__(self):
        self.detection_patterns = {
            # Enhanced patterns that deterministic stage might miss
            'employment_info': re.compile(
                r'(?:work(?:er|ing|ed)?|employ(?:ee|er|ment)|staff|colleague|team(?:\s+member)?|boss|manager|supervisor|director|CEO|CTO|founder|entrepreneur)\s+[a-zA-Z]+(?:\s+[a-zA-Z]+)*',
                re.IGNORECASE
            ),
            'salary_info': re.compile(
                r'(?:salary|wage|compensation|income|pay(?:\s+rate)?|rate per hour|hourly|annual|monthly)\s*[:\-]?\s*(?:\$[0-9,]+(?:\.[0-9]{2})?|[0-9,]+(?:\.[0-9]{2})?\s*dollars?)',
                re.IGNORECASE
            ),
            'internal_platforms': re.compile(
                r'(?:confluence|jira|slack|notion|airtable|asana|trello|monday|figma|github|gitlab|bitbucket)\.(?:com|org|io)(?:/[a-zA-Z0-9/\-_]+)?',
                re.IGNORECASE
            ),
            'internal_metrics': re.compile(
                r'(?:uptime|response\s+time|latency|throughput|error\s+rate|sla|availability|performance|reliability)\s*[:\-]?\s*(?:\d+(?:\.\d+)?%?|high|medium|low|critical)',
                re.IGNORECASE
            ),
            'customer_data_refs': re.compile(
                r'(?:customer|client|user|account)\s*(?:data|info|information|profile|record|details)\s*(?:access|leak|breach|exposure|compromise)',
                re.IGNORECASE
            ),
            'intellectual_property': re.compile(
                r'(?:source\s+code|algorithm|trade\s+secret|patent|copyright|proprietary|confidential\s+information)',
                re.IGNORECASE
            ),
            'investigation_details': re.compile(
                r'(?:investigat(?:ing|ion)?|analysis|debugging|troubleshoot(?:ing)?|forensic|audit)\s+(?:found|discovered|revealed|identified|determined)\s+(?:that|this|the)',
                re.IGNORECASE
            )
        }
        
        self.contextual_keywords = {
            'sensitive': ['confidential', 'private', 'restricted', 'classified', 'security breach', 'data leak'],
            'internal': ['internal meeting', 'team chat', 'staff discussion', 'employee review', 'company policy'],
            'financial': ['revenue', 'profit', 'loss', 'budget', 'expense', 'investment', 'cost'],
            'operational': ['incident response', 'crisis management', 'business continuity', 'disaster recovery']
        }
    
    def analyze_contextual_pii(self, text: str, existing_spans: List[Dict[str, Any]]) -> List[LLMDetection]:
        """Analyze text for contextual PII that deterministic methods missed"""
        detections = []
        
        # Get existing positions to avoid duplicates
        existing_positions = set()
        for span in existing_spans:
            for pos in range(span['start_pos'], span['end_pos']):
                existing_positions.add(pos)
        
        text_lower = text.lower()
        
        for pattern_name, pattern_regex in self.detection_patterns.items():
            try:
                matches = pattern_regex.finditer(text)
                
                for match in matches:
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # Check for overlaps with deterministic detections
                    if any(pos in existing_positions for pos in range(start_pos, end_pos)):
                        continue
                    
                    # Calculate contextual confidence
                    confidence = self._calculate_contextual_confidence(match.group(), text, start_pos)
                    
                    if confidence >= 0.6:  # Minimum threshold for LLM detection
                        detection = LLMDetection(
                            span_id=f"llm_{pattern_name}_{start_pos}_{end_pos}",
                            entity_type=f"contextual_{pattern_name}",
                            detected_text=match.group(),
                            start_pos=start_pos,
                            end_pos=end_pos,
                            confidence_score=confidence,
                            reasoning=f"Context suggests {pattern_name.replace('_', ' ')} information",
                            context_snippet=self._extract_context_snippet(text, start_pos, end_pos),
                            detection_time=datetime.now().isoformat()
                        )
                        detections.append(detection)
                        
            except Exception as e:
                logger.warning(f"Contextual pattern {pattern_name} failed: {e}")
        
        return detections
    
    def _calculate_contextual_confidence(self, match_text: str, full_text: str, position: int) -> float:
        """Calculate confidence based on contextual clues"""
        confidence = 0.5  # Base confidence
        
        # Context clues around the match
        context_start = max(0, position - 100)
        context_end = min(len(full_text), position + len(match_text) + 100)
        context_window = full_text[context_start:context_end].lower()
        
        # Check for reinforcing keywords
        for category, keywords in self.contextual_keywords.items():
            if any(keyword in context_window for keyword in keywords):
                confidence += 0.2
        
        # Check for privacy/security indicators
        privacy_indicators = ['pii', 'gdpr', 'ccpa', 'sox', 'hipaa', 'compliance', 'privacy', 'protection']
        if any(indicator in context_window for indicator in privacy_indicators):
            confidence += 0.15
        
        # Check for incident-related language
        incident_indicators = ['incident', 'breach', 'outage', 'failure', 'issue', 'problem', 'alert']
        if any(indicator in context_window for indicator in incident_indicators):
            confidence += 0.1
        
        # Length-based adjustment (longer matches often more reliable)
        if len(match_text) > 20:
            confidence += 0.1
        elif len(match_text) < 5:
            confidence -= 0.1
        
        return min(1.0, max(0.0, confidence))
    
    def _extract_context_snippet(self, text: str, start: int, end: int, context_size: int = 75) -> str:
        """Extract context around detected span"""
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        prefix = "..." if context_start > 0 else ""
        suffix = "..." if context_end < len(text) else ""
        
        return f"{prefix}{text[context_start:context_end]}{suffix}"

class LLMSimulator:
    """Simulates LLM responses for when actual LLM is not available"""
    
    def __init__(self):
        self.model_name = "simulated_gpt4"
        self.response_templates = {
            'email_pattern': "I detected what appears to be an email address in the text.",
            'name_pattern': "I identified a person's name that may be sensitive employee information.",
            'internal_system': "This references an internal system or infrastructure component.",
            'financial_data': "The text appears to contain financial or business-sensitive information.",
            'technical_details': "I found technical implementation details that might be proprietary.",
            'general_pii': "This text likely contains personally identifiable information."
        }
    
    async def analyze_spans(self, text: str, candidate_spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Simulate LLM analysis of candidate spans"""
        results = {}
        
        for span in candidate_spans:
            span_id = span['span_id']
            span_text = span['text']
            
            # Simulate LLM reasoning
            reasoning = self._generate_reasoning(span_text, span['entity_type'])
            
            # Determine if this needs additional processing
            requires_further_review = span['confidence'] < 0.8
            
            results[span_id] = {
                'confirmed': True,
                'confidence_adjustment': self._get_confidence_adjustment(span),
                'additional_context': True,
                'requires_expert_review': requires_further_review,
                'reasoning': reasoning,
                'alternative_classification': self._get_alternative_classification(span),
                'context_sensitivity': self._assess_context_sensitivity(span_text, text)
            }
        
        # Simulate API delay
        await asyncio.sleep(0.1)
        
        return results
    
    def _generate_reasoning(self, text: str, entity_type: str) -> str:
        """Generate realistic LLM reasoning text"""
        templates = {
            'email': f"The text '{text}' appears to be an email address. Email addresses are considered PII data.",
            'person_name': f"The text '{text}' represents a person's name, which is sensitive personal information.",
            'phone': f"The string '{text}' appears to be a telephone number, categorized as PII.",
            'custom_': f"The text '{text}' appears to reference {entity_type.replace('custom_', '')} information.",
            'internal_': f"The term '{text}' suggests {entity_type.replace('internal_', '')} data that may be sensitive."
        }
        
        for pattern, template in templates.items():
            if entity_type.startswith(pattern):
                return template
        
        return f"I detected '{text}' which appears to contain sensitive information based on context."
    
    def _get_confidence_adjustment(self, span: Dict[str, Any]) -> float:
        """Simulate LLM confidence adjustment"""
        original_confidence = span['confidence']
        
        # Simulate realistic adjustments
        adjustments = {
            0.85: 0.05,  # High confidence - slight increase
            0.75: 0.10,  # Medium-high - moderate increase
            0.65: 0.00,  # Medium - no change
            0.45: -0.15  # Low confidence - decrease
        }
        
        adjustment = adjustments.get(round(original_confidence, 1), 0.0)
        return max(0.0, min(1.0, original_confidence + adjustment))
    
    def _get_alternative_classification(self, span: Dict[str, Any]) -> Optional[str]:
        """Suggest alternative entity classifications"""
        alternatives = {
            'email': 'person_contact',
            'person_name': 'employee_name',
            'custom_jira_ticket': 'internal_reference',
            'custom_hostname': 'infrastructure_element'
        }
        
        return alternatives.get(span['entity_type'], None)
    
    def _assess_context_sensitivity(self, text: str, full_context: str) -> str:
        """Assess how context affects sensitivity"""
        context_lower = full_context.lower()
        
        if any(word in context_lower for word in ['breach', 'security', 'incident', 'report']):
            return 'high'
        elif any(word in context_lower for word in ['internal', 'team', 'meeting', 'discussion']):
            return 'medium'
        else:
            return 'low'

class LLMFinderProcessor:
    """Main processor for Stage 4: LLM Detection (Finder)"""
    
    def __init__(self, policy: PIIPolicy):
        self.policy = policy
        self.contextual_detector = ContextualPIIDetector()
        self.llm_simulator = LLMSimulator()
        
        # Store LLM analysis results for Stage 5
        self.span_analyses = {}
    
    async def find_llm_detections(self, deterministic_output: DeterministicOutput) -> LLMFinderResult:
        """Main method to perform LLM-based detection"""
        logger.info(f"Starting LLM Finder analysis on text with {len(deterministic_output.candidate_spans)} candidate spans")
        
        # Step 1: Analyze candidate spans from deterministic stage
        candidate_results = await self._analyze_candidate_spans(
            deterministic_output.original_text, 
            deterministic_output.candidate_spans
        )
        
        # Step 2: Find additional contextual PII detections
        additional_detections = self.contextual_detector.analyze_contextual_pii(
            deterministic_output.original_text,
            deterministic_output.candidate_spans
        )
        
        # Step 3: Combine all LLM detections
        all_llm_detections = self._combine_llm_detections(candidate_results, additional_detections)
        
        # Step 4: Generate processing statistics
        processing_stats = self._generate_processing_stats(
            deterministic_output, 
            all_llm_detections
        )
        
        # Store analyses for Stage 5
        self.span_analyses.update(candidate_results)
        
        logger.info(f"LLM Finder complete: {len(all_llm_detections)} total detections found")
        
        return LLMFinderResult(
            original_text=deterministic_output.original_text,
            detected_spans=all_llm_detections,
            candidate_spans_processed=deterministic_output.candidate_spans,
            additional_detections=additional_detections,
            processing_stats=processing_stats,
            timestamp=datetime.now().isoformat()
        )
    
    async def _analyze_candidate_spans(self, text: str, candidate_spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze candidate spans using simulated LLM"""
        try:
            # In production, this would be: await openai_client.analyze_spans(text, candidate_spans)
            llm_results = await self.llm_simulator.analyze_spans(text, candidate_spans)
            
            # Combine with span metadata
            enriched_results = {}
            for span in candidate_spans:
                span_id = span['span_id']
                if span_id in llm_results:
                    enriched_results[span_id] = {
                        **span,  # Original deterministic detection
                        **llm_results[span_id],  # LLM analysis
                        'processed_by_finder': True,
                        'llm_model': self.llm_simulator.model_name
                    }
            
            return enriched_results
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {}
    
    def _combine_llm_detections(self, candidate_results: Dict[str, Dict[str, Any]], 
                               additional_detections: List[LLMDetection]) -> List[LLMDetection]:
        """Combine candidate span analyses with new contextual detections"""
        combined_detections = []
        
        # Process candidate spans
        for span_id, span_data in candidate_results.items():
            detection = LLMDetection(
                span_id=span_id,
                entity_type=span_data['entity_type'],
                detected_text=span_data['text'],
                start_pos=span_data['start_pos'],
                end_pos=span_data['end_pos'],
                confidence_score=span_data['confidence'] + span_data.get('confidence_adjustment', 0.0),
                reasoning=span_data['reasoning'],
                context_snippet=span_data['context_snippet'],
                llm_model=span_data['llm_model'],
                detection_time=datetime.now().isoformat()
            )
            combined_detections.append(detection)
        
        # Add contextual detections
        combined_detections.extend(additional_detections)
        
        # Sort by confidence score (highest first)
        combined_detections.sort(key=lambda x: x.confidence_score, reverse=True)
        
        return combined_detections
    
    def _generate_processing_stats(self, deterministic_output: DeterministicOutput, 
                                 llm_detections: List[LLMDetection]) -> Dict[str, Any]:
        """Generate processing statistics"""
        stats = {
            'input_length': len(deterministic_output.original_text),
            'candidate_spans_input': len(deterministic_output.candidate_spans),
            'llm_detections_found': len(llm_detections),
            'additional_contextual_detections': len([d for d in llm_detections if 'llm_' in d.span_id]),
            'avg_confidence': sum(d.confidence_score for d in llm_detections) / len(llm_detections) if llm_detections else 0.0,
            'high_confidence_detections': len([d for d in llm_detections if d.confidence_score >= 0.8]),
            'medium_confidence_detections': len([d for d in llm_detections if 0.6 <= d.confidence_score < 0.8]),
            'low_confidence_detections': len([d for d in llm_detections if d.confidence_score < 0.6])
        }
        
        # Detection method breakdown
        methods = {}
        for detection in llm_detections:
            if 'llm_' in detection.span_id:
                methods['contextual'] = methods.get('contextual', 0) + 1
            else:
                methods['enhanced_deterministic'] = methods.get('enhanced_deterministic', 0) + 1
        stats['detection_methods'] = methods
        
        return stats
    
    def get_span_analysis(self, span_id: str) -> Optional[Dict[str, Any]]:
        """Get stored span analysis for Stage 5"""
        return self.span_analyses.get(span_id)
    
    def save_results(self, result: LLMFinderResult, filepath: str):
        """Save LLM Finder results"""
        data = {
            'original_text': result.original_text,
            'detected_spans': [asdict(detection) for detection in result.detected_spans],
            'candidate_spans_processed': result.candidate_spans_processed,
            'additional_detections': [asdict(detection) for detection in result.additional_detections],
            'processing_stats': result.processing_stats,
            'timestamp': result.timestamp
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"LLM Finder results saved to {filepath}")

# Example usage and testing
if __name__ == "__main__":
    logger.info("Stage 4: LLM Detection (Finder) module loaded")
