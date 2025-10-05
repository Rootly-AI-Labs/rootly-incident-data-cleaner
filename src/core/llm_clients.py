"""
LLM Client implementations for OpenAI GPT-4o and Anthropic Claude-3.5-Sonnet
"""

import json
import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Union
from abc import ABC, abstractmethod

from config.llm_config import LLMModel, LLMProvider, LLMConfigManager

logger = logging.getLogger(__name__)

class LLMClient(ABC):
    """Abstract base class for LLM clients"""
    
    def __init__(self, model: LLMModel):
        self.model = model
        self.client = None
        self._setup_client()
    
    @abstractmethod
    def _setup_client(self):
        """Setup the client"""
        pass
    
    @abstractmethod
    async def analyze_spans(self, text: str, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze spans for PII detection"""
        pass
    
    @abstractmethod
    async def judge_redaction(self, text: str, detected_entity: Dict[str, Any], policy_context: str) -> Dict[str, Any]:
        """Judge whether entity should be redacted"""
        pass

class OpenAIClient(LLMClient):
    """OpenAI GPT-4o client"""
    
    def _setup_client(self):
        """Setup OpenAI client"""
        try:
            import openai
            self.openai = openai
            
            api_key = self.model.api_key_env_var
            import os
            key = os.getenv(api_key)
            
            if not key:
                logger.warning(f"No API key found for {api_key}")
                self.client = None
                return
            
            self.client = openai.AsyncOpenAI(
                api_key=key,
                timeout=self.model.timeout
            )
            logger.info(f"OpenAI client initialized for {self.model.model_name}")
            
        except ImportError:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.client = None
    
    async def analyze_spans(self, text: str, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze spans using GPT-4o"""
        if not self.client:
            return self._simulate_analysis(spans)
        
        try:
            # Create prompt for span analysis
            prompt = self._create_finder_prompt(text, spans)
            
            response = await self.client.chat.completions.create(
                model=self.model.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert PII detection AI. Analyze each span and determine if it contains sensitive information."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=self.model.max_tokens,
                temperature=self.model.temperature
            )
            
            # Parse response
            analysis = self._parse_finder_response(response.choices[0].message.content, spans)
            logger.info(f"GPT-4o analyzed {len(spans)} spans")
            return analysis
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return self._simulate_analysis(spans)
    
    async def judge_redaction(self, text: str, detected_entity: Dict[str, Any], policy_context: str) -> Dict[str, Any]:
        """Judge redaction using GPT-4o"""
        if not self.client:
            return self._simulate_judgement(detected_entity)
        
        try:
            prompt = self._create_judge_prompt(text, detected_entity, policy_context)
            
            response = await self.client.chat.completions.create(
                model=self.model.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a privacy expert judge. Decide whether detected entities should be redacted based on policy and context."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.model.max_tokens,
                temperature=self.model.temperature
            )
            
            judgement = self._parse_judge_response(response.choices[0].message.content, detected_entity)
            logger.info(f"GPT-4o judged {detected_entity.get('entity_type', 'unknown')} entity")
            return judgement
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return self._simulate_judgement(detected_entity)
    
    def _create_finder_prompt(self, text: str, spans: List[Dict[str, Any]]) -> str:
        """Create prompt for finding additional PII"""
        spans_info = []
        for span in spans:
            spans_info.append(f"Span {span['span_id']}: '{span['text']}' at position {span['start_pos']}-{span['end_pos']}")
        
        return f"""
Analyze this text for any additional PII or sensitive information:

Text: {text[:1000]}...

Known detections so far:
{chr(10).join(spans_info)}

Additional context-detection patterns to look for:
- Employment information (team references, job roles, employee mentions)
- Financial data (salary, revenue, budget mentions)
- Internal operations (platform usage, investigation details)
- Technical details (API endpoints, authentication flows)

For each span, provide:
- Span ID
- Additional PII detected (if any)
- Confidence score (0.0-1.0)
- Reasoning

Respond in JSON format:
{{
  "span_analyses": [
    {{
      "span_id": "...",
      "additional_pii": "...",
      "confidence": 0.85,
      "reasoning": "..."
    }}
  ]
}}
"""
    
    def _create_judge_prompt(self, text: str, entity: Dict[str, Any], policy_context: str) -> str:
        """Create prompt for judging redaction"""
        entity_text = entity.get('detected_text', '')
        entity_type = entity.get('entity_type', 'unknown')
        
        return f"""
You are a privacy compliance judge. Determine whether this entity should be redacted.

Entity Details:
- Type: {entity_type}
- Text: "{entity_text}"
- Confidence: {entity.get('confidence_score', 0.0)}

Context: {text[:500]}...

Policy Guidelines:
{policy_context}

Decision Criteria:
1. HIGH SENSITIVITY: Personal identifiers (names, emails, phones, SSNs) → REDACT
2. MEDIUM SENSITIVITY: Operational info (hostnames, internal references) → PSEUDONYMIZE  
3. LOW SENSITIVITY: Public info or safe references → RETAIN
4. SECRETS: Always REDACT regardless of context

Respond with JSON:
{{
  "decision": "REDACT|PSEUDONYMIZE|RETAIN",
  "confidence": 0.95,
  "reasoning": "...",
  "policy_violation_level": "HIGH|MEDIUM|LOW|NONE",
  "alternatives": ["...", "..."]
}}
"""
    
    def _parse_finder_response(self, response: str, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Parse GPT-4o finder response"""
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            results = {}
            for analysis in data.get('span_analyses', []):
                span_id = analysis['span_id']
                results[span_id] = {
                    'confirmed': True,
                    'confidence_adjustment': min(0.2, max(-0.1, float(analysis.get('confidence', 0.8)) - 0.8)),
                    'additional_context': analysis.get('additional_pii', ''),
                    'requires_expert_review': float(analysis.get('confidence', 0.8)) < 0.7,
                    'reasoning': analysis.get('reasoning', 'GPT-4o analysis'),
                    'alternative_classification': None,
                    'context_sensitivity': 'medium'
                }
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to parse GPT-4o finder response: {e}")
            return self._simulate_analysis(spans)
    
    def _parse_judge_response(self, response: str, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GPT-4o judge response"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            return {
                'keep_redaction': data.get('decision') in ['REDACT', 'PSEUDONYMIZE'],
                'replacement_hint': data.get('alternative_classification'),
                'confidence': float(data.get('confidence', 0.9)),
                'reasoning': data.get('reasoning', 'No reasoning provided'),
                'policy_violation_level': data.get('policy_violation_level', 'MEDIUM'),
                'decision': data.get('decision', 'RETAIN'),
                'llm_model': self.model.model_name,
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Failed to parse GPT-4o judge response: {e}")
            return self._simulate_judgement(entity)
    
    def _simulate_analysis(self, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Simulate analysis when API unavailable"""
        return {
            span['span_id']: {
                'confirmed': True,
                'confidence_adjustment': 0.1,
                'additional_context': True,
                'requires_expert_review': span.get('confidence', 0.8) < 0.7,
                'reasoning': 'Simulated GPT-4o analysis (API unavailable)',
                'alternative_classification': None,
                'context_sensitivity': 'medium'
            }
            for span in spans
        }
    
    def _simulate_judgement(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate judgement when API unavailable"""
        entity_type = entity.get('entity_type', 'unknown')
        
        # Simple rule-based simulation
        if 'email' in entity_type.lower() or 'credit_card' in entity_type.lower():
            decision = 'REDACT'
        elif 'person_name' in entity_type.lower():
            decision = 'PSEUDONYMIZE'
        else:
            decision = 'RETAIN'
        
        return {
            'keep_redaction': decision in ['REDACT', 'PSEUDONYMIZE'],
            'replacement_hint': None,
            'confidence': 0.7,
            'reasoning': f'Simulated GPT-4o judgement for {entity_type}',
            'policy_violation_level': 'MEDIUM',
            'decision': decision,
            'llm_model': f'simulated_{self.model.model_name}',
            'timestamp': time.time()
        }

class AnthropicClient(LLMClient):
    """Anthropic Claude-3.5-Sonnet client"""
    
    def _setup_client(self):
        """Setup Anthropic client"""
        try:
            import anthropic
            self.anthropic = anthropic
            
            api_key = self.model.api_key_env_var
            import os
            key = os.getenv(api_key)
            
            if not key:
                logger.warning(f"No API key found for {api_key}")
                self.client = None
                return
            
            self.client = anthropic.AsyncAnthropic(
                api_key=key,
                timeout=self.model.timeout
            )
            logger.info(f"Anthropic client initialized for {self.model.model_name}")
            
        except ImportError:
            logger.error("Anthropic package not installed. Install with: pip install anthropic")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            self.client = None
    
    async def analyze_spans(self, text: str, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze spans using Claude-3.5-Sonnet"""
        if not self.client:
            return self._simulate_analysis(spans)
        
        try:
            prompt = self._create_finder_prompt(text, spans)
            
            response = await self.client.messages.create(
                model=self.model.model_name,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.model.max_tokens,
                temperature=self.model.temperature
            )
            
            analysis = self._parse_finder_response(response.content[0].text, spans)
            logger.info(f"Claude-3.5-Sonnet analyzed {len(spans)} spans")
            return analysis
            
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return self._simulate_analysis(spans)
    
    async def judge_redaction(self, text: str, detected_entity: Dict[str, Any], policy_context: str) -> Dict[str, Any]:
        """Judge redaction using Claude-3.5-Sonnet"""
        if not self.client:
            return self._simulate_judgement(detected_entity)
        
        try:
            prompt = self._create_judge_prompt(text, detected_entity, policy_context)
            
            response = await self.client.messages.create(
                model=self.model.model_name,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.model.max_tokens,
                temperature=self.model.temperature
            )
            
            judgement = self._parse_judge_response(response.content[0].text, detected_entity)
            logger.info(f"Claude-3.5-Sonnet judged {detected_entity.get('entity_type', 'unknown')} entity")
            return judgement
            
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return self._simulate_judgement(detected_entity)
    
    def _create_finder_prompt(self, text: str, spans: List[Dict[str, Any]]) -> str:
        """Create prompt for finding additional PII"""
        spans_info = []
        for span in spans:
            spans_info.append(f"Span {span['span_id']}: '{span['text']}' at position {span['start_pos']}-{span['end_pos']}")
        
        return f"""
Analyze this incident/support text for additional sensitive information:

Text: {text[:1000]}...

Detected so far:
{chr(10).join(spans_info)}

Focus on finding nuanced context-sensitive PII:
- Team/organizational references revealing internal structure
- Technical details exposing system architecture  
- Financial/business metrics requiring protection
- Investigation/enumeration details

For each detection region, assess:
- Additional sensitive info discovered
- Context sensitivity level
- Regulatory compliance risk

Format response as JSON:
{{
  "span_analyses": [
    {{
      "span_id": "...",
      "contextual_pii": "...",
      "sensitivity_score": 0.85,
      "compliance_risk": "HIGH|MEDIUM|LOW",
      "reasoning": "Detailed explanation..."
    }}
  ]
}}
"""
    
    def _create_judge_prompt(self, text: str, entity: Dict[str, Any], policy_context: str) -> str:
        """Create prompt for judging redaction"""
        entity_text = entity.get('detected_text', '')
        entity_type = entity.get('entity_type', 'unknown')
        
        return f"""
Privacy compliance decision required:

Entity: "{entity_text}"
Type: {entity_type}
Confidence: {entity.get('confidence_score', 0.0)}

Document context: {text[:500]}...

Compliance policies:
{policy_context}

Legal/privacy assessment:
- GDPR/HIPAA/SOX compliance risks
- Data minimization principles
- Organizational vs personal data distinction
- Context-driven risk evaluation

Provide structured judgement:
{{
  "decision": "REDACT|PSEUDONYMIZE|RETAIN",
  "compliance_assessment": "HIGH|MEDIUM|LOW|NONE", 
  "confidence": 0.95,
  "legal_reasoning": "Detailed legal/privacy analysis",
  "risk_factors": ["factor1", "factor2"],
  "policy_alignment": true,
  "recommended_action": "..."
}}
"""
    
    def _parse_finder_response(self, response: str, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Parse Claude-3.5-Sonnet finder response"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            results = {}
            for analysis in data.get('span_analyses', []):
                span_id = analysis['span_id']
                sensitivity_score = float(analysis.get('sensitivity_score', 0.6))
                
                results[span_id] = {
                    'confirmed': True,
                    'confidence_adjustment': min(0.25, max(-0.15, sensitivity_score - 0.6)),
                    'additional_context': analysis.get('contextual_pii', ''),
                    'requires_expert_review': analysis.get('compliance_risk') == 'HIGH',
                    'reasoning': analysis.get('reasoning', 'Claude-3.5-Sonnet analysis'),
                    'alternative_classification': None,
                    'context_sensitivity': analysis.get('compliance_risk', 'MEDIUM').lower()
                }
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to parse Claude-3.5-Sonnet finder response: {e}")
            return self._simulate_analysis(spans)
    
    def _parse_judge_response(self, response: str, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Claude-3.5-Sonnet judge response"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            return {
                'keep_redaction': data.get('decision') in ['REDACT', 'PSEUDONYMIZE'],
                'replacement_hint': data.get('recommended_action'),
                'confidence': float(data.get('confidence', 0.9)),
                'reasoning': data.get('legal_reasoning', 'No reasoning provided'),
                'policy_violation_level': data.get('compliance_assessment', 'MEDIUM'),
                'decision': data.get('decision', 'RETAIN'),
                'risk_factors': data.get('risk_factors', []),
                'policy_alignment': data.get('policy_alignment', False),
                'llm_model': self.model.model_name,
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Failed to parse Claude-3.5-Sonnet judge response: {e}")
            return self._simulate_judgement(entity)
    
    def _simulate_analysis(self, spans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Simulate analysis when API unavailable"""
        return {
            span['span_id']: {
                'confirmed': True,
                'confidence_adjustment': 0.15,
                'additional_context': True,
                'requires_expert_review': span.get('confidence', 0.8) < 0.6,
                'reasoning': 'Simulated Claude-3.5-Sonnet analysis (API unavailable)',
                'alternative_classification': None,
                'context_sensitivity': 'high'
            }
            for span in spans
        }
    
    def _simulate_judgement(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate judgement when API unavailable"""
        entity_type = entity.get('entity_type', 'unknown')
        
        # More conservative simulation for Claude
        if 'email' in entity_type.lower() or 'credit_card' in entity_type.lower() or 'ssn' in entity_type.lower():
            decision = 'REDACT'
        elif 'person_name' in entity_type.lower() or 'salary' in entity_type.lower():
            decision = 'PSEUDONYMIZE'
        else:
            decision = 'RETAIN'
        
        return {
            'keep_redaction': decision in ['REDACT', 'PSEUDONYMIZE'],
            'replacement_hint': None,
            'confidence': 0.85,
            'reasoning': f'Simulated Claude-3.5-Sonnet judgement for {entity_type}',
            'policy_violation_level': 'HIGH' if decision == 'REDACT' else 'MEDIUM',
            'decision': decision,
            'risk_factors': ['simulated_analysis'],
            'policy_alignment': True,
            'llm_model': f'simulated_{self.model.model_name}',
            'timestamp': time.time()
        }
