"""
Core PII redaction functionality
"""
import logging
from typing import List, Dict, Any, Optional
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer import OperatorConfig
from .pii_detector import PIIDetector, PIIOccurrence

logger = logging.getLogger(__name__)

class PIIRedactor:
    """Main PII redaction engine"""
    
    def __init__(self):
        """Initialize the PII redactor"""
        try:
            self.anonymizer = AnonymizerEngine()
            self.detector = PIIDetector()
            logger.info("PII Redactor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize PII redactor: {e}")
            raise
    
    def redact_text(self, text: str, redaction_method: str = "replace") -> Dict[str, Any]:
        """
        Redact PII from text using specified method
        
        Args:
            text: Input text containing PII
            redaction_method: Method to use for redaction ('replace', 'hash', 'mask', 'remove')
            
        Returns:
            Dictionary with redacted text and details about redactions performed
        """
        try:
            # Detect PII first
            pii_occurrences = self.detector.detect_pii(text)
            
            if not pii_occurrences:
                return {"redacted_text": text, "redactions": [], "original_length": len(text)}
            
            # Configure anonymization operators based on method
            operators = self._get_operators_for_method(redaction_method)
            
            # Anonymize using Presidio
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=pii_occurrences,
                operators=operators
            )
            
            # Process redaction details
            redactions = self._process_redaction_details(
                text, 
                pii_occurrences, 
                anonymized_result.text,
                redaction_method
            )
            
            logger.info(f"Redacted {len(redactions)} PII occurrences")
            
            return {
                "redacted_text": anonymized_result.text,
                "redactions": redactions,
                "original_length": len(text),
                "redacted_length": len(anonymized_result.text)
            }
            
        except Exception as e:
            logger.error(f"Error redacting PII: {e}")
            raise
    
    def redact_batch(self, texts: List[str], redaction_method: str = "replace") -> Dict[str, Dict[str, Any]]:
        """
        Redact PII from multiple texts
        
        Args:
            texts: List of texts to redact
            redaction_method: Method to use for redaction
            
        Returns:
            Dictionary mapping text index to redaction results
        """
        results = {}
        for i, text in enumerate(texts):
            results[str(i)] = self.redact_text(text, redaction_method)
        return results
    
    def _get_operators_for_method(self, method: str) -> Dict[str, OperatorConfig]:
        """Get operator configuration for redaction method"""
        operators = {}
        
        if method == "replace":
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "PERSON": OperatorConfig("replace", {"new_value": "[PERSON]"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CARD]"}),
                "US_SSN": OperatorConfig("replace", {"new_value": "[SSN]"}),
            }
        elif method == "hash":
            operators = {
                "DEFAULT": OperatorConfig("hash"),
            }
        elif method == "mask":
            operators = {
                "DEFAULT": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4}),
            }
        elif method == "remove":
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": ""}),
            }
        else:
            # Default to replace
            operators = {
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
            }
            
        return operators
    
    def _process_redaction_details(self, original_text: str, pii_occurrences: List[PIIOccurrence], 
                                 redacted_text: str, method: str) -> List[Dict[str, Any]]:
        """Process and format redaction details"""
        redactions = []
        
        for occurrence in pii_occurrences:
            # Determine what the text was replaced with
            replaced_text = self._find_replacement_text(original_text, redacted_text, occurrence.start)
            
            redaction_detail = {
                "entity_type": occurrence.entity_type,
                "original_text": occurrence.text,
                "replaced_text": replaced_text,
                "position": {
                    "start": occurrence.start,
                    "end": occurrence.end
                },
                "confidence": occurrence.score,
                "redaction_method": method,
                "context": occurrence.context
            }
            redactions.append(redaction_detail)
            
        return redactions
    
    def _find_replacement_text(self, original: str, redacted: str, position: int) -> str:
        """Find what text was used as replacement at given position"""
        # This is a simplified approach - in practice you'd want more sophisticated text diffing
        surrounding_text = original[max(0, position-5):position+5]
        return "[REDACTED]"
