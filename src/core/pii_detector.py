"""
Core PII detection functionality
"""
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import regex as re
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer import RecognizerResult

logger = logging.getLogger(__name__)

@dataclass
class PIIOccurrence:
    """Represents a detected PII occurrence"""
    start: int
    end: int
    entity_type: str
    score: float
    text: str
    context: Optional[str] = None

class PIIDetector:
    """Main PII detection engine"""
    
    overhead_content_types = [
        "PERSON",
        "PHONE_NUMBER", 
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "US_SSN",
        "ADDRESS",
        "DATE_OF_Birth",
        "IP_ADDRESS",
        "IBAN_CODE",
        "NHS",
        "LOCATION"
    ]
    
    def __init__(self):
        """Initialize the PII detector"""
        try:
            # Initialize Presidio analyzer
            self.analyzer = AnalyzerEngine()
            logger.info("PII Detector initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize PII detector: {e}")
            raise
    
    def detect_pii(self, text: str, entities: Optional[List[str]] = None) -> List[PIIOccurrence]:
        """
        Detect PII in the given text
        
        Args:
            text: Input text to analyze
            entities: Specific entity types to search for (None for all)
            
        Returns:
            List of PII occurrences found
        """
        if not entities:
            entities = self.overhead_content_types
            
        try:
            # Use Presidio to analyze the text
            results: List[RecognizerResult] = self.analyzer.analyze(
                text=text,
                entities=entities,
                language="en"
            )
            
            # Convert to our PIIOccurrence format
            pii_occurrences = []
            for result in results:
                occurrence = PIIOccurrence(
                    start=result.start,
                    end=result.end,
                    entity_type=result.entity_type,
                    score=result.score,
                    text=text[result.start:result.end],
                    context=self._extract_context(text, result.start, result.end)
                )
                pii_occurrences.append(occurrence)
                
            logger.info(f"Detected {len(pii_occurrences)} PII occurrences")
            return pii_occurrences
            
        except Exception as e:
            logger.error(f"Error detecting PII: {e}")
            raise
    
    def detect_pii_batch(self, texts: List[str]) -> Dict[str, List[PIIOccurrence]]:
        """
        Detect PII in multiple texts
        
        Args:
            texts: List of texts to analyze
            
        Returns:
            Dictionary mapping text index to list of PII occurrences
        """
        results = {}
        for i, text in enumerate(texts):
            results[str(i)] = self.detect_pii(text)
        return results
    
    def _extract_context(self, text: str, start: int, end: int, context_window: int = 50) -> str:
        """Extract surrounding context for PII occurrence"""
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        context = text[context_start:context_end]
        
        # Add ellipsis if we truncated
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
            
        return context
    
    def validate_pii_false_positive(self, occurrence: PIIOccurrence) -> bool:
        """
        Check if a PII detection might be a false positive
        
        Returns:
            True if likely false positive, False otherwise
        """
        # Common false positive patterns
        false_positive_patterns = {
            "PERSON": [r"^\d+$", r"^[A-Z]{2,}$", r"^\w{1,2}$"],  # Numbers, abbreviations, short words
            "EMAIL_ADDRESS": [r"@example\.com$", r"@test\.com$"],  # Common test emails
            "PHONE_NUMBER": [r"^\d{4}$", r"^\d{3}-\d{4}$"]  # Short numbers, partial formats
        }
        
        patterns = false_positive_patterns.get(occurrence.entity_type, [])
        for pattern in patterns:
            if re.match(pattern, occurrence.text):
                return True
                
        return False
