"""
Stage 7: Validation & Post-Check
Purpose: Ensure final output contains zero residual PII and remains schema-valid.
Run secondary detectors or adversarial LLM checks, validate schema integrity, 
and compute precision/recall metrics.
"""

import json
import logging
import re
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime

from ..policies.policy_manager import PIIPolicy, RedactionAction, DataCategory
from .arbitration_engine import ArbitrationResult, ArbitrationDecision
from ..core.pii_detector import PIIDetector, PIIOccurrence
from ..core.pii_redactor import PIIRedactor

logger = logging.getLogger(__name__)

@dataclass
class ValidationIssue:
    """Represents a validation issue found during post-check"""
    issue_type: str  # 'residual_pii', 'schema_violation', 'inconsistency', 'quality_issue'
    severity: str    # 'critical', 'high', 'medium', 'low'
    description: str
    location: Optional[Dict[str, Any]] = None  # position, line, etc.
    suggested_fix: Optional[str] = None
    confidence: float = 1.0
    detection_method: str = "validation"

@dataclass
class QualityMetrics:
    """Quality assurance metrics"""
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    residual_pii_count: int
    schema_violations: int
    consistency_score: float
    overall_quality_score: float

@dataclass
class ValidationResult:
    """Complete result from Validation & Post-Check stage"""
    original_text: str
    processed_text: str
    validation_issues: List[ValidationIssue]
    quality_metrics: QualityMetrics
    secondary_detection_results: Dict[str, Any]
    schema_validation_results: Dict[str, Any]
    adversarial_check_results: Dict[str, Any]
    recommendations: List[str]
    timestamp: str

class ResidualPIIDetector:
    """Detects residual PII that may have been missed"""
    
    def __init__(self, policy: PIIPolicy):
        self.policy = policy
        self.pii_detector = PIIDetector()
        
        # Enhanced patterns for residual detection
        self.residual_patterns = {
            'email_fragments': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            'phone_fragments': re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            'ssn_fragments': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
            'credit_card_fragments': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ip_address_fragments': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'name_fragments': re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'),
            'hostname_fragments': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\\b'),
            'api_key_fragments': re.compile(r'\b[A-Za-z0-9]{20,}\b'),
            'internal_paths': re.compile(r'/[a-zA-Z0-9_./-]+'),
            'customer_ids': re.compile(r'\b(?:cust|customer|user|account)_\d+\b', re.IGNORECASE)
        }
        
        # Patterns that should NOT be flagged (false positives)
        self.exclusion_patterns = {
            'redaction_markers': re.compile(r'\[REDACTED_[A-Z_]+\]'),
            'pseudonyms': re.compile(r'Person_[a-f0-9]{6}'),
            'example_text': re.compile(r'\(example:.*?\)'),
            'placeholder_text': re.compile(r'\[.*?\]'),
            'technical_refs': re.compile(r'(?:SEC|INC|JIRA|TICKET)-\d+', re.IGNORECASE)
        }
    
    def detect_residual_pii(self, processed_text: str, original_decisions: List[ArbitrationDecision]) -> List[ValidationIssue]:
        """Detect residual PII in processed text"""
        issues = []
        
        # Get positions that were already processed
        processed_positions = set()
        for decision in original_decisions:
            for pos in range(decision.start_pos, decision.end_pos):
                processed_positions.add(pos)
        
        # Check each pattern
        for pattern_name, pattern_regex in self.residual_patterns.items():
            matches = pattern_regex.finditer(processed_text)
            
            for match in matches:
                start_pos = match.start()
                end_pos = match.end()
                matched_text = match.group()
                
                # Skip if this position was already processed
                if any(pos in processed_positions for pos in range(start_pos, end_pos)):
                    continue
                
                # Skip if it matches exclusion patterns
                if self._is_excluded_text(matched_text):
                    continue
                
                # Determine severity based on pattern type
                severity = self._get_pattern_severity(pattern_name)
                
                issue = ValidationIssue(
                    issue_type='residual_pii',
                    severity=severity,
                    description=f"Residual {pattern_name.replace('_', ' ')} detected: '{matched_text}'",
                    location={'start_pos': start_pos, 'end_pos': end_pos, 'text': matched_text},
                    suggested_fix=f"Apply {self._get_suggested_action(pattern_name)} to '{matched_text}'",
                    confidence=0.9,
                    detection_method=f"residual_pattern_{pattern_name}"
                )
                issues.append(issue)
        
        return issues
    
    def _is_excluded_text(self, text: str) -> bool:
        """Check if text should be excluded from residual detection"""
        for exclusion_pattern in self.exclusion_patterns.values():
            if exclusion_pattern.search(text):
                return True
        return False
    
    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Get severity level for pattern type"""
        high_severity = ['email_fragments', 'ssn_fragments', 'credit_card_fragments', 'api_key_fragments']
        medium_severity = ['phone_fragments', 'name_fragments', 'ip_address_fragments']
        
        if pattern_name in high_severity:
            return 'critical'
        elif pattern_name in medium_severity:
            return 'high'
        else:
            return 'medium'
    
    def _get_suggested_action(self, pattern_name: str) -> str:
        """Get suggested action for pattern type"""
        action_map = {
            'email_fragments': 'REDACT',
            'phone_fragments': 'REDACT',
            'ssn_fragments': 'REDACT',
            'credit_card_fragments': 'REDACT',
            'api_key_fragments': 'REDACT',
            'name_fragments': 'PSEUDONYMIZE',
            'ip_address_fragments': 'PSEUDONYMIZE',
            'hostname_fragments': 'PSEUDONYMIZE',
            'customer_ids': 'PSEUDONYMIZE'
        }
        return action_map.get(pattern_name, 'REDACT')

class SchemaValidator:
    """Validates document schema and structure integrity"""
    
    def __init__(self):
        self.schema_patterns = {
            'json_structure': re.compile(r'\{.*\}', re.DOTALL),
            'xml_structure': re.compile(r'<[^>]+>.*</[^>]+>', re.DOTALL),
            'markdown_structure': re.compile(r'^#+ .*$', re.MULTILINE),
            'email_structure': re.compile(r'^From:.*\nTo:.*\nSubject:.*', re.MULTILINE),
            'log_structure': re.compile(r'^\d{4}-\d{2}-\d{2}.*', re.MULTILINE)
        }
    
    def validate_schema_integrity(self, original_text: str, processed_text: str) -> List[ValidationIssue]:
        """Validate that schema structure is preserved"""
        issues = []
        
        # Check basic structure preservation
        original_lines = original_text.split('\n')
        processed_lines = processed_text.split('\n')
        
        if len(original_lines) != len(processed_lines):
            issue = ValidationIssue(
                issue_type='schema_violation',
                severity='high',
                description=f"Line count mismatch: original {len(original_lines)} vs processed {len(processed_lines)}",
                suggested_fix="Review text processing for line break preservation",
                confidence=1.0,
                detection_method="schema_validation"
            )
            issues.append(issue)
        
        # Check for structural patterns
        for pattern_name, pattern_regex in self.schema_patterns.items():
            original_matches = pattern_regex.findall(original_text)
            processed_matches = pattern_regex.findall(processed_text)
            
            if len(original_matches) != len(processed_matches):
                issue = ValidationIssue(
                    issue_type='schema_violation',
                    severity='medium',
                    description=f"{pattern_name} structure altered: {len(original_matches)} → {len(processed_matches)}",
                    suggested_fix=f"Preserve {pattern_name} structure during redaction",
                    confidence=0.8,
                    detection_method="schema_validation"
                )
                issues.append(issue)
        
        # Check for broken formatting
        broken_formatting = self._detect_broken_formatting(original_text, processed_text)
        issues.extend(broken_formatting)
        
        return issues
    
    def _detect_broken_formatting(self, original_text: str, processed_text: str) -> List[ValidationIssue]:
        """Detect broken formatting patterns"""
        issues = []
        
        # Check for broken brackets/parentheses
        original_brackets = original_text.count('[') + original_text.count(']')
        processed_brackets = processed_text.count('[') + processed_text.count(']')
        
        if abs(original_brackets - processed_brackets) > 2:  # Allow some variance
            issue = ValidationIssue(
                issue_type='schema_violation',
                severity='medium',
                description=f"Bracket count mismatch: {original_brackets} → {processed_brackets}",
                suggested_fix="Review bracket/parenthesis preservation",
                confidence=0.7,
                detection_method="formatting_validation"
            )
            issues.append(issue)
        
        # Check for broken quotes
        original_quotes = original_text.count('"') + original_text.count("'")
        processed_quotes = processed_text.count('"') + processed_text.count("'")
        
        if abs(original_quotes - processed_quotes) > 2:
            issue = ValidationIssue(
                issue_type='schema_violation',
                severity='low',
                description=f"Quote count mismatch: {original_quotes} → {processed_quotes}",
                suggested_fix="Review quote preservation",
                confidence=0.6,
                detection_method="formatting_validation"
            )
            issues.append(issue)
        
        return issues

class ConsistencyChecker:
    """Checks consistency of redaction decisions and pseudonymization"""
    
    def __init__(self):
        self.pseudonym_patterns = {
            'person_names': re.compile(r'Person_[a-f0-9]{6}'),
            'emails': re.compile(r'\[REDACTED_EMAIL\]'),
            'phones': re.compile(r'\[REDACTED_PHONE\]'),
            'hostnames': re.compile(r'server-[a-f0-9]{3}\.internal'),
            'ips': re.compile(r'192\.168\.1\.\d+')
        }
    
    def check_consistency(self, processed_text: str, arbitration_decisions: List[ArbitrationDecision]) -> List[ValidationIssue]:
        """Check consistency of redaction decisions"""
        issues = []
        
        # Check pseudonym consistency
        pseudonym_issues = self._check_pseudonym_consistency(processed_text, arbitration_decisions)
        issues.extend(pseudonym_issues)
        
        # Check decision consistency
        decision_issues = self._check_decision_consistency(arbitration_decisions)
        issues.extend(decision_issues)
        
        # Check replacement consistency
        replacement_issues = self._check_replacement_consistency(processed_text, arbitration_decisions)
        issues.extend(replacement_issues)
        
        return issues
    
    def _check_pseudonym_consistency(self, processed_text: str, decisions: List[ArbitrationDecision]) -> List[ValidationIssue]:
        """Check that pseudonyms are used consistently"""
        issues = []
        
        # Group decisions by entity type and original text
        pseudonym_groups = {}
        for decision in decisions:
            if decision.final_action == RedactionAction.PSEUDONYMIZE and decision.pseudonym_map_key:
                key = decision.pseudonym_map_key
                if key not in pseudonym_groups:
                    pseudonym_groups[key] = []
                pseudonym_groups[key].append(decision)
        
        # Check for inconsistent pseudonyms
        for key, group in pseudonym_groups.items():
            pseudonyms = set(decision.replacement_text for decision in group)
            if len(pseudonyms) > 1:
                issue = ValidationIssue(
                    issue_type='inconsistency',
                    severity='high',
                    description=f"Inconsistent pseudonyms for '{key}': {list(pseudonyms)}",
                    suggested_fix=f"Use consistent pseudonym for '{key}'",
                    confidence=1.0,
                    detection_method="consistency_check"
                )
                issues.append(issue)
        
        return issues
    
    def _check_decision_consistency(self, decisions: List[ArbitrationDecision]) -> List[ValidationIssue]:
        """Check consistency of decision patterns"""
        issues = []
        
        # Group by entity type
        entity_decisions = {}
        for decision in decisions:
            entity_type = decision.entity_type
            if entity_type not in entity_decisions:
                entity_decisions[entity_type] = []
            entity_decisions[entity_type].append(decision)
        
        # Check for inconsistent actions within entity types
        for entity_type, group in entity_decisions.items():
            actions = set(decision.final_action for decision in group)
            if len(actions) > 1:
                # This might be intentional (context-dependent), but worth flagging
                issue = ValidationIssue(
                    issue_type='inconsistency',
                    severity='medium',
                    description=f"Mixed actions for {entity_type}: {[a.value for a in actions]}",
                    suggested_fix=f"Review {entity_type} redaction strategy for consistency",
                    confidence=0.7,
                    detection_method="consistency_check"
                )
                issues.append(issue)
        
        return issues
    
    def _check_replacement_consistency(self, processed_text: str, decisions: List[ArbitrationDecision]) -> List[ValidationIssue]:
        """Check that replacements are applied consistently"""
        issues = []
        
        # Check for duplicate replacements that should be unique
        replacement_counts = {}
        for decision in decisions:
            if decision.final_action == RedactionAction.REDACT:
                replacement = decision.replacement_text
                replacement_counts[replacement] = replacement_counts.get(replacement, 0) + 1
        
        # Flag if too many identical redactions (might indicate over-redaction)
        for replacement, count in replacement_counts.items():
            if count > 10:  # Arbitrary threshold
                issue = ValidationIssue(
                    issue_type='quality_issue',
                    severity='medium',
                    description=f"High frequency of '{replacement}' replacements ({count} times)",
                    suggested_fix="Review if this indicates over-redaction",
                    confidence=0.6,
                    detection_method="replacement_analysis"
                )
                issues.append(issue)
        
        return issues

class AdversarialChecker:
    """Performs adversarial checks to find missed PII"""
    
    def __init__(self):
        self.adversarial_patterns = {
            'obfuscated_emails': re.compile(r'\b[a-zA-Z0-9._%+-]+\s*@\s*[a-zA-Z0-9.-]+\s*\.\s*[a-zA-Z]{2,}\b'),
            'spaced_phones': re.compile(r'\b(?:\+?1\s*[-.\s]?\s*)?\(?\s*[0-9]{3}\s*\)?\s*[-.\s]?\s*[0-9]{3}\s*[-.\s]?\s*[0-9]{4}\b'),
            'partial_ssns': re.compile(r'\b\d{3}\s*-\s*\d{2}\s*-\s*\d{4}\b'),
            'credit_card_variants': re.compile(r'\b(?:\d{4}\s*[-\s]?\s*){3}\d{4}\b'),
            'encoded_data': re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b'),  # Base64-like
            'hex_patterns': re.compile(r'\b[0-9a-fA-F]{8,}\b'),
            'obfuscated_names': re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b')
        }
    
    def perform_adversarial_check(self, processed_text: str) -> List[ValidationIssue]:
        """Perform adversarial checks for obfuscated PII"""
        issues = []
        
        for pattern_name, pattern_regex in self.adversarial_patterns.items():
            matches = pattern_regex.finditer(processed_text)
            
            for match in matches:
                matched_text = match.group()
                
                # Skip obvious redaction markers
                if any(marker in matched_text for marker in ['[REDACTED', 'Person_', 'server-']):
                    continue
                
                # Check if this looks like obfuscated PII
                if self._is_suspicious_pattern(matched_text, pattern_name):
                    issue = ValidationIssue(
                        issue_type='residual_pii',
                        severity='high',
                        description=f"Potential obfuscated {pattern_name.replace('_', ' ')}: '{matched_text}'",
                        location={'start_pos': match.start(), 'end_pos': match.end(), 'text': matched_text},
                        suggested_fix=f"Investigate potential obfuscated PII: '{matched_text}'",
                        confidence=0.8,
                        detection_method=f"adversarial_{pattern_name}"
                    )
                    issues.append(issue)
        
        return issues
    
    def _is_suspicious_pattern(self, text: str, pattern_name: str) -> bool:
        """Determine if pattern is suspicious"""
        # Simple heuristics for suspicious patterns
        if pattern_name == 'obfuscated_emails':
            return '@' in text and '.' in text and len(text) > 10
        elif pattern_name == 'spaced_phones':
            return any(c.isdigit() for c in text) and len([c for c in text if c.isdigit()]) >= 10
        elif pattern_name == 'partial_ssns':
            return len([c for c in text if c.isdigit()]) == 9
        elif pattern_name == 'credit_card_variants':
            return len([c for c in text if c.isdigit()]) >= 13
        elif pattern_name == 'encoded_data':
            return len(text) > 20 and text.isalnum()
        elif pattern_name == 'hex_patterns':
            return len(text) >= 8 and all(c in '0123456789abcdefABCDEF' for c in text)
        elif pattern_name == 'obfuscated_names':
            return len(text.split()) == 2 and all(word[0].isupper() for word in text.split())
        
        return False

class ValidationProcessor:
    """Main processor for Stage 7: Validation & Post-Check"""
    
    def __init__(self, policy: PIIPolicy):
        self.policy = policy
        self.residual_detector = ResidualPIIDetector(policy)
        self.schema_validator = SchemaValidator()
        self.consistency_checker = ConsistencyChecker()
        self.adversarial_checker = AdversarialChecker()
        
        # Quality metrics tracking
        self.metrics = {
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'residual_pii_count': 0,
            'schema_violations': 0,
            'consistency_issues': 0
        }
    
    def validate_and_post_check(self, arbitration_result: ArbitrationResult) -> ValidationResult:
        """Main method to perform validation and post-check"""
        
        logger.info("Starting Stage 7: Validation & Post-Check")
        
        # Step 1: Detect residual PII
        residual_issues = self.residual_detector.detect_residual_pii(
            arbitration_result.processed_text, 
            arbitration_result.arbitration_decisions
        )
        
        # Step 2: Validate schema integrity
        schema_issues = self.schema_validator.validate_schema_integrity(
            arbitration_result.original_text,
            arbitration_result.processed_text
        )
        
        # Step 3: Check consistency
        consistency_issues = self.consistency_checker.check_consistency(
            arbitration_result.processed_text,
            arbitration_result.arbitration_decisions
        )
        
        # Step 4: Perform adversarial checks
        adversarial_issues = self.adversarial_checker.perform_adversarial_check(
            arbitration_result.processed_text
        )
        
        # Step 5: Combine all issues
        all_issues = residual_issues + schema_issues + consistency_issues + adversarial_issues
        
        # Step 6: Generate quality metrics
        quality_metrics = self._generate_quality_metrics(
            arbitration_result, all_issues
        )
        
        # Step 7: Generate recommendations
        recommendations = self._generate_recommendations(all_issues, quality_metrics)
        
        # Step 8: Organize results
        secondary_detection_results = {
            'residual_pii_detected': len(residual_issues),
            'adversarial_issues_found': len(adversarial_issues),
            'total_pattern_matches': sum(len(issues) for issues in [residual_issues, adversarial_issues])
        }
        
        schema_validation_results = {
            'schema_violations': len(schema_issues),
            'structure_preserved': len(schema_issues) == 0,
            'formatting_issues': len([i for i in schema_issues if 'formatting' in i.detection_method])
        }
        
        adversarial_check_results = {
            'adversarial_patterns_checked': len(self.adversarial_checker.adversarial_patterns),
            'suspicious_patterns_found': len(adversarial_issues),
            'obfuscation_detected': len([i for i in adversarial_issues if 'obfuscated' in i.description])
        }
        
        logger.info(f"Validation complete: {len(all_issues)} issues found, quality score: {quality_metrics.overall_quality_score:.2f}")
        
        return ValidationResult(
            original_text=arbitration_result.original_text,
            processed_text=arbitration_result.processed_text,
            validation_issues=all_issues,
            quality_metrics=quality_metrics,
            secondary_detection_results=secondary_detection_results,
            schema_validation_results=schema_validation_results,
            adversarial_check_results=adversarial_check_results,
            recommendations=recommendations,
            timestamp=datetime.now().isoformat()
        )
    
    def _generate_quality_metrics(self, arbitration_result: ArbitrationResult, 
                                issues: List[ValidationIssue]) -> QualityMetrics:
        """Generate comprehensive quality metrics"""
        
        # Count issues by severity
        critical_issues = len([i for i in issues if i.severity == 'critical'])
        high_issues = len([i for i in issues if i.severity == 'high'])
        medium_issues = len([i for i in issues if i.severity == 'medium'])
        low_issues = len([i for i in issues if i.severity == 'low'])
        
        # Calculate precision/recall (simplified)
        total_decisions = len(arbitration_result.arbitration_decisions)
        residual_pii_count = len([i for i in issues if i.issue_type == 'residual_pii'])
        
        # Precision: correct redactions / total redactions
        correct_redactions = max(0, total_decisions - residual_pii_count)
        precision = correct_redactions / total_decisions if total_decisions > 0 else 1.0
        
        # Recall: detected PII / total PII (estimated)
        estimated_total_pii = total_decisions + residual_pii_count
        recall = total_decisions / estimated_total_pii if estimated_total_pii > 0 else 1.0
        
        # F1 Score
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # False positive/negative rates
        false_positive_rate = residual_pii_count / total_decisions if total_decisions > 0 else 0.0
        false_negative_rate = residual_pii_count / estimated_total_pii if estimated_total_pii > 0 else 0.0
        
        # Schema violations
        schema_violations = len([i for i in issues if i.issue_type == 'schema_violation'])
        
        # Consistency score
        consistency_issues = len([i for i in issues if i.issue_type == 'inconsistency'])
        consistency_score = max(0.0, 1.0 - (consistency_issues / max(1, total_decisions)))
        
        # Overall quality score (0-1 scale)
        issue_penalty = (critical_issues * 0.3 + high_issues * 0.2 + medium_issues * 0.1 + low_issues * 0.05)
        overall_quality_score = max(0.0, min(1.0, 1.0 - issue_penalty))
        
        return QualityMetrics(
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            residual_pii_count=residual_pii_count,
            schema_violations=schema_violations,
            consistency_score=consistency_score,
            overall_quality_score=overall_quality_score
        )
    
    def _generate_recommendations(self, issues: List[ValidationIssue], 
                                 metrics: QualityMetrics) -> List[str]:
        """Generate actionable recommendations based on validation results"""
        
        recommendations = []
        
        # Quality-based recommendations
        if metrics.overall_quality_score < 0.8:
            recommendations.append("Overall quality score below threshold (0.8). Review redaction strategy.")
        
        if metrics.precision < 0.9:
            recommendations.append("Precision below 90%. Consider refining detection patterns.")
        
        if metrics.recall < 0.95:
            recommendations.append("Recall below 95%. Consider additional detection methods.")
        
        # Issue-based recommendations
        critical_issues = [i for i in issues if i.severity == 'critical']
        if critical_issues:
            recommendations.append(f"Address {len(critical_issues)} critical issues immediately.")
        
        residual_pii = [i for i in issues if i.issue_type == 'residual_pii']
        if residual_pii:
            recommendations.append(f"Review {len(residual_pii)} residual PII detections.")
        
        schema_issues = [i for i in issues if i.issue_type == 'schema_violation']
        if schema_issues:
            recommendations.append(f"Fix {len(schema_issues)} schema integrity issues.")
        
        consistency_issues = [i for i in issues if i.issue_type == 'inconsistency']
        if consistency_issues:
            recommendations.append(f"Resolve {len(consistency_issues)} consistency issues.")
        
        # Specific pattern recommendations
        if any('email' in i.description for i in issues):
            recommendations.append("Review email detection patterns for completeness.")
        
        if any('phone' in i.description for i in issues):
            recommendations.append("Review phone number detection patterns.")
        
        if any('obfuscated' in i.description for i in issues):
            recommendations.append("Consider additional adversarial detection methods.")
        
        return recommendations
    
    def save_results(self, result: ValidationResult, filepath: str):
        """Save validation results"""
        
        # Convert to serializable format
        issues_data = []
        for issue in result.validation_issues:
            issue_data = {
                'issue_type': issue.issue_type,
                'severity': issue.severity,
                'description': issue.description,
                'location': issue.location,
                'suggested_fix': issue.suggested_fix,
                'confidence': issue.confidence,
                'detection_method': issue.detection_method
            }
            issues_data.append(issue_data)
        
        data = {
            'original_text': result.original_text,
            'processed_text': result.processed_text,
            'validation_issues': issues_data,
            'quality_metrics': asdict(result.quality_metrics),
            'secondary_detection_results': result.secondary_detection_results,
            'schema_validation_results': result.schema_validation_results,
            'adversarial_check_results': result.adversarial_check_results,
            'recommendations': result.recommendations,
            'timestamp': result.timestamp
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Validation results saved to {filepath}")

# Example usage and testing
if __name__ == "__main__":
    logger.info("Stage 7: Validation & Post-Check module loaded")
