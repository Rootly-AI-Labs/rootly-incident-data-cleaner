"""
Stage 2: Policy Definition
Purpose: Define what qualifies as PII or sensitive operational data.
"""
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

class DataCategory(Enum):
    """Categories of sensitive data"""
    PII = "PII"
    OPERATIONAL_IDENTIFIERS = "OPERATIONAL_IDENTIFIERS"
    SECRETS = "SECRETS"
    CUSTOMER_ORG_INFO = "CUSTOMER_ORG_INFO"
    MISCELLANEOUS = "MISCELLANEOUS"

class RedactionAction(Enum):
    """Actions to take when PII is detected"""
    REDACT = "REDACT"  # Replace with [REDACTED]
    PSEUDONYMIZE = "PSEUDONYMIZE"  # Replace with deterministic fake value
    RETAIN = "RETAIN"  # Keep original

class SensitivityLevel(Enum):
    """Data sensitivity levels"""
    CRITICAL = "CRITICAL"      # Always redact
    HIGH = "HIGH"              # Typically redact or pseudonymize
    MEDIUM = "MEDIUM"          # Usually pseudonymize
    LOW = "LOW"               # Usually retain or pseudonymize
    MINIMUM = "MINIMUM"        # Usually retain

@dataclass
class DataPattern:
    """Pattern definition for detecting sensitive data"""
    name: str
    category: DataCategory
    regex_pattern: Optional[str] = None
    keywords: Optional[List[str]] = None
    presidio_entities: Optional[List[str]] = None
    description: str = ""
    
@dataclass
class PolicyRule:
    """Rule defining how to handle specific data categories"""
    category: DataCategory
    sensitivity_level: SensitivityLevel
    action: RedactionAction
    patterns: List[DataPattern]
    conditions: Optional[Dict[str, Any]] = None
    exceptions: Optional[List[str]] = None

class PIIPolicy:
    """Policy definition for PII detection and redaction"""
    
    def __init__(self, policy_config_file: Optional[str] = None):
        self.policies: List[PolicyRule] = []
        self.patterns: Dict[str, DataPattern] = {}
        self.load_default_policies()
        
        if policy_config_file:
            self.load_from_file(policy_config_file)
    
    @classmethod
    def from_json(cls, file_path: str):
        """Load PIIPolicy from JSON configuration file"""
        policy = cls()
        policy.load_from_file(file_path)
        return policy
    
    def load_default_policies(self):
        """Load default PII policies based on the proposal"""
        
        # Define data patterns
        self.patterns = {
            # PII Patterns
            "email": DataPattern(
                name="email",
                category=DataCategory.PII,
                presidio_entities=["EMAIL_ADDRESS"],
                description="Email addresses"
            ),
            "phone": DataPattern(
                name="phone", 
                category=DataCategory.PII,
                presidio_entities=["PHONE_NUMBER"],
                description="Phone numbers"
            ),
            "person_name": DataPattern(
                name="person_name",
                category=DataCategory.PII,
                presidio_entities=["PERSON"],
                description="Person names"
            ),
            "credit_card": DataPattern(
                name="credit_card",
                category=DataCategory.PII,
                presidio_entities=["CREDIT_CARD"],
                description="Credit card numbers"
            ),
            "ssn": DataPattern(
                name="ssn",
                category=DataCategory.PII,
                presidio_entities=["US_SSN"],
                description="Social Security Numbers"
            ),
            "address": DataPattern(
                name="address",
                category=DataCategory.PII,
                presidio_entities=["LOCATION"],
                description="Physical addresses"
            ),
            
            # Operational Identifiers
            "hostname": DataPattern(
                name="hostname",
                category=DataCategory.OPERATIONAL_IDENTIFIERS,
                regex_pattern=r"\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b",
                keywords=["host", "server", "node", "db-server", "web-server"],
                description="Server hostnames"
            ),
            "ip_address": DataPattern(
                name="ip_address",
                category=DataCategory.OPERATIONAL_IDENTIFIERS,
                presidio_entities=["IP_ADDRESS"],
                description="IP addresses"
            ),
            "api_key": DataPattern(
                name="api_key",
                category=DataCategory.SECRETS,
                regex_pattern=r"\b[A-Za-z0-9]{20,}\b",
                keywords=["api_key", "API-KEY", "Secret", "token"],
                description="API keys and secrets"
            ),
            "database_url": DataPattern(
                name="database_url",
                category=DataCategory.SECRETS,
                regex_pattern=r"((?:[a-zA-Z0-9]+://)?(?:[a-zA-Z0-9]+[.-])+[a-zA-Z0-9]+(?:/[a-zA-Z0-9_./-]*)?)",
                keywords=["postgres://", "mysql://", "mongodb://", "redis://"],
                description="Database connection URLs"
            ),
            
            # Customer/Organization Info
            "company_name": DataPattern(
                name="company_name",
                category=DataCategory.CUSTOMER_ORG_INFO,
                keywords=["Inc.", "Corp.", "LLC", "Ltd.", "Company"],
                description="Company names"
            ),
            "customer_id": DataPattern(
                name="customer_id",
                category=DataCategory.CUSTOMER_ORG_INFO,
                regex_pattern=r"\bcust_\d+\b|\bcustomer_\d+\b",
                description="Customer identifiers"
            ),
            
            # Miscellaneous
            "internal_path": DataPattern(
                name="internal_path",
                category=DataCategory.MISCELLANEOUS,
                regex_pattern=r"/[a-zA-Z0-9_./-]+",
                keywords=["/internal/", "/private/", "/admin/"],
                description="Internal file/system paths"
            )
        }
        
        # Define policy rules
        self.policies = [
            # CRITICAL - Always redact
            PolicyRule(
                category=DataCategory.SECRETS,
                sensitivity_level=SensitivityLevel.CRITICAL,
                action=RedactionAction.REDACT,
                patterns=[self.patterns["api_key"], self.patterns["database_url"]]
            ),
            PolicyRule(
                category=DataCategory.PII,
                sensitivity_level=SensitivityLevel.CRITICAL,
                action=RedactionAction.REDACT,
                patterns=[self.patterns["ssn"], self.patterns["credit_card"]]
            ),
            
            # HIGH - Redact or pseudonymize
            PolicyRule(
                category=DataCategory.PII,
                sensitivity_level=SensitivityLevel.HIGH,
                action=RedactionAction.REDACT,
                patterns=[self.patterns["email"]],
                exceptions=["support@company.com", "admin@company.com"]
            ),
            PolicyRule(
                category=DataCategory.PII,
                sensitivity_level=SensitivityLevel.HIGH,
                action=RedactionAction.PSEUDONYMIZE,
                patterns=[self.patterns["phone"]]
            ),
            
            # MEDIUM - Pseudonymize
            PolicyRule(
                category=DataCategory.PII,
                sensitivity_level=SensitivityLevel.MEDIUM,
                action=RedactionAction.PSEUDONYMIZE,
                patterns=[self.patterns["person_name"]]
            ),
            PolicyRule(
                category=DataCategory.OPERATIONAL_IDENTIFIERS,
                sensitivity_level=SensitivityLevel.MEDIUM,
                action=RedactionAction.PSEUDONYMIZE,
                patterns=[self.patterns["hostname"], self.patterns["ip_address"]]
            ),
            
            # LOW - Retain or pseudonymize
            PolicyRule(
                category=DataCategory.CUSTOMER_ORG_INFO,
                sensitivity_level=SensitivityLevel.LOW,
                action=RedactionAction.PSEUDONYMIZE,
                patterns=[self.patterns["company_name"], self.patterns["customer_id"]]
            ),
            PolicyRule(
                category=DataCategory.PII,
                sensitivity_level=SensitivityLevel.LOW,
                action=RedactionAction.RETAIN,
                patterns=[self.patterns["address"]]
            ),
            
            # MINIMUM - Usually retain
            PolicyRule(
                category=DataCategory.MISCELLANEOUS,
                sensitivity_level=SensitivityLevel.MINIMUM,
                action=RedactionAction.RETAIN,
                patterns=[self.patterns["internal_path"]]
            )
        ]
    
    def get_action_for_pattern(self, pattern_name: str, context: Optional[str] = None) -> RedactionAction:
        """Get the redaction action for a specific pattern"""
        pattern = self.patterns.get(pattern_name)
        if not pattern:
            return RedactionAction.RETAIN
        
        for policy in self.policies:
            if pattern in policy.patterns:
                # Check exceptions
                if policy.exceptions and context:
                    for exception in policy.exceptions:
                        if exception in context.lower():
                            return RedactionAction.RETAIN
                return policy.action
        
        return RedactionAction.RETAIN
    
    def get_category_for_pattern(self, pattern_name: str) -> DataCategory:
        """Get the category for a specific pattern"""
        pattern = self.patterns.get(pattern_name)
        return pattern.category if pattern else DataCategory.MISCELLANEOUS
    
    def get_patterns_by_category(self, category: DataCategory) -> List[DataPattern]:
        """Get all patterns for a specific category"""
        return [pattern for pattern in self.patterns.values() if pattern.category == category]
    
    def get_patterns_by_action(self, action: RedactionAction) -> List[str]:
        """Get all pattern names that use a specific action"""
        pattern_names = []
        for policy in self.policies:
            if policy.action == action:
                pattern_names.extend([pattern.name for pattern in policy.patterns])
        return pattern_names
    
    def validate_policy(self) -> Dict[str, Any]:
        """Validate the current policy configuration"""
        validation_results = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "summary": {
                "total_patterns": len(self.patterns),
                "total_policies": len(self.policies),
                "categories": len(DataCategory),
                "actions": len(RedactionAction)
            }
        }
        
        # Check for duplicate patterns
        pattern_names = [pattern.name for pattern in self.patterns.values()]
        if len(pattern_names) != len(set(pattern_names)):
            validation_results["errors"].append("Duplicate pattern names found")
            validation_results["valid"] = False
        
        # Check for patterns without policies
        uncovered_patterns = []
        for pattern_name in self.patterns.keys():
            found = False
            for policy in self.policies:
                if pattern_name in [p.name for p in policy.patterns]:
                    found = True
                    break
            if not found:
                uncovered_patterns.append(pattern_name)
        
        if uncovered_patterns:
            validation_results["warnings"].append(f"Patterns without policies: {uncovered_patterns}")
        
        return validation_results
    
    def load_from_file(self, file_path: str):
        """Load policies from JSON configuration file"""
        try:
            with open(file_path, 'r') as f:
                config = json.load(f)
            
            # Load patterns
            if 'patterns' in config:
                for pattern_def in config['patterns']:
                    # Convert string category to enum
                    if 'category' in pattern_def:
                        pattern_def['category'] = DataCategory(pattern_def['category'])
                    pattern = DataPattern(**pattern_def)
                    self.patterns[pattern_def['name']] = pattern
            
            # Load policies
            if 'policies' in config:
                self.policies = []
                for policy_def in config['policies']:
                    patterns = [self.patterns[name] for name in policy_def.get('patterns', []) if name in self.patterns]
                    policy = PolicyRule(
                        category=DataCategory(policy_def['category']),
                        sensitivity_level=SensitivityLevel(policy_def['sensitivity_level']),
                        action=RedactionAction(policy_def['action']),
                        patterns=patterns,
                        conditions=policy_def.get('conditions'),
                        exceptions=policy_def.get('exceptions')
                    )
                    self.policies.append(policy)
            
            logger.info(f"Loaded policy configuration from {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to load policy configuration: {e}")
    
    def save_to_file(self, file_path: str):
        """Save policies to JSON configuration file"""
        config = {
            "patterns": [
                {
                    "name": pattern.name,
                    "category": pattern.category.value,
                    "regex_pattern": pattern.regex_pattern,
                    "keywords": pattern.keywords,
                    "presidio_entities": pattern.presidio_entities,
                    "description": pattern.description
                }
                for pattern in self.patterns.values()
            ],
            "policies": [
                {
                    "category": policy.category.value,
                    "sensitivity_level": policy.sensitivity_level.value,
                    "action": policy.action.value,
                    "patterns": [pattern.name for pattern in policy.patterns],
                    "conditions": policy.conditions,
                    "exceptions": policy.exceptions
                }
                for policy in self.policies
            ]
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Saved policy configuration to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save policy configuration: {e}")
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get a summary of the current policy configuration"""
        summary = {
            "patterns_by_category": {},
            "actions_by_category": {},
            "patterns_by_action": {}
        }
        
        # Patterns by category
        for category in DataCategory:
            summary["patterns_by_category"][category.value] = len(self.get_patterns_by_category(category))
        
        # Actions by category
        for category in DataCategory:
            actions = set()
            for policy in self.policies:
                category_patterns = self.get_patterns_by_category(category)
                for pattern in category_patterns:
                    if pattern in policy.patterns:
                        actions.add(policy.action.value)
            summary["actions_by_category"][category.value] = list(actions)
        
        # Patterns by action
        for action in RedactionAction:
            summary["patterns_by_action"][action.value] = self.get_patterns_by_action(action)
        
        return summary
