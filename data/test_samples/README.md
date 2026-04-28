# Test Sample Data Files

This directory contains realistic sample incident data for all supported platforms. Each file contains 10-15 realistic incidents with various PII types embedded naturally in the incident narratives.

## Platform Samples Overview

| Platform | File | Sample Count | Key Features |
|----------|------|-------------|--------------|
| **Rootly** | `rootly_samples.jsonl` | 6 samples | REST + GraphQL schema, learned lessons |
| **PagerDuty** | `pagerduty_samples.jsonl` | 3 samples | Notes, log entries, alerts |
| **BigPanda** | `bigpanda_samples.jsonl` | 5 samples | Correlation events, alerts |

## PII Types Contained

These samples contain realistic PII across various categories:

### Personal Information
- **Names**: Mike Rodriguez, Sarah Johnson, David Kim, Emily Davis
- **Email Addresses**: john.smith@techcorp.com, sarah.chen@enterprise.net
- **Phone Numbers**: +1-555-1234, +1-555-7890
- **Addresses**: Customer locations, office addresses

### Business Information  
- **Customer Data**: Enterprise business contacts, client information
- **Internal Teams**: Employee details, department information
- **Vendor Contacts**: External partner communications

### Technical PII
- **IP Addresses**: 192.168.1.100, 10.0.0.1
- **SSN/IDs**: Customer account numbers, employee identifiers
- **Credentials**: API keys, certificate details (masked)

## Sample Data Quality

Each platform sample includes:

### Authentic Structure
- Real API endpoint field names
- Platform-specific data organization  
- Actual incident management workflows
- Proper JSON schema compliance

### Realistic Content
- Natural incident narratives with embedded PII
- Technical contexts (databases, APIs, infrastructure)
- Business impact scenarios
- Post-incident analysis patterns

### Diverse PII Patterns
- Embedded in free-text descriptions
- Structured data fields
- Nested objects and arrays
- Cross-platform consistency

## Usage Examples

### Testing Individual Platforms
```bash
# Inspect descriptions
cat data/test_samples/rootly_samples.jsonl | jq '.description' | head

# Check PII detection accuracy
python src/core/pii_detector.py --input data/test_samples/rootly_samples.jsonl
```

### Cross-Platform Comparison
```bash
# Count PII occurrences across platforms
find data/test_samples/ -name "*.jsonl" -exec echo "Platform:" {} \; -exec grep -c "gmail\|yahoo\|@.*\.com" {} \;
```

### Pipeline Testing
```bash
# Run full pipeline on sample data
python -m src.pipeline.main --input-dir data/test_samples --platform all
```

## Data Structure Examples

### Sample Incident Structure
```json
{
  "id": "inc_01j8x7b9k9n1q2w3e4r5t6y7u8i9o0p",
  "summary": "Database Connection Pool Exhausted",
  "description": "During resolution discovered that John Smith (john.smith@company.com) made recent changes...",
  "assignee": {
    "name": "Mike Rodriguez",
    "email": "mike.rodriguez@techcorp.com"
  },
  "timeline_events": [...]
}
```

## PII Detection Patterns

These samples contain various PII detection challenges:

### Obvious PII
- Clear email addresses: `john.smith@company.com`
- Explicit phone numbers: `+1-555-1234`
- Direct names in contexts: `During investigation by Sarah Johnson`

### Contextual PII  
- Names in quotes: `(john.smith@company.com)`
- Embedded in sentences: `Contacted DevOps team Lisa Chen (+1-555-2345)`
- Domain-specific references: `Enterprise CTO David Park`

### Edge Cases
- Partial matches: `john.smith@company` (missing `.com`)
- Formatted text: `Emergency escalation James Martinez`
- Cross-references: `Contact engineering@techcorp.com`

## Validation Strategy

### Manual Verification
1. **Count Expected PII**: Each file should contain 15-25 PII instances
2. **Verify Types**: Ensure mix of names, emails, phones, etc.
3. **Check Contexts**: PII should appear naturally in incident narratives  
4. **Platform Fidelity**: Structure should match real API responses

### Entity Extraction Testing
```bash
# Test entity extraction
python -c "
from src.core.pii_detector import PIIDetector
detector = PIIDetector()
with open('data/test_samples/rootly_samples.jsonl') as f:
    line = f.readline()
    results = detector.detect_pii(line)
    for r in results:
        print(f'{r.entity_type}: {r.text} (confidence: {r.score})')
"
```

## Notes & Disclaimers

- **Realistic but Fictional**: All content is realistic but uses fictional names and companies
- **Educational Purpose**: Designed for PII redaction pipeline testing and development
- **Platform Authenticity**: APIs and structures based on actual platform documentation
- **Data Privacy**: Contains realistic PII patterns for testing redaction accuracy
- **No Real Data**: No actual customer or company data included

## Future Enhancements

- Add more complex PII patterns (dates, addresses, financial data)
- Include multi-language PII detection scenarios
- Add platform-specific incident types (security, compliance)
- Create adversarial test cases for edge detection
