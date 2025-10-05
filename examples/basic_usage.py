#!/usr/bin/env python3
"""
Example usage of the PII Incident Redaction Pipeline
Demonstrates how to use the pipeline programmatically
"""

import asyncio
import json
from pathlib import Path
import sys

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from main import PIIRedactionPipeline

async def example_basic_usage():
    """Basic usage example"""
    
    print("🔍 PII Redaction Pipeline - Basic Usage Example")
    print("=" * 50)
    
    # Sample incident text with PII
    incident_text = """
    SECURITY INCIDENT REPORT
    ========================
    
    Incident ID: INC-2024-001
    Date: March 15, 2024
    Severity: HIGH
    
    Executive Summary:
    Our security team discovered unauthorized access to customer database 
    containing sensitive personal information. The breach occurred between 
    14:30-18:45 UTC on March 14, 2024.
    
    Investigation Team:
    • Lead Investigator: Dr. Sarah Johnson (sarah.johnson@security.company.com)
    • Database Specialist: Michael Chen (michael.chen@dba.company.com)
    • Legal Counsel: Jennifer Rodriguez (jennifer.rodriguez@legal.company.com)
    
    Affected Systems:
    • Primary Database: db-customer-prod-01.mysql.company.com
    • API Gateway: api-gateway-prod.company.com (IP: 10.0.1.45)
    
    Customer Data Exposed:
    • Email addresses: john.doe@customer.com, jane.smith@customer.com
    • Phone numbers: +1-555-123-4567, +1-555-987-6543
    • Social Security Numbers: 123-45-6789, 987-65-4321
    • Credit Card Numbers: 4532-1234-5678-9012, 5555-4444-3333-2222
    • Customer IDs: cust_12345, cust_67890
    
    Contact Information:
    • Incident Commander: mark.davis@incident.company.com
    • Legal Team: legal@company.com
    • Customer Support: +1-800-555-HELP
    """
    
    # Initialize pipeline
    pipeline = PIIRedactionPipeline(use_real_api=False)  # Use simulation for demo
    
    # Process the text
    results = await pipeline.process_text(incident_text, "example_output")
    
    # Display results
    print(f"\n📊 Processing Results:")
    print(f"  Original length: {len(incident_text):,} characters")
    print(f"  Processed length: {len(results['processed_text']):,} characters")
    print(f"  Text reduction: {results['processing_stats']['text_reduction_percentage']:.1f}%")
    print(f"  Quality score: {results['quality_metrics']['overall_quality_score']:.3f}")
    print(f"  Validation issues: {results['validation_issues']}")
    print(f"  Critical issues: {results['critical_issues']}")
    
    print(f"\n🔗 Pseudonym Mappings:")
    for original, pseudonym in list(results['pseudonym_map'].items())[:5]:
        print(f"  {original} → {pseudonym}")
    
    print(f"\n💡 Recommendations:")
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f"  {i}. {rec}")
    
    print(f"\n📝 Sample Processed Text:")
    print("-" * 30)
    print(results['processed_text'][:500] + "...")
    
    return results

async def example_custom_policy():
    """Example with custom policy"""
    
    print("\n🔧 PII Redaction Pipeline - Custom Policy Example")
    print("=" * 50)
    
    # Create a custom policy
    custom_policy = {
        "patterns": [
            {
                "name": "email",
                "category": "PII",
                "presidio_entities": ["EMAIL_ADDRESS"],
                "description": "Email addresses"
            },
            {
                "name": "phone",
                "category": "PII", 
                "presidio_entities": ["PHONE_NUMBER"],
                "description": "Phone numbers"
            }
        ],
        "policies": [
            {
                "category": "PII",
                "sensitivity_level": "HIGH",
                "action": "REDACT",
                "patterns": ["email", "phone"]
            }
        ]
    }
    
    # Save custom policy
    policy_path = "custom_policy.json"
    with open(policy_path, "w") as f:
        json.dump(custom_policy, f, indent=2)
    
    # Sample text
    text = "Contact us at support@company.com or call +1-555-123-4567"
    
    # Initialize with custom policy
    pipeline = PIIRedactionPipeline(policy_path=policy_path, use_real_api=False)
    
    # Process text
    results = await pipeline.process_text(text)
    
    print(f"Original: {text}")
    print(f"Processed: {results['processed_text']}")
    print(f"Quality score: {results['quality_metrics']['overall_quality_score']:.3f}")
    
    # Clean up
    Path(policy_path).unlink()

async def example_batch_processing():
    """Example of batch processing multiple documents"""
    
    print("\n📦 PII Redaction Pipeline - Batch Processing Example")
    print("=" * 50)
    
    # Sample documents
    documents = [
        {
            "id": "incident_001",
            "text": "Security breach affecting john.doe@example.com and +1-555-123-4567"
        },
        {
            "id": "incident_002", 
            "text": "Customer complaint from jane.smith@customer.com regarding service"
        },
        {
            "id": "incident_003",
            "text": "System maintenance completed by admin@company.com"
        }
    ]
    
    # Initialize pipeline
    pipeline = PIIRedactionPipeline(use_real_api=False)
    
    # Process each document
    results = []
    for doc in documents:
        print(f"Processing {doc['id']}...")
        result = await pipeline.process_text(doc['text'])
        results.append({
            'id': doc['id'],
            'original_text': doc['text'],
            'processed_text': result['processed_text'],
            'quality_score': result['quality_metrics']['overall_quality_score'],
            'issues': result['validation_issues']
        })
    
    # Summary
    print(f"\n📊 Batch Processing Summary:")
    print(f"  Documents processed: {len(results)}")
    avg_quality = sum(r['quality_score'] for r in results) / len(results)
    print(f"  Average quality score: {avg_quality:.3f}")
    total_issues = sum(r['issues'] for r in results)
    print(f"  Total validation issues: {total_issues}")
    
    return results

async def main():
    """Run all examples"""
    
    print("🚀 PII Incident Redaction Pipeline - Examples")
    print("=" * 60)
    
    try:
        # Run examples
        await example_basic_usage()
        await example_custom_policy()
        await example_batch_processing()
        
        print("\n✅ All examples completed successfully!")
        print("\n📁 Check the 'example_output' directory for detailed results")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
