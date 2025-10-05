#!/usr/bin/env python3
"""
PII Incident Redaction Pipeline
Main entry point for the PII redaction system
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from src.processing_pipeline import PIIProcessingPipeline
from config.llm_config import LLMConfigManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PIIRedactionPipeline:
    """Main PII redaction pipeline orchestrator"""
    
    def __init__(self, policy_path: Optional[str] = None, use_real_api: bool = False):
        """Initialize the pipeline with optional custom policy"""
        
        # Initialize the processing pipeline
        self.processing_pipeline = PIIProcessingPipeline(policy_path, use_real_api)
        
        logger.info("PII Redaction Pipeline initialized")
    
    async def process_text(self, text: str, output_dir: Optional[str] = None) -> dict:
        """Process text through the complete pipeline"""
        
        logger.info("Starting PII redaction pipeline")
        
        # Use the processing pipeline
        result = await self.processing_pipeline.process_text(text, output_dir)
        
        # Convert ProcessingResult to dict for backward compatibility
        results = {
            'original_text': result.original_text,
            'processed_text': result.processed_text,
            'quality_metrics': result.quality_metrics,
            'validation_issues': result.validation_issues,
            'critical_issues': result.critical_issues,
            'high_issues': result.high_issues,
            'recommendations': result.recommendations,
            'pseudonym_map': result.pseudonym_map,
            'processing_stats': result.processing_stats
        }
        
        logger.info("PII redaction pipeline completed")
        return results

def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(
        description="PII Incident Redaction Pipeline - Automatically detect and redact PII from incident reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process text from command line
  python main.py --text "Incident report with john.doe@example.com and +1-555-123-4567"
  
  # Process text file
  python main.py --file incident_report.txt --output results/
  
  # Use custom policy
  python main.py --file incident.txt --policy custom_policy.json
  
  # Enable real LLM APIs (requires API keys)
  python main.py --file incident.txt --real-api
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--text', help='Text to process directly')
    input_group.add_argument('--file', help='File containing text to process')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output directory for results')
    parser.add_argument('--policy', help='Custom policy JSON file')
    
    # Configuration options
    parser.add_argument('--real-api', action='store_true', 
                       help='Use real LLM APIs (requires API keys)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get input text
    if args.text:
        text = args.text
    else:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            sys.exit(1)
    
    # Initialize pipeline
    try:
        pipeline = PIIRedactionPipeline(
            policy_path=args.policy,
            use_real_api=args.real_api
        )
    except Exception as e:
        logger.error(f"Failed to initialize pipeline: {e}")
        sys.exit(1)
    
    # Process text
    try:
        import asyncio
        results = asyncio.run(pipeline.process_text(text, args.output))
        
        # Print summary
        print("\n" + "="*60)
        print("PII REDACTION PIPELINE RESULTS")
        print("="*60)
        print(f"Original text length: {len(text):,} characters")
        print(f"Processed text length: {len(results['processed_text']):,} characters")
        print(f"Text reduction: {results['processing_stats']['text_reduction_percentage']:.1f}%")
        print(f"Overall quality score: {results['quality_metrics']['overall_quality_score']:.3f}")
        print(f"Validation issues: {results['validation_issues']}")
        print(f"Critical issues: {results['critical_issues']}")
        print(f"High priority issues: {results['high_issues']}")
        
        if results['recommendations']:
            print("\nRecommendations:")
            for i, rec in enumerate(results['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        print("\n" + "="*60)
        
    except Exception as e:
        logger.error(f"Pipeline processing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
