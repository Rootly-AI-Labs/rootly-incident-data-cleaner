#!/usr/bin/env python3
"""
PII Incident Redaction Pipeline
Main entry point for processing Rootly incident data from JSONL files
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
import asyncio
from datetime import datetime

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
    """Main PII redaction pipeline orchestrator for Rootly incident data"""
    
    def __init__(self, policy_path: Optional[str] = None, use_real_api: bool = False):
        """Initialize the pipeline with optional custom policy"""
        
        # Initialize the processing pipeline
        self.processing_pipeline = PIIProcessingPipeline(policy_path, use_real_api)
        
        logger.info("PII Redaction Pipeline initialized")
    
    async def process_jsonl_file(self, input_file: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Process a JSONL file containing Rootly incident data"""
        
        logger.info(f"Starting PII redaction pipeline for {input_file}")
        
        # Create output directory with timestamp
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/rootly_processing_{timestamp}"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Process each incident in the JSONL file
        results = []
        incident_count = 0
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        incident_data = json.loads(line)
                        incident_count += 1
                        
                        # Extract text content from Rootly incident format
                        text_content = self._extract_text_from_incident(incident_data)
                        
                        # Process the text
                        result = await self.processing_pipeline.process_text(text_content, str(output_path))
                        
                        # Save individual incident report
                        incident_id = incident_data.get('id', f'incident_{incident_count}')
                        report_file = output_path / f"incident_{incident_id}_detailed_report.json"
                        
                        report_data = {
                            "incident_id": incident_id,
                            "processing_timestamp": datetime.now().isoformat(),
                            "summary": {
                                "original_text_length": len(text_content),
                                "processed_text_length": len(result.processed_text),
                                "text_reduction_percentage": result.processing_stats.get('text_reduction_percentage', 0),
                                "total_decisions": result.processing_stats.get('arbitration_decisions', 0),
                                "quality_score": result.quality_metrics.get('overall_quality_score', 0)
                            },
                            "quality_metrics": result.quality_metrics,
                            "processing_stats": result.processing_stats,
                            "text_comparison": {
                                "original": text_content,
                                "processed": result.processed_text
                            },
                            "pseudonym_mapping": result.pseudonym_map,
                            "recommendations": result.recommendations
                        }
                        
                        with open(report_file, 'w', encoding='utf-8') as report_f:
                            json.dump(report_data, report_f, indent=2, ensure_ascii=False)
                        
                        results.append({
                            'incident_id': incident_id,
                            'quality_score': result.quality_metrics.get('overall_quality_score', 0),
                            'text_reduction': result.processing_stats.get('text_reduction_percentage', 0),
                            'issues': (len(result.validation_issues) if isinstance(result.validation_issues, list) else 0) + 
                                     (len(result.critical_issues) if isinstance(result.critical_issues, list) else 0) + 
                                     (len(result.high_issues) if isinstance(result.high_issues, list) else 0)
                        })
                        
                        logger.info(f"Processed incident {incident_count}: {incident_id}")
                        
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON on line {line_num}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")
                        continue
            
            # Generate overall summary
            summary_file = output_path / "overall_summary.json"
            summary_data = {
                "processing_timestamp": datetime.now().isoformat(),
                "input_file": input_file,
                "total_incidents_processed": incident_count,
                "average_quality_score": sum(r['quality_score'] for r in results) / len(results) if results else 0,
                "average_text_reduction": sum(r['text_reduction'] for r in results) / len(results) if results else 0,
                "total_issues": sum(r['issues'] for r in results),
                "incident_summaries": results
            }
            
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"PII redaction pipeline completed. Processed {incident_count} incidents.")
            return summary_data
            
        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            raise
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            raise
    
    def _extract_text_from_incident(self, incident_data: Dict[str, Any]) -> str:
        """Extract text content from Rootly incident data format"""
        
        text_parts = []
        
        # Add title
        if 'title' in incident_data and incident_data['title']:
            text_parts.append(f"Title: {str(incident_data['title'])}")
        
        # Add summary
        if 'summary' in incident_data and incident_data['summary']:
            text_parts.append(f"Summary: {str(incident_data['summary'])}")
        
        # Add description
        if 'description' in incident_data and incident_data['description']:
            text_parts.append(f"Description: {str(incident_data['description'])}")
        
        # Add participants
        if 'participants' in incident_data and isinstance(incident_data['participants'], list):
            participants_text = "Participants:\n"
            for participant in incident_data['participants']:
                if isinstance(participant, dict):
                    name = participant.get('name', 'Unknown')
                    email = participant.get('email', '')
                    role = participant.get('role', '')
                    participants_text += f"- {str(name)} ({str(email)}) - {str(role)}\n"
            text_parts.append(participants_text.strip())
        
        return "\n".join(text_parts)

def main():
    """Main CLI entry point for processing Rootly incident data"""
    
    parser = argparse.ArgumentParser(
        description="PII Incident Redaction Pipeline - Process Rootly incident data from JSONL files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process Rootly incident data
  python main.py --input data/test_samples/rootly_samples.jsonl
  
  # Process with custom output directory
  python main.py --input data/test_samples/rootly_samples.jsonl --output results/
  
  # Use custom policy
  python main.py --input data/test_samples/rootly_samples.jsonl --policy custom_policy.json
  
  # Enable real LLM APIs (requires API keys)
  python main.py --input data/test_samples/rootly_samples.jsonl --real-api
        """
    )
    
    # Input file (required)
    parser.add_argument('--input', '-i', required=True, 
                       help='JSONL file containing Rootly incident data')
    
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
    
    # Validate input file
    if not Path(args.input).exists():
        logger.error(f"Input file not found: {args.input}")
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
    
    # Process JSONL file
    try:
        results = asyncio.run(pipeline.process_jsonl_file(args.input, args.output))
        
        # Print summary
        print("\n" + "="*60)
        print("PII REDACTION PIPELINE RESULTS")
        print("="*60)
        print(f"Input file: {args.input}")
        print(f"Total incidents processed: {results['total_incidents_processed']}")
        print(f"Average quality score: {results['average_quality_score']:.3f}")
        print(f"Average text reduction: {results['average_text_reduction']:.1f}%")
        print(f"Total issues found: {results['total_issues']}")
        print(f"Output directory: {results.get('output_directory', 'Generated automatically')}")
        
        print("\n" + "="*60)
        
    except Exception as e:
        logger.error(f"Pipeline processing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
