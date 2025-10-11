#!/usr/bin/env python3
"""
Universal Incident Processing Script
Automatically processes incident data from any platform using incident IDs from JSON files
"""

import json
import asyncio
import sys
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Union, Optional
import logging

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent))

from main import PIIRedactionPipeline
from src.parallel_processing_pipeline import ParallelPIIProcessingPipeline, ProcessingConfig

def load_incident_data(file_path: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Load incident data from JSON or JSONL file"""
    
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if file_path.suffix == '.jsonl':
        # Load JSONL file (one JSON object per line)
        incidents = []
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    incidents.append(json.loads(line.strip()))
        return incidents
    elif file_path.suffix == '.json':
        # Load JSON file (single object or array)
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            return data
        else:
            return [data]  # Single incident, wrap in list
    else:
        raise ValueError(f"Unsupported file format: {file_path.suffix}")

def extract_incident_id(incident: Dict[str, Any]) -> str:
    """Extract incident ID from incident data"""
    
    # Try common ID field names
    id_fields = ['id', 'incident_id', 'incidentId', 'incident-id', 'ticket_id', 'ticketId']
    
    for field in id_fields:
        if field in incident:
            return str(incident[field])
    
    # If no ID field found, generate one from title or use timestamp
    if 'title' in incident:
        # Create ID from title (first 20 chars, alphanumeric only)
        title_id = ''.join(c for c in incident['title'][:20] if c.isalnum())
        return f"incident_{title_id}"
    
    # Fallback to timestamp
    return f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

def extract_text_from_incident(incident: Dict[str, Any]) -> str:
    """Extract all text content from incident for processing"""
    text_parts = []
    
    # Add title
    if 'title' in incident:
        text_parts.append(f"Title: {incident['title']}")
    
    # Add summary
    if 'summary' in incident:
        text_parts.append(f"Summary: {incident['summary']}")
    
    # Add description
    if 'description' in incident:
        text_parts.append(f"Description: {incident['description']}")
    
    # Add participants info
    if 'participants' in incident:
        text_parts.append("Participants:")
        for participant in incident['participants']:
            if isinstance(participant, dict):
                if 'name' in participant and 'email' in participant:
                    text_parts.append(f"- {participant['name']} ({participant['email']})")
                elif 'email' in participant:
                    text_parts.append(f"- {participant['email']}")
    
    # Add timeline events
    timeline_fields = ['timelineEvents', 'timeline_events', 'events', 'updates']
    for field in timeline_fields:
        if field in incident:
            text_parts.append("Timeline Events:")
            for event in incident[field]:
                if isinstance(event, dict):
                    if 'content' in event:
                        text_parts.append(f"- {event['content']}")
                    if 'user' in event and isinstance(event['user'], dict) and 'email' in event['user']:
                        text_parts.append(f"  User: {event['user']['email']}")
            break
    
    # Add comments if available
    if 'comments' in incident:
        text_parts.append("Comments:")
        for comment in incident['comments']:
            if isinstance(comment, dict) and 'content' in comment:
                text_parts.append(f"- {comment['content']}")
    
    return "\n".join(text_parts)

def generate_detailed_report(results: Dict[str, Any], incident_id: str, output_dir: Path):
    """Generate detailed redaction report"""
    
    report = {
        "incident_id": incident_id,
        "processing_timestamp": datetime.now().isoformat(),
        "summary": {
            "original_text_length": len(results['original_text']),
            "processed_text_length": len(results['processed_text']),
            "text_reduction_percentage": results['processing_stats']['text_reduction_percentage'],
            "total_decisions": len(results.get('arbitration_decisions', [])),
            "quality_score": results['quality_metrics']['overall_quality_score']
        },
        "quality_metrics": results['quality_metrics'],
        "processing_stats": results['processing_stats'],
        "text_comparison": {
            "original": results['original_text'],
            "processed": results['processed_text']
        },
        "pseudonym_mapping": results['pseudonym_map'],
        "recommendations": results['recommendations']
    }
    
    # Save detailed report
    report_file = output_dir / f"incident_{incident_id}_detailed_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_file

def print_processing_summary(results: Dict[str, Any], incident_id: str):
    """Print a summary of processing results"""
    
    print(f"\n{'='*80}")
    print(f"INCIDENT: {incident_id}")
    print(f"{'='*80}")
    
    # Quality metrics
    metrics = results['quality_metrics']
    print(f"\n📊 QUALITY METRICS:")
    print(f"  Overall Quality Score: {metrics['overall_quality_score']:.3f}")
    print(f"  Precision: {metrics['precision']:.3f}")
    print(f"  Recall: {metrics['recall']:.3f}")
    print(f"  F1 Score: {metrics['f1_score']:.3f}")
    print(f"  Validation Issues: {results['validation_issues']}")
    print(f"  Critical Issues: {results['critical_issues']}")
    print(f"  High Issues: {results['high_issues']}")
    
    # Text processing stats
    stats = results['processing_stats']
    print(f"\n📏 TEXT PROCESSING:")
    print(f"  Original Length: {len(results['original_text'])} characters")
    print(f"  Processed Length: {len(results['processed_text'])} characters")
    print(f"  Text Reduction: {stats['text_reduction_percentage']:.1f}%")
    print(f"  Deterministic Entities: {stats['deterministic_entities']}")
    print(f"  LLM Detections: {stats['llm_detections']}")
    print(f"  LLM Verifications: {stats['llm_verifications']}")
    print(f"  Arbitration Decisions: {stats['arbitration_decisions']}")
    
    # Pseudonym mapping
    if results['pseudonym_map']:
        print(f"\n🔄 PSEUDONYMIZATION:")
        for original, pseudonym in results['pseudonym_map'].items():
            print(f"  {original} → {pseudonym}")
    
    # Recommendations
    if results['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(results['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    # Text comparison (first 500 chars)
    print(f"\n📝 TEXT COMPARISON (First 500 characters):")
    print(f"\nORIGINAL:")
    print(f"  {results['original_text'][:500]}...")
    print(f"\nPROCESSED:")
    print(f"  {results['processed_text'][:500]}...")

async def process_incidents(file_path: str, output_dir: Optional[str] = None, llm_simulation: bool = False, 
                           policy_path: Optional[str] = None, max_concurrent: int = 5, enable_parallel: bool = True):
    """Process incidents from any platform using automatic incident ID detection"""
    
    # Load incidents
    try:
        incidents = load_incident_data(file_path)
        print(f"📁 Loaded {len(incidents)} incident(s) from {file_path}")
    except Exception as e:
        print(f"❌ Error loading incidents: {e}")
        return
    
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = Path(file_path).stem
    output_dir = Path(output_dir) if output_dir else Path(f"output/{base_name}_processing_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize pipeline
    print("🚀 Initializing PII Redaction Pipeline...")
    if llm_simulation:
        print("💡 LLM simulation mode enabled - no API calls will be made")
    
    if enable_parallel:
        print(f"⚡ Parallel processing enabled with max {max_concurrent} concurrent incidents")
        # Configure parallel processing
        config = ProcessingConfig(
            max_concurrent_incidents=max_concurrent,
            max_concurrent_llm_calls=10,
            enable_deterministic_parallel=True,
            enable_validation_parallel=True
        )
        pipeline = ParallelPIIProcessingPipeline(
            policy_path=policy_path, 
            use_real_api=not llm_simulation,
            config=config
        )
        
        # Process incidents in parallel
        print(f"🔄 Processing {len(incidents)} incidents in parallel...")
        start_time = time.time()
        
        results = await pipeline.process_multiple_incidents(incidents, str(output_dir))
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"⚡ Parallel processing completed in {processing_time:.2f} seconds")
        print(f"📊 Average time per incident: {processing_time/len(incidents):.2f} seconds")
        
        # Generate reports for each result
        all_results = []
        for i, result in enumerate(results):
            incident_id = f"incident_{i+1}"  # Simplified ID for parallel processing
            report_file = generate_detailed_report({
                'original_text': result.original_text,
                'processed_text': result.processed_text,
                'quality_metrics': result.quality_metrics,
                'validation_issues': result.validation_issues,
                'critical_issues': result.critical_issues,
                'high_issues': result.high_issues,
                'recommendations': result.recommendations,
                'pseudonym_map': result.pseudonym_map,
                'processing_stats': result.processing_stats
            }, incident_id, output_dir)
            
            all_results.append({
                'incident_id': incident_id,
                'incident_index': i + 1,
                'results': {
                    'original_text': result.original_text,
                    'processed_text': result.processed_text,
                    'quality_metrics': result.quality_metrics,
                    'validation_issues': result.validation_issues,
                    'critical_issues': result.critical_issues,
                    'high_issues': result.high_issues,
                    'recommendations': result.recommendations,
                    'pseudonym_map': result.pseudonym_map,
                    'processing_stats': result.processing_stats
                },
                'report_file': str(report_file)
            })
        
    else:
        # Use original sequential processing
        pipeline = PIIRedactionPipeline(policy_path=policy_path, use_real_api=not llm_simulation)
        
        # Process each incident sequentially
        all_results = []
        
        for i, incident in enumerate(incidents, 1):
            # Extract incident ID automatically
            incident_id = extract_incident_id(incident)
            print(f"\n🔄 Processing Incident {i}/{len(incidents)}: {incident_id}")
            
            # Extract text for processing
            text_to_process = extract_text_from_incident(incident)
            
            # Process through pipeline
            try:
                # Create incident-specific directory within the main output directory
                incident_output_dir = output_dir / f"incident_{incident_id}"
                results = await pipeline.process_text(text_to_process, str(incident_output_dir))
                
                # Generate detailed report
                report_file = generate_detailed_report(results, incident_id, output_dir)
                
                # Print summary
                print_processing_summary(results, incident_id)
                
                # Store results
                all_results.append({
                    'incident_id': incident_id,
                    'incident_index': i,
                    'results': results,
                    'report_file': str(report_file)
                })
                
            except Exception as e:
                print(f"❌ Error processing {incident_id}: {e}")
                continue
    
    # Generate overall summary
    if all_results:
        generate_overall_summary(all_results, output_dir, file_path)
        print(f"\n✅ Processing complete! Reports saved to: {output_dir}")
        print(f"📊 Processed {len(all_results)} incidents successfully")

def generate_overall_summary(all_results: List[Dict], output_dir: Path, source_file: str):
    """Generate overall summary report"""
    
    summary = {
        "processing_timestamp": datetime.now().isoformat(),
        "source_file": str(source_file),
        "total_incidents": len(all_results),
        "successful_incidents": len(all_results),
        "overall_statistics": {
            "average_quality_score": sum(r['results']['quality_metrics']['overall_quality_score'] for r in all_results) / len(all_results),
            "average_text_reduction": sum(r['results']['processing_stats']['text_reduction_percentage'] for r in all_results) / len(all_results),
            "total_pseudonyms_generated": sum(len(r['results']['pseudonym_map']) for r in all_results),
            "total_validation_issues": sum(r['results']['validation_issues'] for r in all_results),
            "total_critical_issues": sum(r['results']['critical_issues'] for r in all_results)
        },
        "incident_summaries": []
    }
    
    for result in all_results:
        incident_summary = {
            "incident_id": result['incident_id'],
            "quality_score": result['results']['quality_metrics']['overall_quality_score'],
            "text_reduction_percentage": result['results']['processing_stats']['text_reduction_percentage'],
            "pseudonyms_count": len(result['results']['pseudonym_map']),
            "validation_issues": result['results']['validation_issues'],
            "critical_issues": result['results']['critical_issues'],
            "report_file": result['report_file']
        }
        summary["incident_summaries"].append(incident_summary)
    
    # Save overall summary
    summary_file = output_dir / "overall_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Print overall summary
    print(f"\n{'='*80}")
    print(f"OVERALL PROCESSING SUMMARY")
    print(f"{'='*80}")
    print(f"📁 Source File: {Path(source_file).name}")
    print(f"📊 Total Incidents Processed: {summary['total_incidents']}")
    print(f"📈 Average Quality Score: {summary['overall_statistics']['average_quality_score']:.3f}")
    print(f"📉 Average Text Reduction: {summary['overall_statistics']['average_text_reduction']:.1f}%")
    print(f"🔄 Total Pseudonyms Generated: {summary['overall_statistics']['total_pseudonyms_generated']}")
    print(f"⚠️  Total Validation Issues: {summary['overall_statistics']['total_validation_issues']}")
    print(f"🚨 Total Critical Issues: {summary['overall_statistics']['total_critical_issues']}")
    print(f"\n📁 Detailed reports saved to: {output_dir}")

def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(
        description="Process incident data through PII redaction pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python process_incidents.py data/test_samples/rootly_samples.jsonl
  python process_incidents.py data/test_samples/_samples.jsonl --llm-simulation
  python process_incidents.py data/test_samples/_samples.jsonl --output-dir output/custom_results
  python process_incidents.py incidents.json --llm-simulation --log-level DEBUG

Supported formats:
  - JSON files (.json) - single incident or array of incidents
  - JSONL files (.jsonl) - one incident per line

Automatic incident ID detection:
  - Uses 'id', 'incident_id', 'incidentId', 'incident-id', 'ticket_id', 'ticketId' fields
  - Falls back to title-based ID or timestamp if no ID field found
        """
    )
    
    parser.add_argument("file_path", help="Path to incident data file (JSON or JSONL)")
    parser.add_argument("--output-dir", "-o", help="Output directory for results (default: auto-generated)")
    parser.add_argument("--llm-simulation", "-s", action="store_true", 
                       help="Run LLM stages in simulation mode (no API calls)")
    parser.add_argument("--policy", "-p", help="Path to custom PII policy JSON file")
    parser.add_argument("--log-level", "-l", default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Set logging level")
    parser.add_argument("--max-concurrent", "-c", type=int, default=5,
                       help="Maximum number of concurrent incidents to process (default: 5)")
    parser.add_argument("--disable-parallel", action="store_true",
                       help="Disable parallel processing and use sequential mode")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(process_incidents(
        args.file_path, 
        args.output_dir, 
        args.llm_simulation, 
        args.policy,
        args.max_concurrent,
        not args.disable_parallel
    ))

if __name__ == "__main__":
    main()
