#!/usr/bin/env python3
"""
Database CLI Tool - MVP
Simple command-line interface for managing incidents in the database
"""

import argparse
import json
import sys
from pathlib import Path
import asyncio
from typing import Optional

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from src.database import IncidentDatabase
from src.processing_pipeline import PIIProcessingPipeline

def load_incidents_from_jsonl(file_path: str) -> list:
    """Load incidents from JSONL file"""
    incidents = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                incident_data = json.loads(line)
                incidents.append(incident_data)
            except json.JSONDecodeError as e:
                print(f"Error parsing line {line_num}: {e}")
                continue
    
    return incidents

def extract_text_from_incident(incident_data: dict) -> str:
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

async def process_incident(incident_data: dict, processing_pipeline: PIIProcessingPipeline) -> dict:
    """Process a single incident through the PII redaction pipeline"""
    # Extract text content
    text_content = extract_text_from_incident(incident_data)
    
    # Process the text (using a temporary directory for output)
    result = await processing_pipeline.process_text(text_content, "temp_output")
    
    return {
        'original_text': text_content,
        'processed_text': result.processed_text,
        'quality_metrics': result.quality_metrics,
        'processing_stats': result.processing_stats,
        'pseudonym_mapping': result.pseudonym_map,
        'recommendations': result.recommendations
    }

async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Incident Database CLI - MVP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load incidents from JSONL file
  python db_cli.py load --input data/test_samples/rootly_samples.jsonl
  
  # Process unprocessed incidents
  python db_cli.py process
  
  # Show database stats
  python db_cli.py stats
  
  # Get incident details
  python db_cli.py get --id <incident_id>
  python db_cli.py get --rootly-id <rootly_id> --include-processing
  
  # List all incidents
  python db_cli.py list --limit 10
        """
    )
    
    parser.add_argument('--db', default='incidents.db', help='Database file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Load command
    load_parser = subparsers.add_parser('load', help='Load incidents from JSONL file')
    load_parser.add_argument('--input', '-i', required=True, help='JSONL file path')
    load_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Process unprocessed incidents')
    process_parser.add_argument('--limit', type=int, help='Limit number of incidents to process')
    process_parser.add_argument('--real-api', action='store_true', help='Use real LLM APIs')
    process_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get incident details')
    get_parser.add_argument('--id', help='Incident ID')
    get_parser.add_argument('--rootly-id', help='Rootly incident ID')
    get_parser.add_argument('--include-processing', action='store_true', help='Include processing results')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List incidents')
    list_parser.add_argument('--limit', type=int, default=10, help='Number of incidents to show')
    list_parser.add_argument('--unprocessed', action='store_true', help='Show only unprocessed incidents')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize database
    db = IncidentDatabase(args.db)
    
    if args.command == 'load':
        # Load incidents from JSONL file
        print(f"Loading incidents from {args.input}...")
        incidents = load_incidents_from_jsonl(args.input)
        
        stored_count = 0
        for incident in incidents:
            try:
                incident_id = db.store_incident(incident)
                stored_count += 1
                if args.verbose:
                    print(f"Stored incident: {incident.get('id', 'unknown')} -> {incident_id}")
            except Exception as e:
                print(f"Error storing incident {incident.get('id', 'unknown')}: {e}")
        
        print(f"Successfully loaded {stored_count} incidents into database")
    
    elif args.command == 'process':
        # Process unprocessed incidents
        print("Finding unprocessed incidents...")
        unprocessed = db.get_incidents_without_processing()
        
        if not unprocessed:
            print("No unprocessed incidents found")
            return
        
        if args.limit:
            unprocessed = unprocessed[:args.limit]
        
        print(f"Processing {len(unprocessed)} incidents...")
        
        # Initialize processing pipeline
        processing_pipeline = PIIProcessingPipeline(use_real_api=args.real_api)
        
        processed_count = 0
        for incident in unprocessed:
            try:
                print(f"Processing incident: {incident['rootly_id']} - {incident['title']}")
                
                # Process the incident
                result_data = await process_incident(incident['raw_data'], processing_pipeline)
                
                # Store the result
                db.store_processing_result(incident['id'], result_data)
                processed_count += 1
                
                if args.verbose:
                    quality_score = result_data['quality_metrics'].get('overall_quality_score', 0)
                    print(f"  Quality score: {quality_score:.3f}")
                
            except Exception as e:
                print(f"Error processing incident {incident['rootly_id']}: {e}")
        
        print(f"Successfully processed {processed_count} incidents")
    
    elif args.command == 'stats':
        # Show database statistics
        stats = db.get_processing_stats()
        
        print("\n" + "="*50)
        print("DATABASE STATISTICS")
        print("="*50)
        print(f"Total incidents: {stats['total_incidents']}")
        print(f"Processed incidents: {stats['processed_incidents']}")
        print(f"Unprocessed incidents: {stats['unprocessed_incidents']}")
        print(f"Processing percentage: {stats['processing_percentage']:.1f}%")
        print(f"Average quality score: {stats['average_quality_score']:.3f}")
        print("="*50)
    
    elif args.command == 'get':
        # Get incident details
        if args.id:
            incident = db.get_incident(args.id)
            if not incident:
                print(f"Incident with ID {args.id} not found")
                return
        elif args.rootly_id:
            incident = db.get_incident_by_rootly_id(args.rootly_id)
            if not incident:
                print(f"Incident with Rootly ID {args.rootly_id} not found")
                return
        else:
            print("Please specify either --id or --rootly-id")
            return
        
        print(f"\nIncident Details:")
        print(f"ID: {incident['id']}")
        print(f"Rootly ID: {incident['rootly_id']}")
        print(f"Title: {incident['title']}")
        print(f"Status: {incident['status']}")
        print(f"Severity: {incident['severity']}")
        print(f"Created: {incident['created_at']}")
        
        if args.include_processing:
            result = db.get_processing_result(incident['id'])
            if result:
                print(f"\nProcessing Results:")
                print(f"Quality Score: {result['quality_metrics'].get('overall_quality_score', 0):.3f}")
                print(f"Processed: {result['processing_timestamp']}")
                print(f"\nOriginal Text (first 200 chars):")
                print(result['original_text'][:200] + "...")
                print(f"\nProcessed Text (first 200 chars):")
                print(result['processed_text'][:200] + "...")
            else:
                print("\nNo processing results found for this incident")
    
    elif args.command == 'list':
        # List incidents
        if args.unprocessed:
            incidents = db.get_incidents_without_processing()
            print(f"\nUnprocessed Incidents (limit: {args.limit}):")
        else:
            incidents = db.get_all_incidents(args.limit)
            print(f"\nAll Incidents (limit: {args.limit}):")
        
        if not incidents:
            print("No incidents found")
            return
        
        print("-" * 80)
        for incident in incidents:
            print(f"ID: {incident['id']}")
            print(f"Rootly ID: {incident['rootly_id']}")
            print(f"Title: {incident['title']}")
            print(f"Status: {incident['status']} | Severity: {incident['severity']}")
            print(f"Created: {incident['created_at']}")
            print("-" * 80)

if __name__ == "__main__":
    asyncio.run(main())
