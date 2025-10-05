"""
Data Collection Module
Professional orchestrator for collecting incident data from various platforms
"""

import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

from .data_collection._collector import Collector
from .data_collection._collector import Collector
from .data_collection.rootly_collector import RootlyCollector
from .data_collection._collector import Collector
from .data_collection.pagerduty_collector import PagerDutyCollector
from .data_collection.bigpanda_collector import BigPandaCollector

logger = logging.getLogger(__name__)

@dataclass
class CollectionResult:
    """Result from data collection operation"""
    platform: str
    incidents_collected: int
    output_file: str
    collection_time: str
    success: bool
    error_message: Optional[str] = None

@dataclass
class CollectionSummary:
    """Summary of all data collection operations"""
    total_platforms: int
    successful_collections: int
    failed_collections: int
    total_incidents: int
    collection_results: List[CollectionResult]
    output_directory: str
    collection_timestamp: str

class DataCollectionOrchestrator:
    """Professional data collection orchestrator for incident management platforms"""
    
    def __init__(self, output_dir: str = "data/collected"):
        """Initialize the data collection orchestrator"""
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize platform collectors
        self.collectors = {
            '': Collector(),
            '': Collector(),
            'rootly': RootlyCollector(),
            '': Collector(),
            'pagerduty': PagerDutyCollector(),
            'bigpanda': BigPandaCollector()
        }
        
        logger.info("Data Collection Orchestrator initialized")
    
    def collect_from_platform(self, platform: str, api_key: Optional[str] = None, 
                           num_samples: int = 10) -> CollectionResult:
        """Collect data from a specific platform"""
        
        if platform not in self.collectors:
            return CollectionResult(
                platform=platform,
                incidents_collected=0,
                output_file="",
                collection_time=datetime.now().isoformat(),
                success=False,
                error_message=f"Unsupported platform: {platform}"
            )
        
        try:
            logger.info(f"Collecting data from {platform}")
            
            collector = self.collectors[platform]
            
            # Generate sample data (in production, this would use real API calls)
            incidents = collector.generate_sample_incidents(num_samples)
            
            # Save to output file
            output_file = self.output_dir / f"{platform}_incidents.jsonl"
            with open(output_file, 'w') as f:
                for incident in incidents:
                    f.write(json.dumps(incident) + '\n')
            
            logger.info(f"Successfully collected {len(incidents)} incidents from {platform}")
            
            return CollectionResult(
                platform=platform,
                incidents_collected=len(incidents),
                output_file=str(output_file),
                collection_time=datetime.now().isoformat(),
                success=True
            )
            
        except Exception as e:
            logger.error(f"Failed to collect data from {platform}: {e}")
            return CollectionResult(
                platform=platform,
                incidents_collected=0,
                output_file="",
                collection_time=datetime.now().isoformat(),
                success=False,
                error_message=str(e)
            )
    
    def collect_from_all_platforms(self, api_keys: Optional[Dict[str, str]] = None,
                                 num_samples_per_platform: int = 10) -> CollectionSummary:
        """Collect data from all supported platforms"""
        
        logger.info("Starting data collection from all platforms")
        
        results = []
        successful_collections = 0
        failed_collections = 0
        total_incidents = 0
        
        for platform in self.collectors.keys():
            api_key = api_keys.get(platform) if api_keys else None
            result = self.collect_from_platform(platform, api_key, num_samples_per_platform)
            results.append(result)
            
            if result.success:
                successful_collections += 1
                total_incidents += result.incidents_collected
            else:
                failed_collections += 1
        
        summary = CollectionSummary(
            total_platforms=len(self.collectors),
            successful_collections=successful_collections,
            failed_collections=failed_collections,
            total_incidents=total_incidents,
            collection_results=results,
            output_directory=str(self.output_dir),
            collection_timestamp=datetime.now().isoformat()
        )
        
        # Save collection summary
        summary_file = self.output_dir / "collection_summary.json"
        with open(summary_file, 'w') as f:
            json.dump({
                'total_platforms': summary.total_platforms,
                'successful_collections': summary.successful_collections,
                'failed_collections': summary.failed_collections,
                'total_incidents': summary.total_incidents,
                'output_directory': summary.output_directory,
                'collection_timestamp': summary.collection_timestamp,
                'platform_results': [
                    {
                        'platform': r.platform,
                        'incidents_collected': r.incidents_collected,
                        'output_file': r.output_file,
                        'collection_time': r.collection_time,
                        'success': r.success,
                        'error_message': r.error_message
                    }
                    for r in results
                ]
            }, f, indent=2)
        
        logger.info(f"Data collection completed: {successful_collections}/{len(self.collectors)} platforms successful")
        return summary
    
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported platforms"""
        return list(self.collectors.keys())
    
    def validate_api_keys(self, api_keys: Dict[str, str]) -> Dict[str, bool]:
        """Validate API keys for all platforms"""
        validation_results = {}
        
        for platform, api_key in api_keys.items():
            if platform in self.collectors:
                # In production, this would make actual API calls to validate
                validation_results[platform] = bool(api_key and len(api_key) > 10)
            else:
                validation_results[platform] = False
        
        return validation_results
    
    def get_collection_statistics(self) -> Dict[str, Any]:
        """Get statistics about collected data"""
        
        stats = {
            'total_files': 0,
            'total_incidents': 0,
            'platforms_with_data': [],
            'file_sizes': {},
            'last_collection': None
        }
        
        if self.output_dir.exists():
            for file_path in self.output_dir.glob("*.jsonl"):
                if file_path.name != "collection_summary.json":
                    platform = file_path.stem.replace("_incidents", "")
                    stats['platforms_with_data'].append(platform)
                    stats['total_files'] += 1
                    
                    # Count incidents in file
                    incident_count = 0
                    with open(file_path, 'r') as f:
                        for line in f:
                            if line.strip():
                                incident_count += 1
                    
                    stats['total_incidents'] += incident_count
                    stats['file_sizes'][platform] = {
                        'file_size_mb': file_path.stat().st_size / (1024 * 1024),
                        'incident_count': incident_count
                    }
        
        return stats
