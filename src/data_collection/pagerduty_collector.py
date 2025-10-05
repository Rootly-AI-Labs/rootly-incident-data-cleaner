#!/usr/bin/env python3
"""
Data collection script for PagerDuty
Fetches incidents, notes, alerts, and status updates from PagerDuty REST API

API Documentation: https://developer.pagerduty.com/api-reference/
Requires: PAGERDUTY_API_TOKEN
"""

import os
import sys
import json
import requests
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config.settings import LOG_LEVEL

logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

class PagerDutyCollector:
    """Collects data from PagerDuty REST API"""
    
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.pagerduty.com"
        self.headers = {
            "Authorization": f"Token token={api_token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json"
        }
        
    def fetch_incidents(self, limit: int = 100, days_back: int = 30, service_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Fetch incidents from PagerDuty"""
        url = f"{self.base_url}/incidents"
        
        # Calculate date filter
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "limit": min(limit, 100),  # API limit is 100 per request
            "since": start_date.isoformat(),
            "until": end_date.isoformat(),
            "sort_by": "created_at:desc",
            "include": ["services", "assignments", "users"]
        }
        
        # Filter by services if provided
        if service_ids:
            params["service_ids[]"] = service_ids
        
        all_incidents = []
        offset = 0
        
        while True:
            params["offset"] = offset
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                incidents = data.get("incidents", [])
                all_incidents.extend(incidents)
                
                logger.info(f"Fetched {len(incidents)} incidents (total: {len(all_incidents)})")
                
                # Check if we have more data
                more = data.get("more", False)
                if not more or len(all_incidents) >= limit:
                    break
                    
                offset += len(incidents)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching incidents: {e}")
                break
                
        logger.info(f"Total incidents fetched: {len(all_incidents)}")
        return all_incidents[:limit]
    
    def fetch_incident_notes(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch notes for a specific incident"""
        url = f"{self.base_url}/incidents/{incident_id}/notes"
        
        params = {
            "limit": 100
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            notes = data.get("notes", [])
            
            logger.info(f"Fetched {len(notes)} notes for incident {incident_id}")
            return notes
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching notes for incident {incident_id}: {e}")
            return []
    
    def fetch_incident_log_entries(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch log entries (status updates) for a specific incident"""
        url = f"{self.base_url}/incidents/{incident_id}/log_entries"
        
        params = {
            "limit": 100,
            "include": ["incidents", "services", "users"]
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            log_entries = data.get("log_entries", [])
            
            logger.info(f"Fetched {len(log_entries)} log entries for incident {incident_id}")
            return log_entries
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching log entries for incident {incident_id}: {e}")
            return []
    
    def fetch_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch alerts for a specific incident"""
        url = f"{self.base_url}/alerts"
        
        params = {
            "incident_id": incident_id,
            "limit": 100,
            "include": ["services", "integrations"]
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            alerts = data.get("alerts", [])
            
            logger.info(f"Fetched {len(alerts)} alerts for incident {incident_id}")
            return alerts
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching alerts for incident {incident_id}: {e}")
            return []
    
    def enrich_incidents(self, incidents: List[Dict[str, Any]], include_full_data: bool = True) -> List[Dict[str, Any]]:
        """Enrich incidents with notes, log entries, and alerts"""
        enriched_incidents = []
        
        for incident in incidents:
            incident_id = incident.get("id")
            
            enriched_incident = incident.copy()
            
            if include_full_data:
                # Add related data
                notes = self.fetch_incident_notes(incident_id)
                log_entries = self.fetch_incident_log_entries(incident_id)
                alerts = self.fetch_alerts(incident_id)
                
                enriched_incident["notes"] = notes
                enriched_incident["log_entries"] = log_entries
                enriched_incident["alerts"] = alerts
                
            enriched_incidents.append(enriched_incident)
            
        return enriched_incidents
    
    def fetch_services(self) -> List[Dict[str, Any]]:
        """Fetch all services for reference"""
        url = f"{self.base_url}/services"
        
        params = {
            "limit": 100,
            "include": ["integrations", "escalation_policy"]
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            services = data.get("services", [])
            
            logger.info(f"Fetched {len(services)} services")
            return services
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching services: {e}")
            return []
    
    def fetch_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch users for reference"""
        url = f"{self.base_url}/users"
        
        params = {
            "limit": limit
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            users = data.get("users", [])
            
            logger.info(f"Fetched {len(users)} users")
            return users
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching users: {e}")
            return []

def save_to_jsonl(data: List[Dict[str, Any]], filename: str) -> None:
    """Save data to JSONL file"""
    with open(filename, 'w') as f:
        for item in data:
            json.dump(item, f)
            f.write('\n')
    
    logger.info(f"Saved {len(data)} records to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Collect PagerDuty data")
    parser.add_argument("--api-token", required=True, help="PagerDuty API token")
    parser.add_argument("--output-dir", default="./data/raw", help="Output directory")
    parser.add_argument("--limit", type=int, default=100, help="Max records to fetch")
    parser.add_argument("--days-back", type=int, default=30, help="Days of data to fetch")
    parser.add_argument("--include-full-data", action="store_true", help="Include notes, logs, and alerts")
    parser.add_argument("--service-ids", nargs="+", help="Filter by specific service IDs")
    parser.add_argument("--include-reference-data", action="store_true", help="Include services and users")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize collector
    collector = PagerDutyCollector(args.api_token)
    
    # Collect data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Fetch incidents
    logger.info("Fetching incidents...")
    incidents = collector.fetch_incidents(
        limit=args.limit,
        days_back=args.days_back,
        service_ids=args.service_ids
    )
    
    if incidents:
        if args.include_full_data:
            incidents = collector.enrich_incidents(incidents, include_full_data=True)
        
        save_to_jsonl(incidents, f"{args.output_dir}/pagerduty_incidents_{timestamp}.jsonl")
    
    # Fetch reference data if requested
    if args.CLUDE_reference_data:
        logger.info("Fetching services...")
        services = collector.fetch_services()
        if services:
            save_to_jsonl(services, f"{args.output_dir}/pagerduty_services_{timestamp}.jsonl")
        
        logger.info("Fetching users...")
        users = collector.fetch_users(limit=args.limit)
        if users:
            save_to_jsonl(users, f"{args.output_dir}/pagerduty_users_{timestamp}.jsonl")

if __name__ == "__main__":
    main()
