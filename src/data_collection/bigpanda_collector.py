#!/usr/bin/env python3
"""
Data collection script for BigPanda
Fetches incidents, alerts, and events from BigPanda REST API

API Documentation: BigPanda REST API
Requires: BIGPANDA_API_TOKEN, BIGPANDA_ORG_ID
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

class BigPandaCollector:
    """Collects data from BigPanda REST API"""
    
    def __init__(self, api_token: str, org_id: str):
        self.api_token = api_token
        self.org_id = org_id
        self.base_url = "https://api.bigpanda.io/v2"  # Update with actual endpoint
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "X-BigPanda-Org-ID": org_id
        }
        
    def fetch_incidents(self, limit: int = 100, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch incidents from BigPanda"""
        url = f"{self.base_url}/incidents"
        
        # Calculate date filter
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "limit": min(limit, 1000),  # BigPanda typically allows higher limits
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "sort": "-created_time",
            "fields": "all"  # Get all fields
        }
        
        all_incidents = []
        page = 1
        
        while True:
            params["page"] = page
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                incidents = data.get("incidents", [])
                all_incidents.extend(incidents)
                
                logger.info(f"Fetched page {page}: {len(incidents)} incidents (total: {len(all_incidents)})")
                
                # Check pagination
                total_pages = data.get("pagination", {}).get("total_pages", 0)
                if page >= total_pages or len(incidents) == 0:
                    break
                    
                page += 1
                
                # Limit total results
                if len(all_incidents) >= limit:
                    break
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching incidents page {page}: {e}")
                break
                
        logger.info(f"Total incidents fetched: {len(all_incidents)}")
        return all_incidents[:limit]
    
    def fetch_alerts(self, incident_id: Optional[str] = None, limit: int = 100, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch alerts, optionally filtered by incident"""
        url = f"{self.base_url}/alerts"
        
        # Calculate date filter
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "limit": min(limit, 1000),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "sort": "-created_time",
            "fields": "all"
        }
        
        # Filter by incident if provided
        if incident_id:
<｜tool▁call▁begin｜>query

                
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                alerts = data.get("alerts", [])
                all_alerts.extend(alerts)
                
                logger.info(f"Fetched page {page}: {len(alerts)} alerts (total: {len(all_alerts)})")
                
                # Check pagination
                total_pages = data.get("pagination", {}).get("total_pages", 0)
                if page >= total_pages or len(alerts) == 0:
                    break
                    
                page += 1
                
                if len(all_alerts) >= limit:
                    break
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching alerts page {page}: {e}")
                break
                
        return all_alerts[:limit]
    
    def fetch_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch events related to a specific incident"""
        url = f"{self.base_url}/incidents/{incident_id}/events"
        
        params = {
            "limit": 1000,
            "fields": "all"
        }
        
        all_events = []
        page = 1
        
        while True:
            params["page"] = page
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                events = data.get("events", [])
                all_events.extend(events)
                
                logger.info(f"Fetched {len(events)} events for incident {incident_id}")
                
                # Check pagination
                total_pages = data.get("pagination", {}).get("total_pages", 0)
                if page >= total_pages or len(events) == 0:
                    break
                    
                page += 1
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Error fetching events for incident {incident_id}: {e}")
                break
                
        return all_events
    
    def fetch_correlation_events(self, request_id: Optional[str] = None, limit: int = 100, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch correlation events - useful for understanding incident context"""
        url = f"{self.base_url}/correlation_events"
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "limit": min(limit, 1000),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "fields": "all"
        }
        
        if request_id:
            params["request_id"] = request_id
        
        all_correlation_events = []
        page = 1
        
        while True:
            params["page"] = page
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                correlation_events = data.get("correlation_events", [])
                all_correlation_events.extend(correlation_events)
                
                logger.info(f"Fetched page {page}: {len(correlation_events)} correlation events")
                
                # Check pagination
                total_pages = data.get("pagination", {}).get("total_pages", 0)
                if page >= total_pages or len(correlation_events) == 0:
                    break
                    
                page += 1
                
                if len(all_correlation_events) >= limit:
                    break
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching correlation events: {e}")
                break
                
        return all_correlation_events[:limit]
    
    def enrich_incidents_with_events(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich incidents with related events"""
        enriched_incidents = []
        
        for incident in incidents:
            incident_id = incident.get("id")
            events = self.fetch_incident_events(incident_id)
            
            enriched_incident = incident.copy()
            enriched_incident["events"] = events
            enriched_incidents.append(enriched_incident)
            
        return enriched_incidents

def save_to_jsonl(data: List[Dict[str, Any]], filename: str) -> None:
    """Save data to JSONL file"""
    with open(filename, 'w') as f:
        for item in data:
            json.dump(item, f)
            f.write('\n')
    
    logger.info(f"Saved {len(data)} records to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Collect BigPanda data")
    parser.add_argument("--api-token", required=True, help="BigPanda API token")
    parser.add_argument("--org-id", required=True, help="BigPanda organization ID")
    parser.add_argument("--output-dir", default="./data/raw", help="Output directory")
    parser.add_argument("--limit", type=int, default=100, help="Max records to fetch")
    parser.add_argument("--days-back", type=int, default=30, help="Days of data to fetch")
    parser.add_argument("--include-events", action="store_true", help="Include events for incidents")
    parser.add_argument("--fetch-alerts", action="store_true", help="Fetch standalone alerts")
    parser.add_argument("--fetch-correlation-events", action="store_true", help="Fetch correlation events")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize collector
    collector = BigPandaCollector(args.api_token, args.org_id)
    
    # Collect data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Fetch incidents
    logger.info("Fetching incidents...")
    incidents = collector.fetch_incidents(limit=args.limit, days_back=args.days_back)
    
    if incidents:
        if args.include_events:
            incidents = collector.enrich_incidents_with_events(incidents)
        
        save_to_jsonl(incidents, f"{args.output_dir}/bigpanda_incidents_{timestamp}.jsonl")
    
    # Fetch standalone alerts if requested
    if args.fetch_alerts:
        logger.info("Fetching alerts...")
        alerts = collector.fetch_alerts(limit=args.limit, days_back=args.days_back)
        
        if alerts:
            save_to_jsonl(alerts, f"{args.output_dir}/bigpanda_alerts_{timestamp}.jsonl")
    
    # Fetch correlation events if requested
    if args.fetch_correlation_events:
        logger.info("Fetching correlation events...")
        correlation_events = collector.fetch_correlation_events(limit=args.limit, days_back=args.days_back)
        
        if correlation_events:
            save_to_jsonl(correlation_events, f"{args.output_dir}/bigpanda_correlation_events_{timestamp}.jsonl")

if __name__ == "__main__":
    main()
