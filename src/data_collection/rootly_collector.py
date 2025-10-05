#!/usr/bin/env python3
"""
Data collection script for Rootly
Fetches incidents, tasks, and retrospectives from Rootly API
Supports both REST API and GraphQL endpoints

API Documentation: https://docs.google.com/doc/api
Requires: ROOTLY_API_KEY, ROOTLY_ORG_ID
"""

import os
import sys
import json
import requests
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
from dataclasses import dataclass

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config.settings import LOG_LEVEL

logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

@dataclass
class RootlyQuery:
    """GraphQL query template"""
    query: str
    variables: Dict[str, Any] = None

class RootlyCollector:
    """Collects data from Rootly API (both REST and GraphQL)"""
    
    def __init__(self, api_key: str, org_id: str, use_graphql: bool = False):
        self.api_key = api_key
        self.org_id = org_id
        self.use_graphql = use_graphql
        
        if use_graphql:
            self.base_url = "https://api.rootly.com/graphql"
        else:
            self.base_url = "https://api.rootly.com/v1"
            
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
    def fetch_incidents_rest(self, limit: int = 100, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch incidents using REST API"""
        url = f"{self.base_url}/incidents"
        
        # Calculate date filter
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "limit": limit,
            "organization_id": self.org_id,
            "created_at[gte]": start_date.isoformat(),
            "created_at[lte]": end_date.isoformat(),
            "order[created_at]": "desc"
        }
        
        all_incidents = []
        page = 1
        has_more = True
        
        while has_more:
            params["page"] = page
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                incidents = data.get("data", [])
                all_incidents.extend(incidents)
                
                logger.info(f"Fetched page {page}: {len(incidents)} incidents (total: {len(all_incidents)})")
                
                # Check if there are more pages
                pagination = data.get("meta", {}).get("pagination", {})
                has_more = pagination.get("pages", 0) > page
                page += 1
                
                if not incidents:  # No more data
                    break
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching incidents page {page}: {e}")
                break
                
        logger.info(f"Total incidents fetched: {len(all_incidents)}")
        return all_incidents
    
    def fetch_incidents_graphql(self, limit: int = 100, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch incidents using GraphQL"""
        query = """
        query GetIncidents($organizationId: ID!, $limit: Int, $createdAtGte: ISO8601DateTime, $createdAtLte: ISO8601DateTime) {
          incidents(
            organizationId: $organizationId
            limit: $limit
            createdAt: { gte: $createdAtGte, lte: $createdAtLte }
          ) {
            id
            title
            summary
            description
            status
            severity
            severityKey
            createdAt
            updatedAt
            resolvedAt
            incidentCommander {
              id
              name
              email
            }
            participants {
              id
              name
              email
              role
            }
            sources {
              id
              name
              type
            }
            tags {
              id
              name
            }
            customFields {
              id
              name
              value
            }
            timelineEvents {
              id
              type
              title
              content
              createdAt
              user {
                id
                name
                email
              }
            }
          }
        }
        """
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        variables = {
            "organizationId": self.org_id,
            "limit": limit,
            "createdAtGte": start_date.isoformat(),
            "createdAtLte": end_date.isoformat()
        }
        
        rql_query = RootlyQuery(query=query, variables=variables)
        
        try:
            response = requests.post(
                self.base_url,
                headers=self.headers,
                json={"query": rql_query.query, "variables": rql_query.variables},
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            
            if "errors" in data:
                logger.error(f"GraphQL errors: {data['errors']}")
                return []
                
            incidents = data.get("data", {}).get("incidents", [])
            
            logger.info(f"Fetched {len(incidents)} incidents via GraphQL")
            return incidents
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error with GraphQL request: {e}")
            return []
    
    def fetch_tasks(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch tasks for a specific incident"""
        url = f"{self.base_url}/incidents/{incident_id}/tasks"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            tasks = data.get("data", [])
            
            logger.info(f"Fetched {len(tasks)} tasks for incident {incident_id}")
            return tasks
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching tasks for incident {incident_id}: {e}")
            return []
    
    def fetch_retrospectives(self) -> List[Dict[str, Any]]:
        """Fetch retrospectives including learned lessons and follow-ups"""
        if self.use_graphql:
            return self._fetch_retrospectives_graphql()
        else:
            return self._fetch_retrospectives_rest()
    
    def _fetch_retrospectives_rest(self) -> List[Dict[str, Any]]:
        """Fetch retrospectives using REST API"""
        url = f"{self.base_url}/retrospectives"
        
        params = {
            "organization_id": self.org_id,
            "limit": 100
        }
        
        all_retrospectives = []
        page similar with incidence pagination
    
    def _fetch_retrospectives_graphql(self) -> List[Dict[str, Any]]:
        """Fetch retrospectives using GraphQL with learned lessons"""
        query = """
        query GetRetrospectives($organizationId: ID!, $limit: Int) {
          retrospectives(organizationId: $organizationId, limit: $limit) {
            id
            title
            summary
            incident {
              id
              title
              summary
            }
            lessonsLearned {
              template
              categories
              questions
            }
            learnedLessons
            followUps
            createdAt
            updatedAt
            team {
              id
              name
            }
            authors {
              id
              name
              email
            }
          }
        }
        """
        
        variables = {
            "organizationId": self.org_id,
            "limit": 100
        }
        
        try:
            response = requests.post(
                self.base_url,
                headers=self.headers,
                json={"query": query, "variables": variables},
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            
            if "errors" in data:
                logger.error(f"GraphQL errors: {data['errors']}")
                return []
                
            retrospectives = data.get("data", {}).get("retrospectives", [])
            
            logger.info(f"Fetched {len(retrospectives)} retrospectives via GraphQL")
            return retrospectives
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error with GraphQL retrospective request: {e}")
            return []
    
    def enrich_incidents_with_tasks(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich incidents with tasks"""
        enriched_incidents = []
        
        for incident in incidents:
            incident_id = incident.get("id")
            tasks = self.fetch_tasks(incident_id)
            
            enriched_incident = incident.copy()
            enriched_incident["tasks"] = tasks
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
    parser = argparse.ArgumentParser(description="Collect Rootly data")
    parser.add_argument("--api-key", required=True, help="Rootly API key")
    parser.add_argument("--org-id", required=True, help="Rootly organization ID")
    parser.add_argument("--use-graphql", action="store_true", help="Use GraphQL instead of REST API")
    parser.add_argument("--output-dir", default="./data/raw", help="Output directory")
    parser.add_argument("--limit", type=int, default=100, help="Max records to fetch")
    parser.add_argument("--merits-back", type=int, default=30, help="Days of data to fetch")
    parser.add_argument("--include-tasks", action="store_true", help="Include tasks for incidents")
    
    args = parser.parse_args()
    
    # Create output directory  
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize collector
    collector = RootlyCollector(args.api_key, args.org_id, use_graphql=args.use_graphql)
    
    # Collect data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Fetch incidents
    logger.info(f"Fetching incidents using {'GraphQL' if args.use_graphql else 'REST'}...")
    
    if args.use_graphql:
        incidents = collector.fetch_incidents_graphql(limit=args.limit, days_back=args.days_back)
    else:
        incidents = collector.fetch_incidents_rest(limit=args.limit, days_back=args.days_back)
    
    if incidents:
        if args.include_tasks:
            incidents = collector.enrich_incidents_with_tasks(incidents)
            
        save_to_jsonl(incidents, f"{args.output_dir}/rootly_incidents_{timestamp}.jsonl")
    
    # Fetch retrospectives
    logger.info("Fetching retrospectives...")
    retrospectives = collector.fetch_retrospectives()
    
    if retrospectives:
        save_to_jsonl(retrospectives, f"{args.output_dir}/rootly_retrospectives_{timestamp}.jsonl")

if __name__ == "__main__":
    main()
