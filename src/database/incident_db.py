#!/usr/bin/env python3
"""
Incident Database Module - MVP
Simple SQLite-based storage for Rootly incidents and PII redaction results
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class IncidentDatabase:
    """Simple SQLite database for storing incidents and PII redaction results"""
    
    def __init__(self, db_path: str = "incidents.db"):
        """Initialize database connection and create tables"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_database()
        logger.info(f"Incident database initialized at {self.db_path}")
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Incidents table - stores original Rootly incident data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    rootly_id TEXT UNIQUE,
                    title TEXT,
                    summary TEXT,
                    description TEXT,
                    status TEXT,
                    severity TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    resolved_at TEXT,
                    raw_data TEXT,  -- Full JSON data
                    created_timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Processing results table - stores PII redaction results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS processing_results (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    original_text TEXT,
                    processed_text TEXT,
                    quality_metrics TEXT,  -- JSON
                    processing_stats TEXT,  -- JSON
                    pseudonym_mapping TEXT,  -- JSON
                    recommendations TEXT,  -- JSON
                    processing_timestamp TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents (id)
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_rootly_id ON incidents (rootly_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_processing_incident_id ON processing_results (incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at)")
            
            conn.commit()
    
    def store_incident(self, incident_data: Dict[str, Any]) -> str:
        """Store a Rootly incident in the database"""
        incident_id = str(uuid.uuid4())
        rootly_id = incident_data.get('id', '')
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO incidents 
                (id, rootly_id, title, summary, description, status, severity, 
                 created_at, updated_at, resolved_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                rootly_id,
                incident_data.get('title', ''),
                incident_data.get('summary', ''),
                incident_data.get('description', ''),
                incident_data.get('status', ''),
                incident_data.get('severity', ''),
                incident_data.get('created_at', ''),
                incident_data.get('updated_at', ''),
                incident_data.get('resolved_at', ''),
                json.dumps(incident_data)
            ))
            
            conn.commit()
        
        logger.info(f"Stored incident {rootly_id} with ID {incident_id}")
        return incident_id
    
    def store_processing_result(self, incident_id: str, result_data: Dict[str, Any]) -> str:
        """Store PII redaction processing results"""
        result_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO processing_results 
                (id, incident_id, original_text, processed_text, quality_metrics,
                 processing_stats, pseudonym_mapping, recommendations, processing_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result_id,
                incident_id,
                result_data.get('original_text', ''),
                result_data.get('processed_text', ''),
                json.dumps(result_data.get('quality_metrics', {})),
                json.dumps(result_data.get('processing_stats', {})),
                json.dumps(result_data.get('pseudonym_mapping', {})),
                json.dumps(result_data.get('recommendations', [])),
                datetime.now().isoformat()
            ))
            
            conn.commit()
        
        logger.info(f"Stored processing result {result_id} for incident {incident_id}")
        return result_id
    
    def get_incident_by_rootly_id(self, rootly_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by Rootly ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM incidents WHERE rootly_id = ?", (rootly_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'rootly_id': row[1],
                    'title': row[2],
                    'summary': row[3],
                    'description': row[4],
                    'status': row[5],
                    'severity': row[6],
                    'created_at': row[7],
                    'updated_at': row[8],
                    'resolved_at': row[9],
                    'raw_data': json.loads(row[10]) if row[10] else {}
                }
        
        return None
    
    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'rootly_id': row[1],
                    'title': row[2],
                    'summary': row[3],
                    'description': row[4],
                    'status': row[5],
                    'severity': row[6],
                    'created_at': row[7],
                    'updated_at': row[8],
                    'resolved_at': row[9],
                    'raw_data': json.loads(row[10]) if row[10] else {}
                }
        
        return None
    
    def get_processing_result(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve processing result for an incident"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM processing_results WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'incident_id': row[1],
                    'original_text': row[2],
                    'processed_text': row[3],
                    'quality_metrics': json.loads(row[4]) if row[4] else {},
                    'processing_stats': json.loads(row[5]) if row[5] else {},
                    'pseudonym_mapping': json.loads(row[6]) if row[6] else {},
                    'recommendations': json.loads(row[7]) if row[7] else [],
                    'processing_timestamp': row[8]
                }
        
        return None
    
    def get_all_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve all incidents with optional limit"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM incidents ORDER BY created_timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            incidents = []
            for row in rows:
                incidents.append({
                    'id': row[0],
                    'rootly_id': row[1],
                    'title': row[2],
                    'summary': row[3],
                    'description': row[4],
                    'status': row[5],
                    'severity': row[6],
                    'created_at': row[7],
                    'updated_at': row[8],
                    'resolved_at': row[9],
                    'raw_data': json.loads(row[10]) if row[10] else {}
                })
            
            return incidents
    
    def get_incidents_without_processing(self) -> List[Dict[str, Any]]:
        """Get incidents that haven't been processed yet"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT i.* FROM incidents i
                LEFT JOIN processing_results p ON i.id = p.incident_id
                WHERE p.incident_id IS NULL
                ORDER BY i.created_timestamp DESC
            """)
            rows = cursor.fetchall()
            
            incidents = []
            for row in rows:
                incidents.append({
                    'id': row[0],
                    'rootly_id': row[1],
                    'title': row[2],
                    'summary': row[3],
                    'description': row[4],
                    'status': row[5],
                    'severity': row[6],
                    'created_at': row[7],
                    'updated_at': row[8],
                    'resolved_at': row[9],
                    'raw_data': json.loads(row[10]) if row[10] else {}
                })
            
            return incidents
    
    def cleanup_orphaned_results(self) -> int:
        """Remove processing results that reference non-existent incidents"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM processing_results 
                WHERE incident_id NOT IN (SELECT id FROM incidents)
            """)
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.warning(f"Cleaned up {deleted_count} orphaned processing results")
            
            return deleted_count
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get basic processing statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total incidents
            cursor.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = cursor.fetchone()[0]
            
            # Processed incidents (only count results that reference existing incidents)
            cursor.execute("""
                SELECT COUNT(DISTINCT p.incident_id) 
                FROM processing_results p
                INNER JOIN incidents i ON p.incident_id = i.id
            """)
            processed_incidents = cursor.fetchone()[0]
            
            # Average quality score
            cursor.execute("""
                SELECT AVG(CAST(json_extract(p.quality_metrics, '$.overall_quality_score') AS REAL))
                FROM processing_results p
                INNER JOIN incidents i ON p.incident_id = i.id
                WHERE p.quality_metrics IS NOT NULL
            """)
            avg_quality = cursor.fetchone()[0] or 0
            
            return {
                'total_incidents': total_incidents,
                'processed_incidents': processed_incidents,
                'unprocessed_incidents': total_incidents - processed_incidents,
                'processing_percentage': (processed_incidents / total_incidents * 100) if total_incidents > 0 else 0,
                'average_quality_score': round(avg_quality, 3)
            }
