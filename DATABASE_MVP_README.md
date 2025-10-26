# Incident Database MVP

This is a minimal viable product (MVP) for managing Rootly incidents in a database with PII redaction capabilities.

## Features

✅ **Basic Database Storage**
- SQLite database for storing incidents
- Store original Rootly incident data
- Store PII redaction processing results

✅ **PII Processing**
- Process incidents using existing PII redaction logic
- Store original and processed text
- Track quality metrics and processing statistics

✅ **Simple CLI Interface**
- Load incidents from JSONL files
- Process unprocessed incidents
- View database statistics
- Retrieve incident details
- List incidents

## Quick Start

### 1. Load Incidents
```bash
python db_cli.py load --input data/test_samples/rootly_samples.jsonl
```

### 2. Process Incidents
```bash
python db_cli.py process --limit 5
```

### 3. View Statistics
```bash
python db_cli.py stats
```

### 4. Get Incident Details
```bash
python db_cli.py get --id <incident_id> --include-processing
```

### 5. List Incidents
```bash
python db_cli.py list --limit 10
```

## Database Schema

### Incidents Table
- `id`: Unique incident ID (UUID)
- `rootly_id`: Original Rootly incident ID
- `title`, `summary`, `description`: Incident details
- `status`, `severity`: Incident metadata
- `created_at`, `updated_at`, `resolved_at`: Timestamps
- `raw_data`: Full JSON data from Rootly

### Processing Results Table
- `id`: Unique result ID (UUID)
- `incident_id`: Reference to incident
- `original_text`: Text before PII redaction
- `processed_text`: Text after PII redaction
- `quality_metrics`: JSON with quality scores
- `processing_stats`: JSON with processing statistics
- `pseudonym_mapping`: JSON with pseudonym mappings
- `recommendations`: JSON with recommendations
- `processing_timestamp`: When processing occurred

## Example Usage

```bash
# Load sample incidents
python db_cli.py load --input data/test_samples/rootly_samples.jsonl --verbose

# Process all unprocessed incidents
python db_cli.py process --verbose

# Check processing status
python db_cli.py stats

# Get details of a specific incident
python db_cli.py get --id aa7418da-7032-4402-a346-6aab38ff640f --include-processing

# List unprocessed incidents
python db_cli.py list --unprocessed
```

## Next Steps (Future Enhancements)

- **API Endpoints**: REST API for web interface
- **Advanced Metrics**: More detailed analytics and reporting
- **Multiple Database Support**: PostgreSQL, MySQL support
- **Batch Processing**: Process multiple incidents in parallel
- **Web Dashboard**: Web interface for incident management
- **Real-time Processing**: Process incidents as they come in
- **Advanced Querying**: Search and filter capabilities
