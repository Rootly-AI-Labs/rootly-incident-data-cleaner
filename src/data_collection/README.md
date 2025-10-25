# Data Collection Scripts

This directory contains the data collection script for Rootly incident management platform. The script collects real incident data via their respective APIs and saves them as JSONL files for testing the PII redaction pipeline.

## Platform Coverage

| Platform | Script | API Documentation | Status |
|----------|--------|-------------------|---------|
| Rootly | `rootly_collector.py` | https://docs.google.com/doc/api | ✅ Complete (REST + GraphQL) |

## Prerequisites

### API Credentials

You'll need API credentials for Rootly:

#### Rootly
- `ROOTLY_API_KEY`: Your Rootly API key
- `ROOTLY_ORG_ID`: Your organization ID

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install the data collection scripts
pip install -e .
```

## Usage Examples

### Rootly
```bash
python src/data_collection/rootly_collector.py \
  --api-key YOUR_ROOTLY_API_KEY \
  --org-id YOUR_ORG_ID \
  --output data/test_samples/rootly_samples.jsonl \
  --num-incidents 10
```

## Output Format

The script outputs JSONL files (one JSON object per line) with the following naming convention:
```
rootly_incidents_{timestamp}.jsonl
```

Example:
- `rootly_incidents_20241215_143022.jsonl`

## Data Schema

Rootly incident data includes:

### Common Fields
- `id`: Unique identifier
- `title`: Incident summary/title
- `summary`: Brief incident description
- `description`: Detailed incident description
- `status`: Current status (resolved, mitigating, etc.)
- `severity`: Impact level (high, medium, low)
- `created_at`: Incident creation timestamp
- `updated_at`: Last modification timestamp
- `resolved_at`: Resolution timestamp
- `incidentCommander`: Primary responder information
- `participants`: List of incident participants with roles
- `timelineEvents`: Real-time incident updates
- `customFields`: Additional metadata

### Rootly-Specific Features
- `learnedLessons`: Structured learning outcomes
- `followUps`: Trackable action items
- `tasks`: Specific tasks with assignees and due dates
- Both REST and GraphQL endpoints supported

## Best Practices

1. **Start Small**: Begin with `--num-incidents 5` to test API access
2. **Rate Limiting**: Script includes built-in rate limiting and error handling
3. **Data Privacy**: All collected data contains real operational information - handle securely
4. **Incremental Collection**: Use timestamp filtering to collect only new data
5. **Storage**: Consider archiving old JSONL files to manage disk usage

## Troubleshooting

### Common Issues

#### Authentication Errors
```
Error: HTTP 401 Unauthorized
```
- Verify your API credentials are correct
- Check if your API key is active and has proper permissions
- Ensure organization ID matches your account

#### Rate Limiting
```
Error: HTTP 429 Too Many Requests
```
- Script automatically handles rate limiting
- Reduce `--num-incidents` or increase collection intervals
- Check Rootly's rate limits in their documentation

#### Missing Data
```
Warning: No incidents found in date range
```
- Verify the date range spans active incidents
- Check if your account has access to the requested data
- Some incidents may require specific states (e.g., "resolved")

### Getting Help

1. Check Rootly's API documentation
2. Verify credentials and permissions with Rootly support
3. Test with minimal parameters first (`--num-incidents 1`)
4. Review error logs for specific troubleshooting information
