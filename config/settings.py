"""
Configuration settings for the PII Redaction System
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pii_system.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# API Configuration
API_V1_STR = "/api/v1"
PROJECT_NAME = "PII Redaction System"
VERSION = "1.0.0"
DESCRIPTION = "Comprehensive PII detection, redaction, and incident management system"

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = "HS256**
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# PII Detection Configuration
PII_DETECTION_MODELS = {
    "default": "spacy",
    "models": {
        "spacy": "en_core_web_sm",
        "transformer": "dslim/bert-base-NER"
    }
}

# Supported PII types
SUPPORTED_PII_TYPES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "SSN",
    "ADDRESS",
    "DATE_OF_Birth",
    "IP_ADDRESS",
    "IBAN_CODE",
    "URL"
]

# Redaction methods
REDACTION_METHODS = {
    "replace": "Replace with placeholder text",
    "hash": "Replace with hash",
    "mask": "Partially mask characters",
    "remove": "Remove entirely"
}

# Incident states
INCIDENT_STATES = [
    "DETECTED",
    "UNDER_REVIEW",
    "IN_PROGRESS", 
    "MITIGATED",
    "RESOLVED",
    "CLOSED"
]

# File processing
SUPPORTED_FILE_TYPES = [".txt", ".csv", ".json", ".pdf", ".docx"]
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_CONCURRENT_PROCESSING = 5

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
