"""
Allowlist of strings that should be preserved (not redacted) even when the
detection pipeline flags them as PII.

The pipeline aggressively flags hostnames, region codes, and service identifiers
as PII because they can be identifying. In an incident-narrative context, those
tokens are usually operationally important and should survive redaction. The
allowlist is the user-controlled escape hatch.

Intentionally simple: two lists, no precedence rules, no scopes. Applied at
arbitration time, after the per-stage detectors have run, so allowlist hits are
recorded in the audit trail rather than silently swallowed.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Pattern

logger = logging.getLogger(__name__)

DEFAULT_ALLOWLIST_PATH = "config/allowlist.json"


class Allowlist:
    """Match detected entity text against a user-configured allowlist."""

    def __init__(self, literals: Optional[List[str]] = None,
                 regex_patterns: Optional[List[str]] = None):
        self._literals = {s.strip().lower() for s in (literals or []) if s and s.strip()}
        self._compiled: List[Pattern[str]] = []
        for pattern in regex_patterns or []:
            if not pattern:
                continue
            try:
                self._compiled.append(re.compile(pattern))
            except re.error as exc:
                logger.warning(f"Allowlist: skipping invalid regex {pattern!r}: {exc}")

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls()

    @classmethod
    def from_file(cls, path: str) -> "Allowlist":
        file_path = Path(path)
        if not file_path.exists():
            logger.warning(f"Allowlist: file {path} not found; using empty allowlist")
            return cls.empty()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(f"Allowlist: failed to load {path}: {exc}; using empty allowlist")
            return cls.empty()
        return cls(
            literals=data.get("literals") or [],
            regex_patterns=data.get("regex_patterns") or [],
        )

    def is_empty(self) -> bool:
        return not self._literals and not self._compiled

    def match(self, text: str) -> Optional[str]:
        """Return the matched pattern (literal or regex) if text is allowlisted, else None."""
        if not text:
            return None
        candidate = text.strip()
        if candidate.lower() in self._literals:
            return candidate.lower()
        for pattern in self._compiled:
            if pattern.search(candidate):
                return pattern.pattern
        return None
