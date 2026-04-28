"""
LLM-based final review of redacted text.

Runs as the last pipeline stage. Asks an LLM whether the already-redacted
output still contains identifiable information. The pattern-based validator
(quality_validator.py) catches obvious leftovers like emails or phone numbers;
this stage catches contextual re-identification — descriptions that uniquely
point at a person, customer, or system without containing a literal PII token.

It is the most expensive stage (one LLM call per incident) and runs only when
real APIs are enabled. In simulation mode or when no API key is available, it
returns a skipped result so downstream consumers always see a populated field.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """You are a privacy auditor. The text below has already been processed by a redaction pipeline. Your job is to find any remaining personally identifiable information (PII) or contextual identifiers that could re-identify a person, customer, employee, or specific internal system.

Look for:
- Names, emails, phone numbers, SSNs, or credit-card-like patterns the redactor missed
- Contextual identification: descriptions that uniquely point at someone without naming them (e.g. "the engineer who pushed last week's redis migration", "the enterprise customer in Sao Paulo with the recurring billing bug")
- Internal hostnames, account IDs, or customer references that uniquely identify

Respond ONLY with JSON of this exact shape, no prose before or after:
{
  "is_clean": true,
  "confidence": 0.92,
  "overall_assessment": "one-sentence summary of the review",
  "issues": [
    {
      "snippet": "the exact problematic text from the input",
      "issue_type": "residual_pii",
      "severity": "high",
      "reasoning": "why this is identifiable"
    }
  ]
}

Use issue_type values from: "residual_pii", "contextual_identification", "ambiguous".
Use severity values from: "high", "medium", "low".
If the text is clean, return is_clean=true with an empty issues array.

Text to review:
\"\"\"
__TEXT__
\"\"\"
"""


@dataclass
class FinalReviewIssue:
    snippet: str
    issue_type: str
    severity: str
    reasoning: str


@dataclass
class FinalReviewResult:
    is_clean: bool
    confidence: float
    overall_assessment: str
    issues: List[FinalReviewIssue] = field(default_factory=list)
    model_used: str = ""
    skipped: bool = False
    skip_reason: Optional[str] = None
    timestamp: float = 0.0

    def to_dict(self):
        data = asdict(self)
        data['issues'] = [asdict(i) for i in self.issues]
        return data


class LLMFinalReviewer:
    """Final LLM-based pass to catch contextual leakage that pattern-based post-checks miss."""

    MAX_INPUT_CHARS = 8000

    def __init__(self, config_manager, enabled: bool = True):
        self.config_manager = config_manager
        self.enabled = enabled
        self.client = None
        self.provider = ""
        self.model_name = ""
        self.timeout = 30
        self.max_tokens = 800
        self.temperature = 0.0
        if self.enabled:
            self._setup_client()

    def _setup_client(self):
        judge = self.config_manager.config.judge_model
        self.model_name = judge.model_name
        provider = judge.provider
        self.provider = provider.value if hasattr(provider, 'value') else str(provider)
        self.timeout = judge.timeout

        api_key = os.getenv(judge.api_key_env_var)
        if not api_key:
            logger.warning(f"LLMFinalReviewer: no {judge.api_key_env_var}; final review will be skipped")
            self.client = None
            return

        try:
            if self.provider == 'anthropic':
                import anthropic
                self.client = anthropic.AsyncAnthropic(api_key=api_key, timeout=self.timeout)
            elif self.provider == 'openai':
                import openai
                self.client = openai.AsyncOpenAI(api_key=api_key, timeout=self.timeout)
            else:
                logger.warning(f"LLMFinalReviewer: unsupported provider {self.provider}; skipping")
                self.client = None
                return
            logger.info(f"LLMFinalReviewer initialized with {self.provider}/{self.model_name}")
        except ImportError as e:
            logger.warning(f"LLMFinalReviewer: missing SDK ({e}); skipping")
            self.client = None
        except Exception as e:
            logger.warning(f"LLMFinalReviewer init failed: {e}; skipping")
            self.client = None

    async def review(self, processed_text: str) -> FinalReviewResult:
        if not self.enabled:
            return self._skipped("disabled", "Final review disabled")
        if self.client is None:
            return self._skipped("no_api_client", "No API client available")

        prompt = PROMPT_TEMPLATE.replace("__TEXT__", processed_text[: self.MAX_INPUT_CHARS])

        try:
            if self.provider == 'anthropic':
                response = await self.client.messages.create(
                    model=self.model_name,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = response.content[0].text
            else:
                response = await self.client.chat.completions.create(
                    model=self.model_name,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = response.choices[0].message.content
            return self._parse(raw)
        except Exception as e:
            logger.warning(f"LLMFinalReviewer call failed: {e}")
            return self._skipped("api_error", f"LLM review failed: {e}")

    def _parse(self, raw: str) -> FinalReviewResult:
        try:
            json_start = raw.find('{')
            json_end = raw.rfind('}') + 1
            data = json.loads(raw[json_start:json_end])

            issues = [
                FinalReviewIssue(
                    snippet=str(item.get('snippet', ''))[:500],
                    issue_type=str(item.get('issue_type', 'ambiguous')),
                    severity=str(item.get('severity', 'medium')),
                    reasoning=str(item.get('reasoning', ''))[:500],
                )
                for item in data.get('issues', [])
            ]
            return FinalReviewResult(
                is_clean=bool(data.get('is_clean', False)),
                confidence=float(data.get('confidence', 0.5)),
                overall_assessment=str(data.get('overall_assessment', ''))[:500],
                issues=issues,
                model_used=self.model_name,
                timestamp=time.time(),
            )
        except Exception as e:
            logger.warning(f"LLMFinalReviewer: failed to parse response: {e}")
            return self._skipped("parse_error", "Failed to parse LLM response")

    def _skipped(self, reason: str, assessment: str) -> FinalReviewResult:
        return FinalReviewResult(
            is_clean=True,
            confidence=0.0,
            overall_assessment=assessment,
            issues=[],
            model_used=self.model_name,
            skipped=True,
            skip_reason=reason,
            timestamp=time.time(),
        )
