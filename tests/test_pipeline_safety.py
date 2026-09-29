"""Regression checks for review coverage and residual-PII decisions."""

import json
import re
from types import SimpleNamespace

import pytest

from process_incidents import assess_human_review
from src.policies.policy_manager import PIIPolicy, RedactionAction
from src.processing.arbitration_engine import ConflictResolver, TextProcessor
from src.processing.llm_final_reviewer import LLMFinalReviewer
from src.processing.quality_validator import ResidualPIIDetector
from src.processing_pipeline import PIIProcessingPipeline


class FakeCompletions:
    def __init__(self, fail_after=None):
        self.prompts = []
        self.fail_after = fail_after

    async def create(self, **kwargs):
        prompt = kwargs['messages'][0]['content']
        self.prompts.append(prompt)
        if self.fail_after and len(self.prompts) == self.fail_after:
            raise RuntimeError('review unavailable')
        found = 'Zyx42Identifier' in prompt
        response = {
            'is_clean': not found,
            'confidence': 0.9,
            'overall_assessment': 'identifier found' if found else 'clean',
            'issues': ([{'snippet': 'Zyx42Identifier', 'issue_type': 'residual_pii',
                         'severity': 'high', 'reasoning': 'identifying token'}] if found else []),
        }
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content=json.dumps(response)))])


def reviewer_with_fake_client(completions):
    reviewer = LLMFinalReviewer(None, enabled=False)
    reviewer.enabled = True
    reviewer.provider = 'openai'
    reviewer.model_name = 'test-model'
    reviewer.client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return reviewer


@pytest.mark.asyncio
async def test_final_review_covers_text_after_first_window():
    completions = FakeCompletions()
    reviewer = reviewer_with_fake_client(completions)
    text = 'a' * 8100 + 'Zyx42Identifier'

    result = await reviewer.review(text)

    assert len(completions.prompts) == 2
    assert result.chunks_reviewed == 2
    assert result.reviewed_chars == result.total_chars == len(text)
    assert result.is_clean is False
    assert result.issues[0].snippet == 'Zyx42Identifier'


@pytest.mark.asyncio
async def test_incomplete_final_review_requires_human_review():
    reviewer = reviewer_with_fake_client(FakeCompletions(fail_after=2))
    result = await reviewer.review('a' * 8100)

    assert result.skipped is True
    assert result.reviewed_chars == 8000
    assessment = assess_human_review({
        'quality_metrics': {'overall_quality_score': 1.0, 'precision': 1.0,
                            'recall': 1.0, 'f1_score': 1.0},
        'final_review': result.to_dict(),
    }, 0.7)
    assert assessment['needs_review'] is True
    assert assessment['final_review_unavailable'] is True


def test_residual_scan_uses_processed_text_positions():
    detector = ResidualPIIDetector.__new__(ResidualPIIDetector)
    detector.residual_patterns = {'email_fragments': re.compile(r'\b[a-z]+@[a-z]+\.com\b')}
    detector.exclusion_patterns = {}
    detector.pii_detector = SimpleNamespace(detect_pii=lambda *args, **kwargs: [])

    issues = detector.detect_residual_pii(
        'x@example.com', [SimpleNamespace(
            start_pos=0, end_pos=13, final_action=RedactionAction.REDACT,
            replacement_text='[REDACTED_EMAIL]', original_text='old@example.com',
            arbitration_reasoning='',
        )])

    assert len(issues) == 1
    assert issues[0].location['text'] == 'x@example.com'


def test_critical_validation_issue_requires_review_at_threshold():
    assessment = assess_human_review({
        'quality_metrics': {'overall_quality_score': 0.7, 'precision': 1.0,
                            'recall': 1.0, 'f1_score': 1.0, 'residual_pii_count': 1},
        'critical_issues': 1,
        'final_review': {'skipped': True, 'skip_reason': 'disabled'},
    }, 0.7)

    assert assessment['needs_review'] is True
    assert assessment['validation_flag'] is True


def test_support_address_elsewhere_cannot_retain_detected_person():
    resolver = ConflictResolver(PIIPolicy())
    action, _ = resolver.resolve_conflict(
        'person_name',
        {'deterministic': RedactionAction.PSEUDONYMIZE,
         'llm_finder': RedactionAction.RETAIN},
        'Contact support@example.com about Maria Garcia',
        'Maria Garcia',
    )

    assert action == RedactionAction.PSEUDONYMIZE


def test_detected_name_is_pseudonymized_at_every_mention():
    text = 'Maria Garcia investigated. Maria Garcia resolved it.'
    decision = SimpleNamespace(
        start_pos=0, end_pos=12, original_text='Maria Garcia',
        replacement_text='Person_12345678', entity_type='person_name',
        final_action=RedactionAction.PSEUDONYMIZE, entity_id='name-1',
        redaction_type='pseudonymize', timestamp='test',
    )

    result, transformations = TextProcessor().apply_redactions(text, [decision])

    assert result.count('Person_12345678') == 2
    assert 'Maria Garcia' not in result
    assert any(t['redaction_type'] == 'remaining_mentions' for t in transformations)


@pytest.mark.asyncio
async def test_incident_infrastructure_identifiers_preserve_operational_context():
    text = (
        'The payments-api service on db-prod-01.internal at 10.2.3.4 failed. '
        'kafka-broker-3.us-east-1 was healthy. See INC-123 and '
        'arn:aws:lambda:us-east-1:123456789012:function:payments.'
    )

    result = await PIIProcessingPipeline(use_real_api=False).process_text(text)

    assert 'db-prod-01.internal' not in result.processed_text
    assert '10.2.3.4' not in result.processed_text
    assert 'INC-123' not in result.processed_text
    assert 'arn:aws:lambda' not in result.processed_text
    assert 'payments-api' in result.processed_text
    assert 'kafka-broker-3.us-east-1' in result.processed_text
    assert result.validation_issues == 0
