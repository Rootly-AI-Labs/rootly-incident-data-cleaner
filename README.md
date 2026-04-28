# PII Incident Redaction Pipeline

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Goal

This project exists for **research purposes**: to make incident post-mortems safe to feed into AI systems (LLMs, embeddings, fine-tuning datasets, retrieval pipelines) without leaking the sensitive information they typically contain.

Incident reports mix valuable operational signal — what broke, how it was diagnosed, what fixed it — with personal and confidential data: names, emails, phone numbers, IPs, customer identifiers, internal hostnames, secrets. The pipeline takes raw incident JSON/JSONL and produces a redacted (or pseudonymized) copy plus an audit trail describing what was changed and why, so the post-mortem narrative stays useful for analysis while the sensitive fields are removed. Sample data uses the Rootly export shape; other shapes can be adapted by adjusting the field-extraction logic.

This is **not a compliance tool**. It is intended to support research and experimentation on incident data — please review outputs before sharing them externally.

## Pipeline steps

Each incident flows through seven stages:

1. **Policy load** — read the JSON policy that defines which categories are PII and which action to take (redact, pseudonymize, keep).
2. **Deterministic extraction** — find obvious PII with regex, Presidio, and spaCy (emails, phones, SSNs, IPs, names).
3. **LLM detection** — a "finder" model (OpenAI `gpt-5` by default) catches contextual PII the rules miss.
4. **LLM verification** — a "judge" model (Anthropic `claude-sonnet-4-6` by default) re-checks each candidate against the policy.
5. **Arbitration & redaction** — conflicting decisions are resolved, then the text is rewritten with redactions or pseudonyms.
6. **Quality validation** — pattern-based scan of the redacted text for residual PII and schema integrity issues; produces `quality_metrics`.
7. **LLM final review** — one extra LLM call per incident asks the judge model whether the redacted text still contains identifiable info, including *contextual* re-identification (descriptions that uniquely point at someone without naming them). Catches what the pattern-based validator can't. This is the most expensive stage, so it runs last and skips automatically in simulation mode or when no API key is set. Disable explicitly with `--skip-final-review`.

A simulation mode (`--llm-simulation`) skips stages 3, 4, and 7 (no API calls), so the pipeline can be exercised without keys. Models are configurable in `config/llm_models.json`.

## What it removes

The pipeline targets the categories defined in `config/policies/default_policy.json`. Out of the box, that includes:

- **Personal identifiers** — full names, email addresses, phone numbers, postal addresses
- **Government/financial IDs** — SSNs, credit card numbers, bank account numbers
- **Network identifiers** — IP addresses, MAC addresses, hostnames that map to individuals
- **Account data** — usernames, customer IDs, employee IDs
- **Credentials** — API keys, tokens, and other secrets that surface in incident notes

Each category has a configurable action — `REDACT` replaces the value with a placeholder (e.g. `[REDACTED_EMAIL]`), `PSEUDONYMIZE` swaps in a stable fake value so downstream analysis still works. Edit the policy JSON to add categories or change actions.

## Allowlist for operational tokens

Some strings the detectors flag as PII are actually operationally useful and shouldn't be redacted — region codes (`us-east-1`), internal hostnames (`kafka-broker-3.us-east-1`), service identifiers, well-known infra names. The allowlist is a user-controlled override applied during arbitration.

The list lives in `config/allowlist.json` and has two fields:

- `literals` — case-insensitive exact-string match. Use for things like `us-east-1`, `eu-central-1`.
- `regex_patterns` — Python `re.search` semantics. Use for parameterized names like `^kafka-broker-\d+(\.[a-z0-9-]+)*$`.

When a detected entity matches any allowlisted pattern, the arbitration step overrides its action to `RETAIN` and records the matched pattern in the audit trail so it shows up in `arbitration.json` and the per-incident report.

CLI control:

- Default: the bundled `config/allowlist.json` is loaded automatically.
- `--allowlist path/to/custom.json` — use a different file (e.g. per-environment).
- `--no-allowlist` — disable entirely; every detection goes through normal redaction.

**Warning:** the allowlist overrides redaction. Never put anything that could be PII (names, emails, SSNs, customer IDs) in it. The default file ships with public AWS region codes and a regex for `kafka-broker-*` / `redis-cache-*` as starter examples; trim or extend it for your environment.

## Human review of low-confidence outputs

Automated redaction is not infallible, so each incident is scored against a confidence threshold (default `0.7`, override with `--confidence-threshold`). Any incident whose `overall_quality_score` (or sub-metric: precision, recall, F1) falls below that threshold is flagged for human review.

Two signals can flip the flag:

1. **Quality score below threshold** — the validator's `overall_quality_score` (or any of `precision` / `recall` / `f1_score`) falls below the threshold.
2. **LLM final review verdict** — stage 7 returns `is_clean: false` with a list of suspicious snippets.

Either signal sets `needs_review: true`.

Where the flag shows up:

- **Per-incident report** (`incident_<id>_detailed_report.json`) — top-level `human_review` block with `needs_review`, `quality_score`, the failing metrics, the LLM verdict, and a `reason` line. The full LLM final-review payload (issues + reasoning) is in the sibling `final_review` block.
- **Overall summary** (`overall_summary.json`) — `human_review.incidents_needing_review_count`, list of incident IDs, and a separate `final_review_summary` showing how many incidents the LLM flagged.
- **Console output** — `👀 Needs Human Review:` and `🔎 LLM Final Review:` lines.

A reviewer should diff the original vs processed text for those incidents, focus on entities the LLM flagged, and either accept the output, edit it, or tighten the policy and re-run.

## Known limitations

- **English only.** Detection relies on `spaCy en_core_web_sm`; non-English incidents will have lower recall.
- **Schema-tuned.** Field extraction is tuned to the included sample shape (Rootly export). Other shapes need an adapter in `src/data_collection/`.
- **LLM-dependent quality.** Stages 3–4 use LLMs; results depend on the model, prompt, and policy. Simulation mode skips these stages and will miss contextual PII the rules don't catch.
- **Pseudonym consistency is per-run.** The same name in two separate processing runs may map to different pseudonyms. Use the SQLite store (`db_cli.py`) if you need cross-run consistency.
- **No guarantee of zero residual PII.** The quality validator flags issues but cannot certify a redacted output is clean — always review high-sensitivity outputs manually.
- **API cost scales with volume** when using real LLM calls; benchmark with `--llm-simulation` first.

## Install

```bash
git clone https://github.com/Rootly-AI-Labs/incident-data-cleaner.git
cd incident-data-cleaner
pip install -r requirements.txt
pip install -e .
python -m spacy download en_core_web_sm
```

## Usage

```bash
# Process a JSONL file of incidents (no API calls)
python process_incidents.py data/test_samples/rootly_samples.jsonl --llm-simulation

# Real LLM calls — requires API keys in env
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
python process_incidents.py data/test_samples/rootly_samples.jsonl --max-concurrent 5
```

Run `python process_incidents.py --help` for all flags. Results land in `output/<file>_processing_<timestamp>/`.

## Configuration

- **Redaction policy:** `config/policies/default_policy.json` defines categories, sensitivity levels, and actions. Pass a custom one with `--policy path/to/policy.json`.
- **LLM models:** `config/llm_models.json` selects the finder/judge models. Defaults are `gpt-5` (OpenAI) for the finder and `claude-sonnet-4-6` (Anthropic) for the judge; change those strings to use a different model. Keys come from `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`.
- **Confidence threshold:** `--confidence-threshold 0.7` (default) controls when an incident is flagged for human review.

## Database CLI

A SQLite store for tracking processed incidents is available via `db_cli.py` (`load`, `process`, `list`, `get`, `stats`). See [DATABASE_MVP_README.md](DATABASE_MVP_README.md).

## Tests

```bash
make test-all
```

## License

MIT — see [LICENSE](LICENSE).
