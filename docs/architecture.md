# Signalspin Architecture Notes

## Goal
Turn fragmented security telemetry into an ordered, reviewable set of event relationships. Each candidate relationship should be explainable using shared fields and a configurable time window.

## Data flow
1. **Input** — CSV/JSON events from a controlled lab or synthetic dataset.
2. **Validation** — require unique event IDs, timezone-aware timestamps, source and event type. Keep raw input files unchanged.
3. **Normalization** — map records to the common `SecurityEvent` schema.
4. **Correlation** — compare events inside a time window and create links only when host or user keys match.
5. **Scoring** — apply documented indicator weights. The score is a heuristic, not a probability or verdict.
6. **Review** — an analyst inspects the timeline and reasons before escalation.
7. **Integrity check** — calculate a SHA-256 digest. Store it somewhere trusted if it will be used to detect later changes.

## Current prototype
The API is implemented with FastAPI. It returns a sorted timeline, reason strings, candidate links, and limitations. Synthetic sample data demonstrates repeated authentication failures followed by endpoint, file, and network events.

## Security and reliability boundaries
- Do not ingest private or production logs into a public demo without authorization and data minimization.
- A SHA-256 digest is not proof of provenance, lawful collection, or chain of custody.
- Time proximity and shared identifiers are weak signals; account for shared hosts, service accounts, and clock skew.
- A rule-based risk score needs labeled evaluation before operational use.
- The prototype has no blocking, containment, or automatic response capability.

## Next milestones
- Parsers with source-specific mapping and parse-error reporting.
- Persistent case storage and analyst notes.
- Graph visualization with edge provenance and timestamps.
- PDF/CSV report export and evidence manifest.
- Tests for timezone offsets, malformed records, duplicate IDs, and false-positive scenarios.
- Evaluation report with data description, precision/recall, false-positive rate, and limitations.
