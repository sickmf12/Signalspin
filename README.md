# Signalspin
### Evidence-Linked Incident Reconstruction

Signalspin is a prototype investigation workspace for connecting security events from authentication, endpoint, file-audit, and network logs into an evidence-linked incident timeline.

The initial version deliberately uses deterministic, inspectable rules. It is an analyst-assistance tool, not an autonomous incident-response system.

## What works in this starter
- Normalize structured security events into a common schema.
- Correlate events by host, user, and configurable time window.
- Assign a transparent, rule-based risk score with reasons.
- Keep source event IDs available for review.
- Compute SHA-256 hashes for evidence files.
- FastAPI endpoints for health, sample events, and incident analysis.
- Synthetic example data and automated tests.

## Project structure
```text
Signalspin/
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── analyzer.py
│   └── schemas.py
├── data/sample_events.csv
├── docs/architecture.md
├── tests/test_analyzer.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Run locally
Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000/docs for interactive API documentation.

Try:
```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/analyze/sample
pytest -q
```

## Event fields
Each event includes an event ID, timezone-aware timestamp, source, event type, host, user, and description. Event IDs must be unique within an analysis request.

## Important limitations
- Included events are synthetic and for demonstration only.
- Correlation is a lead for analyst review, not proof of compromise.
- SHA-256 detects whether a file differs from a recorded digest; it does not prove authenticity, origin, or legal chain of custody.
- No blocking, containment, or external network actions are performed.
- No accuracy claims are made until the tool is evaluated on a documented, labeled dataset.

## Roadmap
1. Add parsers for selected log formats and clock-skew handling.
2. Build a visual timeline and relationship graph.
3. Add evidence provenance and analyst notes to exported reports.
4. Evaluate precision and false-positive rates on controlled scenarios.

## License
No license has been selected yet. Until one is added, do not assume this repository grants permission to reuse the code.
