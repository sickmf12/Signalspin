"""TRACE-X HTTP API."""
import csv
import hashlib
from pathlib import Path
from fastapi import FastAPI, HTTPException
from .analyzer import correlate_events
from .schemas import AnalysisRequest, SecurityEvent

app = FastAPI(
    title="TRACE-X API",
    description="Evidence-linked security event correlation prototype.",
    version="0.1.0",
)
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "sample_events.csv"


def load_sample_events() -> list[SecurityEvent]:
    try:
        with DATA_FILE.open("r", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        return [SecurityEvent.model_validate(row) for row in rows]
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"Unable to load sample data: {exc}") from exc


@app.get("/", tags=["status"])
def root() -> dict:
    return {"name": "TRACE-X API", "version": "0.1.0", "docs": "/docs"}


@app.get("/health", tags=["status"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/sample/events", tags=["demo"])
def sample_events() -> dict:
    events = load_sample_events()
    return {"count": len(events), "events": [event.model_dump(mode="json") for event in events]}


@app.get("/sample/evidence-hash", tags=["demo"])
def sample_evidence_hash() -> dict:
    """Return a digest of sample data; this is not a chain-of-custody claim."""
    try:
        digest = hashlib.sha256(DATA_FILE.read_bytes()).hexdigest()
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Unable to read sample evidence file") from exc
    return {
        "file": DATA_FILE.name, "algorithm": "SHA-256", "sha256": digest,
        "note": "Detects changes relative to a trusted recorded digest; does not prove origin or collection history."
    }


@app.post("/analyze", tags=["analysis"])
def analyze(request: AnalysisRequest) -> dict:
    return correlate_events(request.events, request.window_minutes)


@app.post("/analyze/sample", tags=["analysis"])
def analyze_sample() -> dict:
    return correlate_events(load_sample_events(), window_minutes=15)
