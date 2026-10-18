from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.analyzer import correlate_events
from backend.main import app
from backend.schemas import SecurityEvent

client = TestClient(app)


def make_event(event_id, minutes, event_type, host="host-a", user="alex", description=""):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minutes),
        source="TEST",
        event_type=event_type,
        host=host,
        user=user,
        description=description,
    )


def test_empty_input_returns_safe_result():
    result = correlate_events([])
    assert result["event_ids"] == []
    assert result["risk_score"] == 0


def test_repeated_failures_and_followup_activity_are_explained():
    events = [
        make_event("A1", 0, "failed_login"),
        make_event("A2", 1, "failed_login"),
        make_event("A3", 2, "failed_login"),
        make_event("A4", 3, "successful_login"),
        make_event("E1", 4, "process_start", description="powershell.exe launched"),
        make_event("F1", 5, "file_access", description="Sensitive folder read"),
        make_event("N1", 6, "outbound_connection", description="New outbound connection"),
    ]
    result = correlate_events(events, window_minutes=15)
    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] <= 100
    assert "A1" in result["event_ids"]
    assert any("authentication failures" in reason.lower() for reason in result["reasons"])
    assert result["score_type"] == "heuristic; not a probability"


def test_unrelated_events_are_not_linked_only_by_time():
    events = [
        make_event("A", 0, "failed_login", host="host-a", user="alice"),
        make_event("B", 1, "successful_login", host="host-b", user="bob"),
    ]
    result = correlate_events(events)
    assert result["linked_event_ids"] == []


def test_api_health_and_sample_analysis():
    assert client.get("/health").json()["status"] == "ok"
    response = client.post("/analyze/sample")
    assert response.status_code == 200
    assert response.json()["event_ids"]


def test_sample_hash_is_reported():
    response = client.get("/sample/evidence-hash")
    assert response.status_code == 200
    assert len(response.json()["sha256"]) == 64
