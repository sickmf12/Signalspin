"""Deterministic, explainable correlation logic for the Signalspin prototype."""
from __future__ import annotations
from typing import Iterable
from .schemas import SecurityEvent


def correlate_events(events: Iterable[SecurityEvent], window_minutes: int = 15) -> dict:
    """Create a candidate incident from temporally nearby related events.

    The score is a demonstration heuristic, not a calibrated probability.
    """
    ordered = sorted(events, key=lambda event: event.timestamp)
    if not ordered:
        return {
            "incident_id": "INC-0000", "risk_level": "LOW", "risk_score": 0,
            "reasons": ["No events were provided."], "event_ids": [], "timeline": [],
            "limitations": ["No data is available to analyze."]
        }

    window_seconds = window_minutes * 60
    linked_ids: set[str] = set()
    links: set[str] = set()

    for index, left in enumerate(ordered):
        left_keys = set()
        if left.host:
            left_keys.add(("host", left.host.casefold()))
        if left.user:
            left_keys.add(("user", left.user.casefold()))

        for right in ordered[index + 1:]:
            delta = (right.timestamp - left.timestamp).total_seconds()
            if delta > window_seconds:
                break
            right_keys = set()
            if right.host:
                right_keys.add(("host", right.host.casefold()))
            if right.user:
                right_keys.add(("user", right.user.casefold()))
            shared = left_keys & right_keys
            if shared:
                linked_ids.update((left.event_id, right.event_id))
                label = ", ".join(f"{kind}={value}" for kind, value in sorted(shared))
                links.add(f"{left.event_id} <-> {right.event_id}: within {window_minutes} minutes; shared {label}.")

    types = {event.event_type.casefold() for event in ordered}
    descriptions = " ".join(event.description.casefold() for event in ordered)
    score = 0
    reasons = []

    failed = sum(
        1 for event in ordered
        if "failed" in event.event_type.casefold() or "failed login" in event.description.casefold()
    )
    if failed >= 3:
        score += 25
        reasons.append(f"Repeated authentication failures observed ({failed} events).")
    elif failed:
        score += 8
        reasons.append(f"Authentication failure observed ({failed} event).")

    if any("success" in kind and ("login" in kind or "auth" in kind) for kind in types) or "successful login" in descriptions:
        score += 10
        reasons.append("A successful authentication event is present; validate its context.")
    if any(any(term in kind for term in ("process", "powershell", "command")) for kind in types) or "powershell" in descriptions:
        score += 20
        reasons.append("A process or command-execution indicator is present.")
    if any(any(term in kind for term in ("file_access", "file access", "sensitive_file")) for kind in types) or "sensitive folder" in descriptions:
        score += 15
        reasons.append("A file-access indicator is present; confirm expected user activity.")
    if any(any(term in kind for term in ("outbound", "network_connection", "network connection")) for kind in types) or "outbound connection" in descriptions:
        score += 20
        reasons.append("An outbound network-activity indicator is present; inspect destination context.")
    if len(linked_ids) >= 3:
        score += 10
        reasons.append(f"{len(linked_ids)} events participate in host/user-linked pairs inside the time window.")

    score = min(score, 100)
    risk = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    if not reasons:
        reasons.append("No configured indicator matched; this does not prove the activity is benign.")

    timeline = [{
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "host": event.host,
        "user": event.user,
        "description": event.description,
        "linked_by_configured_keys": event.event_id in linked_ids,
    } for event in ordered]

    return {
        "incident_id": "INC-" + ordered[0].timestamp.strftime("%Y%m%d%H%M%S"),
        "risk_level": risk,
        "risk_score": score,
        "score_type": "heuristic; not a probability",
        "window_minutes": window_minutes,
        "reasons": reasons,
        "correlation_links": sorted(links),
        "event_ids": [event.event_id for event in ordered],
        "linked_event_ids": sorted(linked_ids),
        "timeline": timeline,
        "limitations": [
            "Correlation is a lead for analyst review, not proof of compromise.",
            "The score is a demo heuristic and has not been calibrated on labeled data.",
            "Missing telemetry, clock skew, and incomplete identity fields may hide relationships."
        ],
    }
