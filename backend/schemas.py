"""Data models for normalized Signalspin security events."""
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    source: str = Field(min_length=1, max_length=40)
    event_type: str = Field(min_length=1, max_length=80)
    host: Optional[str] = Field(default=None, max_length=255)
    user: Optional[str] = Field(default=None, max_length=255)
    description: str = Field(default="", max_length=2000)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone, preferably UTC")
        return value.astimezone(timezone.utc)


class AnalysisRequest(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=10000)
    window_minutes: int = Field(default=15, ge=1, le=1440)

    @field_validator("events")
    @classmethod
    def event_ids_must_be_unique(cls, events: list[SecurityEvent]) -> list[SecurityEvent]:
        ids = [event.event_id for event in events]
        if len(ids) != len(set(ids)):
            raise ValueError("event_id values must be unique within a request")
        return events
