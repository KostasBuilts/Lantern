"""Event schema (the contract from Doc 0 section 5)."""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class Event(BaseModel):
    # Unknown detail fields are allowed (forward-compatible); top-level ones are required by shape.
    model_config = ConfigDict(extra="ignore")
    ts: str
    src: str                                   # net | endpoint | gateway
    host: str
    user: str
    kind: str                                  # dns|tls|flow|local_ai|file_open|usb_copy|prompt
    app: Optional[str] = "unknown"
    detail: dict[str, Any] = Field(default_factory=dict)
    score: float = 0.0
    action: str = "observe"


class TriageUpdate(BaseModel):
    status: str                                # ack | resolved | open
    note: Optional[str] = None


class SanctionUpdate(BaseModel):
    sanctioned: bool
