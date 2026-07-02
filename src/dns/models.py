from __future__ import annotations

from pydantic import BaseModel, Field


class DNSResult(BaseModel):
    """Pydantic model representing outputs of DNS resolution queries."""

    domain: str
    ips: list[str] = Field(default_factory=list)
    resolved: bool = False
