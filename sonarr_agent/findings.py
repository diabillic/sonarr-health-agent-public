from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    key: str  # stable identity, used for notification dedupe and escalation fingerprints
    summary: str
    severity: str = "warning"  # info | warning | error
    resolved: bool = False  # True when the agent fixed it (or would have, in dry run)
    escalate: bool = False  # True when rules can't handle it and the LLM should look
    details: dict[str, Any] = field(default_factory=dict)
