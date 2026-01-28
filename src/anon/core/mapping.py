"""Bidirectional mapping for reversible anonymization."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class AnonymizationMapping:
    """Bidirectional mapping between tokens and original values."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    mappings: dict[str, str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, repr=False)

    def add(self, entity_type: str, original_value: str) -> str:
        """Add a value and return its token. Returns existing token if already mapped."""
        if original_value in self._reverse:
            return self._reverse[original_value]

        counter = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = counter
        token = f"[{entity_type}_{counter}]"

        self.mappings[token] = original_value
        self._reverse[original_value] = token

        return token

    def get_original(self, token: str) -> Optional[str]:
        """Get original value from token."""
        return self.mappings.get(token)

    def get_token(self, original: str) -> Optional[str]:
        """Get token from original value."""
        return self._reverse.get(original)

    def to_json(self, indent: int = 2) -> str:
        """Serialize mapping to JSON."""
        return json.dumps(
            {
                "session_id": self.session_id,
                "created_at": self.created_at,
                "mappings": self.mappings,
            },
            indent=indent,
            ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, json_str: str) -> AnonymizationMapping:
        """Deserialize mapping from JSON."""
        data = json.loads(json_str)
        mapping = cls(
            session_id=data["session_id"],
            created_at=data["created_at"],
            mappings=data["mappings"],
        )
        mapping._reverse = {v: k for k, v in mapping.mappings.items()}
        return mapping

    def save(self, path: Path) -> None:
        """Save mapping to file."""
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> AnonymizationMapping:
        """Load mapping from file."""
        return cls.from_json(path.read_text())

    def restore_text(self, text: str) -> str:
        """Restore original values in text using the mapping."""
        result = text
        for token, original in self.mappings.items():
            result = result.replace(token, original)
        return result

    def __len__(self) -> int:
        return len(self.mappings)
