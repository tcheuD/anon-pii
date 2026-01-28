"""JSON format handler."""

from __future__ import annotations

import json
from typing import Any, Callable


def process_json(
    content: str,
    anonymize_fn: Callable[[str], str],
) -> str:
    """
    Process JSON content, anonymizing string values while preserving structure.

    Args:
        content: JSON string
        anonymize_fn: Function that takes a string and returns anonymized string

    Returns:
        Anonymized JSON string
    """
    data = json.loads(content)
    anonymized = _process_value(data, anonymize_fn)

    original_indent = _detect_indent(content)
    return json.dumps(anonymized, indent=original_indent, ensure_ascii=False)


def _process_value(value: Any, anonymize_fn: Callable[[str], str]) -> Any:
    """Recursively process JSON values."""
    if isinstance(value, str):
        return anonymize_fn(value)
    elif isinstance(value, dict):
        return {k: _process_value(v, anonymize_fn) for k, v in value.items()}
    elif isinstance(value, list):
        return [_process_value(item, anonymize_fn) for item in value]
    else:
        return value


def _detect_indent(content: str) -> int | None:
    """Detect indentation level from JSON content."""
    lines = content.split("\n")
    for line in lines[1:5]:
        stripped = line.lstrip()
        if stripped:
            indent = len(line) - len(stripped)
            if indent > 0:
                return indent
    return 2
