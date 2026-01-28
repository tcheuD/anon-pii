"""Format auto-detection."""

from __future__ import annotations

from enum import Enum


class Format(str, Enum):
    """Supported input formats."""
    JSON = "json"
    TEXT = "text"
    SQL = "sql"
    CSV = "csv"


def detect_format(content: str) -> Format:
    """
    Auto-detect the format of the input content.

    Returns:
        Detected format, defaults to TEXT if uncertain.
    """
    stripped = content.strip()

    if not stripped:
        return Format.TEXT

    if stripped.startswith(("{", "[")):
        try:
            import json
            json.loads(stripped)
            return Format.JSON
        except json.JSONDecodeError:
            pass

    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"]
    first_word = stripped.split()[0].upper() if stripped.split() else ""
    if first_word in sql_keywords:
        return Format.SQL

    lines = stripped.split("\n")
    if len(lines) > 1:
        first_line_commas = lines[0].count(",")
        if first_line_commas > 0:
            consistent = all(
                abs(line.count(",") - first_line_commas) <= 1
                for line in lines[:5]
                if line.strip()
            )
            if consistent:
                return Format.CSV

    return Format.TEXT
