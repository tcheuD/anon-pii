"""Plain text format handler."""

from __future__ import annotations

from typing import Callable


def process_text(
    content: str,
    anonymize_fn: Callable[[str], str],
) -> str:
    """
    Process plain text content.

    Args:
        content: Plain text string
        anonymize_fn: Function that takes a string and returns anonymized string

    Returns:
        Anonymized text string
    """
    return anonymize_fn(content)
