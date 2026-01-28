"""Format detection and handling."""

from anon.formats.detector import detect_format, Format
from anon.formats.json_handler import process_json
from anon.formats.text_handler import process_text

__all__ = ["detect_format", "Format", "process_json", "process_text"]
