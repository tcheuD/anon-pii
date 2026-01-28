"""Custom PII recognizers."""

from anon.recognizers.french import get_french_recognizers
from anon.recognizers.aviation import get_aviation_recognizers

__all__ = ["get_french_recognizers", "get_aviation_recognizers"]
