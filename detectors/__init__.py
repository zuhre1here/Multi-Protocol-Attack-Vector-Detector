"""Attack detectors package."""

from .sqli_detector import SQLiDetector
from .xss_detector import XSSDetector

__all__ = ['SQLiDetector', 'XSSDetector']
