"""
Capture Module Package
Real-world traffic capture modules for the IDS.
"""

from .base_capture import BaseCapturer, CaptureMode
from .pcap_capture import PcapCapturer
from .http_proxy import HTTPProxyCapturer
from .log_parser import LogParser

__all__ = [
    "BaseCapturer",
    "CaptureMode",
    "PcapCapturer",
    "HTTPProxyCapturer",
    "LogParser",
]
