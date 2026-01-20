"""
WebSocket Protocol Analyzer
Detects attacks in WebSocket frame data.
"""

import json
import re
from typing import List, Optional, Any

from .base_analyzer import BaseAnalyzer, AnalysisResult
from ..core.packet import Packet, Protocol
from ..core.logger import SecurityLogger
from ..detectors.xss_detector import XSSDetector
from ..detectors.sqli_detector import SQLiDetector


class WebSocketAnalyzer(BaseAnalyzer):
    """
    Analyzer for WebSocket (WS/WSS) traffic.
    
    Detects:
    - XSS payloads in frame data
    - SQLi in frame data
    - Invalid/malformed JSON data
    - Suspicious binary frame patterns
    - Command injection attempts
    """
    
    # Maximum allowed message size (10 MB)
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024
    
    # Suspicious patterns in WebSocket messages
    SUSPICIOUS_PATTERNS = [
        (r"(?i)\beval\s*\(", "eval() function detected"),
        (r"(?i)\bexec\s*\(", "exec() function detected"),
        (r"(?i)\bsystem\s*\(", "system() call detected"),
        (r"(?i)\bspawn\s*\(", "spawn() call detected"),
        (r"(?i)__proto__", "Prototype pollution attempt"),
        (r"(?i)constructor\s*\[", "Constructor access attempt"),
        (r"(?i)\bprocess\.env\b", "Environment variable access"),
        (r"(?i)\brequire\s*\(", "require() call (code injection)"),
        (r"(?i)\bimport\s*\(", "Dynamic import() call"),
    ]
    
    def __init__(self, logger: Optional[SecurityLogger] = None):
        """Initialize WebSocket analyzer."""
        super().__init__(logger)
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLiDetector()
        self.compiled_patterns = [
            (re.compile(pattern), desc) for pattern, desc in self.SUSPICIOUS_PATTERNS
        ]
        
    @property
    def protocol_name(self) -> str:
        return "WebSocket"
    
    def can_handle(self, packet: Packet) -> bool:
        """Check if packet is WebSocket traffic."""
        if packet.protocol == Protocol.WEBSOCKET:
            return True
        
        # Check for WebSocket upgrade header
        upgrade = packet.headers.get("Upgrade", "").lower()
        if upgrade == "websocket":
            return True
        
        # Check for WebSocket-specific headers
        if "Sec-WebSocket-Key" in packet.headers:
            return True
        
        return False
    
    def analyze(self, packet: Packet) -> List[AnalysisResult]:
        """
        Analyze WebSocket frame data.
        
        Args:
            packet: WebSocket packet to analyze
            
        Returns:
            List of detected attacks
        """
        results = []
        
        # Get frame data (from body or raw_data)
        frame_data = packet.body or packet.raw_data.decode('utf-8', errors='ignore')
        
        if not frame_data:
            return results
        
        # Check message size
        size_result = self._check_size(frame_data)
        if size_result:
            results.append(size_result)
            self.log_finding(packet, size_result)
        
        # Check for XSS
        xss_results = self._check_xss(frame_data)
        for result in xss_results:
            results.append(result)
            self.log_finding(packet, result)
        
        # Check for SQLi
        sqli_results = self._check_sqli(frame_data)
        for result in sqli_results:
            results.append(result)
            self.log_finding(packet, result)
        
        # Check JSON validity and content
        json_results = self._check_json(frame_data)
        for result in json_results:
            results.append(result)
            self.log_finding(packet, result)
        
        # Check for suspicious patterns
        pattern_results = self._check_patterns(frame_data)
        for result in pattern_results:
            results.append(result)
            self.log_finding(packet, result)
        
        return results
    
    def _check_size(self, data: str) -> Optional[AnalysisResult]:
        """Check for oversized messages (potential DoS)."""
        size = len(data.encode('utf-8'))
        
        if size > self.MAX_MESSAGE_SIZE:
            return AnalysisResult(
                is_malicious=True,
                attack_type="WebSocket DoS",
                severity="MEDIUM",
                details=f"Oversized WebSocket message: {size} bytes",
                matched_content=f"Size: {size} bytes",
                recommendations=["Implement message size limits"]
            )
        return None
    
    def _check_xss(self, data: str) -> List[AnalysisResult]:
        """Check for XSS payloads in WebSocket data."""
        results = []
        
        detections = self.xss_detector.detect(data)
        for matched, description in detections:
            results.append(AnalysisResult(
                is_malicious=True,
                attack_type="WebSocket XSS",
                severity="HIGH",
                details=f"XSS payload in WebSocket frame: {description}",
                matched_content=matched,
                recommendations=[
                    "Sanitize WebSocket message content before rendering",
                    "Implement Content Security Policy"
                ]
            ))
        
        return results
    
    def _check_sqli(self, data: str) -> List[AnalysisResult]:
        """Check for SQL injection in WebSocket data."""
        results = []
        
        detections = self.sqli_detector.detect(data)
        for matched, description in detections:
            results.append(AnalysisResult(
                is_malicious=True,
                attack_type="WebSocket SQLi",
                severity="CRITICAL",
                details=f"SQL injection in WebSocket frame: {description}",
                matched_content=matched,
                recommendations=[
                    "Validate WebSocket data before database queries",
                    "Use parameterized queries"
                ]
            ))
        
        return results
    
    def _check_json(self, data: str) -> List[AnalysisResult]:
        """Check JSON structure and content for manipulation."""
        results = []
        
        # Try to parse as JSON
        try:
            parsed = json.loads(data)
            
            # Check for deeply nested JSON (potential DoS)
            depth = self._get_json_depth(parsed)
            if depth > 20:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="WebSocket JSON Depth Attack",
                    severity="MEDIUM",
                    details=f"Deeply nested JSON structure (depth: {depth})",
                    matched_content=data[:200],
                    recommendations=["Limit JSON nesting depth"]
                ))
            
            # Recursively check string values for injections
            self._check_json_values(parsed, results, data)
            
        except json.JSONDecodeError:
            # Not JSON - might be intentionally malformed
            if data.strip().startswith('{') or data.strip().startswith('['):
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="Malformed WebSocket Data",
                    severity="LOW",
                    details="Invalid JSON structure in WebSocket frame",
                    matched_content=data[:200],
                    recommendations=["Validate JSON structure before processing"]
                ))
        
        return results
    
    def _get_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate the maximum depth of a JSON object."""
        if isinstance(obj, dict):
            if not obj:
                return current_depth + 1
            return max(self._get_json_depth(v, current_depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth + 1
            return max(self._get_json_depth(v, current_depth + 1) for v in obj)
        return current_depth
    
    def _check_json_values(self, obj: Any, results: List[AnalysisResult], original_data: str):
        """Recursively check JSON string values for attacks."""
        if isinstance(obj, str):
            # Check for prototype pollution keys
            if obj in ("__proto__", "constructor", "prototype"):
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="WebSocket Prototype Pollution",
                    severity="HIGH",
                    details=f"Prototype pollution attempt: {obj}",
                    matched_content=obj,
                    recommendations=["Sanitize object keys before use"]
                ))
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("__proto__", "constructor", "prototype"):
                    results.append(AnalysisResult(
                        is_malicious=True,
                        attack_type="WebSocket Prototype Pollution",
                        severity="HIGH",
                        details=f"Prototype pollution key: {key}",
                        matched_content=f"Key: {key}",
                        recommendations=["Sanitize object keys"]
                    ))
                self._check_json_values(value, results, original_data)
        elif isinstance(obj, list):
            for item in obj:
                self._check_json_values(item, results, original_data)
    
    def _check_patterns(self, data: str) -> List[AnalysisResult]:
        """Check for suspicious patterns in WebSocket data."""
        results = []
        
        for pattern, description in self.compiled_patterns:
            matches = pattern.findall(data)
            for match in matches:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="WebSocket Suspicious Pattern",
                    severity="MEDIUM",
                    details=description,
                    matched_content=match if isinstance(match, str) else str(match),
                    recommendations=[
                        "Validate and sanitize WebSocket message content",
                        "Implement strict message schema validation"
                    ]
                ))
        
        return results
