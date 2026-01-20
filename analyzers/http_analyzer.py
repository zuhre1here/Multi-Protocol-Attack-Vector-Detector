"""
HTTP/1.1 & HTTP/2 Protocol Analyzer
Detects attacks in HTTP traffic including abnormal methods and malicious headers.
"""

from typing import List, Optional, Set

from .base_analyzer import BaseAnalyzer, AnalysisResult
from ..core.packet import Packet, Protocol
from ..core.logger import SecurityLogger
from ..detectors.sqli_detector import SQLiDetector
from ..detectors.xss_detector import XSSDetector


class HTTPAnalyzer(BaseAnalyzer):
    """
    Analyzer for HTTP/1.1 and HTTP/2 traffic.
    
    Detects:
    - Abnormal HTTP methods (TRACE, CONNECT, DEBUG, etc.)
    - SQLi in parameters and headers
    - XSS in parameters and headers
    - Suspicious header patterns (excessive length, malicious content)
    """
    
    # Standard safe HTTP methods
    SAFE_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    
    # Potentially dangerous methods
    DANGEROUS_METHODS = {"TRACE", "CONNECT", "DEBUG", "TRACK", "COPY", "MOVE", 
                         "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK",
                         "ARBITRARY", "HACK"}
    
    # Maximum allowed header value length
    MAX_HEADER_LENGTH = 8192
    
    # Suspicious header names
    SUSPICIOUS_HEADERS = {"X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
                          "X-Remote-IP", "X-Remote-Addr", "X-Client-IP"}
    
    def __init__(self, logger: Optional[SecurityLogger] = None):
        """Initialize HTTP analyzer with SQLi and XSS detectors."""
        super().__init__(logger)
        self.sqli_detector = SQLiDetector()
        self.xss_detector = XSSDetector()
        
    @property
    def protocol_name(self) -> str:
        return "HTTP"
    
    def can_handle(self, packet: Packet) -> bool:
        """Check if packet is HTTP/HTTPS."""
        return packet.protocol in (Protocol.HTTP, Protocol.HTTPS)
    
    def analyze(self, packet: Packet) -> List[AnalysisResult]:
        """
        Analyze HTTP packet for various attacks.
        
        Args:
            packet: HTTP packet to analyze
            
        Returns:
            List of detected attacks
        """
        results = []
        
        # Check for abnormal methods
        method_result = self._check_method(packet)
        if method_result:
            results.append(method_result)
            self.log_finding(packet, method_result)
        
        # Check header length and content
        header_results = self._check_headers(packet)
        for result in header_results:
            results.append(result)
            self.log_finding(packet, result)
        
        # Check for SQLi in all parameters
        sqli_results = self._check_sqli(packet)
        for result in sqli_results:
            results.append(result)
            self.log_finding(packet, result)
        
        # Check for XSS in all parameters
        xss_results = self._check_xss(packet)
        for result in xss_results:
            results.append(result)
            self.log_finding(packet, result)
        
        return results
    
    def _check_method(self, packet: Packet) -> Optional[AnalysisResult]:
        """Check for abnormal HTTP methods."""
        if not packet.method:
            return None
            
        method = packet.method.upper()
        
        if method in self.DANGEROUS_METHODS:
            return AnalysisResult(
                is_malicious=True,
                attack_type="Abnormal HTTP Method",
                severity="MEDIUM",
                details=f"Dangerous HTTP method detected: {method}",
                matched_content=f"Method: {method}",
                recommendations=[
                    "Block this method at the firewall level",
                    "Review server configuration to disable unnecessary methods"
                ]
            )
        
        if method not in self.SAFE_METHODS:
            return AnalysisResult(
                is_malicious=True,
                attack_type="Unknown HTTP Method",
                severity="LOW",
                details=f"Non-standard HTTP method: {method}",
                matched_content=f"Method: {method}",
                recommendations=["Investigate the purpose of this method"]
            )
        
        return None
    
    def _check_headers(self, packet: Packet) -> List[AnalysisResult]:
        """Check headers for suspicious patterns."""
        results = []
        
        for header_name, header_value in packet.headers.items():
            # Check for excessive length
            if len(header_value) > self.MAX_HEADER_LENGTH:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="Header Overflow Attack",
                    severity="HIGH",
                    details=f"Excessively long header: {header_name} ({len(header_value)} bytes)",
                    matched_content=f"{header_name}: {header_value[:100]}...",
                    recommendations=["Block requests with oversized headers"]
                ))
            
            # Check for SQLi in headers
            sqli_detections = self.sqli_detector.detect(header_value)
            for matched, description in sqli_detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="SQLi in Header",
                    severity="CRITICAL",
                    details=f"SQL injection in header {header_name}: {description}",
                    matched_content=f"{header_name}: {matched}",
                    recommendations=["Block and investigate source IP"]
                ))
            
            # Check for XSS in headers
            xss_detections = self.xss_detector.detect(header_value)
            for matched, description in xss_detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="XSS in Header",
                    severity="HIGH",
                    details=f"XSS payload in header {header_name}: {description}",
                    matched_content=f"{header_name}: {matched}",
                    recommendations=["Sanitize header values before processing"]
                ))
        
        return results
    
    def _check_sqli(self, packet: Packet) -> List[AnalysisResult]:
        """Check all parameters for SQL injection."""
        results = []
        
        # Check query parameters
        for param, value in packet.query_params.items():
            detections = self.sqli_detector.detect(value)
            for matched, description in detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="SQLi",
                    severity="CRITICAL",
                    details=f"SQL injection in query parameter '{param}': {description}",
                    matched_content=f"{param}={matched}",
                    recommendations=[
                        "Use parameterized queries",
                        "Implement input validation",
                        "Block source IP"
                    ]
                ))
        
        # Check body
        if packet.body:
            detections = self.sqli_detector.detect(packet.body)
            for matched, description in detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="SQLi",
                    severity="CRITICAL",
                    details=f"SQL injection in request body: {description}",
                    matched_content=matched,
                    recommendations=["Validate and sanitize request body"]
                ))
        
        return results
    
    def _check_xss(self, packet: Packet) -> List[AnalysisResult]:
        """Check all parameters for XSS."""
        results = []
        
        # Check query parameters
        for param, value in packet.query_params.items():
            detections = self.xss_detector.detect(value)
            for matched, description in detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="XSS",
                    severity="HIGH",
                    details=f"XSS payload in query parameter '{param}': {description}",
                    matched_content=f"{param}={matched}",
                    recommendations=[
                        "Encode output before rendering",
                        "Implement Content Security Policy"
                    ]
                ))
        
        # Check body
        if packet.body:
            detections = self.xss_detector.detect(packet.body)
            for matched, description in detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="XSS",
                    severity="HIGH",
                    details=f"XSS payload in request body: {description}",
                    matched_content=matched,
                    recommendations=["Sanitize user input before storage"]
                ))
        
        # Check path for XSS
        if packet.path:
            detections = self.xss_detector.detect(packet.path)
            for matched, description in detections:
                results.append(AnalysisResult(
                    is_malicious=True,
                    attack_type="XSS in Path",
                    severity="HIGH",
                    details=f"XSS payload in URL path: {description}",
                    matched_content=matched,
                    recommendations=["Validate and encode URL paths"]
                ))
        
        return results
