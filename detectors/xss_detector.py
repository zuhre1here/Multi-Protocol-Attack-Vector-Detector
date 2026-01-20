"""
Cross-Site Scripting (XSS) Detector
Detects XSS payloads in request content.
"""

import re
from typing import List, Tuple
import html


class XSSDetector:
    """
    Detects Cross-Site Scripting (XSS) attacks using pattern matching.
    
    Covers:
    - Reflected XSS
    - Stored XSS payloads
    - DOM-based XSS patterns
    - Encoded payloads (HTML entities, URL encoding)
    """
    
    # XSS patterns with descriptions (case-insensitive)
    XSS_PATTERNS = [
        # Script tags
        (r"<\s*script[^>]*>", "Script tag injection"),
        (r"</\s*script\s*>", "Script tag closing"),
        (r"<\s*script[^>]*>.*</\s*script\s*>", "Complete script block"),
        
        # Event handlers
        (r"\bon\w+\s*=", "Event handler attribute (onXXX=)"),
        (r"\bonerror\s*=", "onerror event handler"),
        (r"\bonload\s*=", "onload event handler"),
        (r"\bonclick\s*=", "onclick event handler"),
        (r"\bonmouseover\s*=", "onmouseover event handler"),
        (r"\bonfocus\s*=", "onfocus event handler"),
        (r"\bonsubmit\s*=", "onsubmit event handler"),
        
        # JavaScript protocol
        (r"javascript\s*:", "JavaScript protocol handler"),
        (r"vbscript\s*:", "VBScript protocol handler"),
        (r"data\s*:\s*text/html", "Data URI with HTML"),
        
        # Dangerous HTML tags
        (r"<\s*iframe[^>]*>", "iframe injection"),
        (r"<\s*embed[^>]*>", "embed tag injection"),
        (r"<\s*object[^>]*>", "object tag injection"),
        (r"<\s*svg[^>]*\s+onload\s*=", "SVG with onload"),
        (r"<\s*img[^>]*\s+onerror\s*=", "img with onerror"),
        (r"<\s*body[^>]*\s+onload\s*=", "body with onload"),
        (r"<\s*input[^>]*\s+onfocus\s*=", "input with onfocus"),
        (r"<\s*marquee[^>]*\s+onstart\s*=", "marquee with onstart"),
        (r"<\s*video[^>]*\s+onerror\s*=", "video with onerror"),
        (r"<\s*audio[^>]*\s+onerror\s*=", "audio with onerror"),
        
        # Expression and eval
        (r"\beval\s*\(", "eval() function call"),
        (r"\bexpression\s*\(", "CSS expression()"),
        (r"\bsetTimeout\s*\(", "setTimeout() call"),
        (r"\bsetInterval\s*\(", "setInterval() call"),
        (r"\bFunction\s*\(", "Function constructor"),
        
        # Document/window access
        (r"document\s*\.\s*cookie", "document.cookie access"),
        (r"document\s*\.\s*write", "document.write()"),
        (r"document\s*\.\s*location", "document.location access"),
        (r"window\s*\.\s*location", "window.location access"),
        (r"document\s*\.\s*domain", "document.domain access"),
        
        # Encoded patterns
        (r"&#x?[0-9a-f]+;", "HTML entity encoding"),
        (r"%3c\s*script", "URL encoded script tag"),
        (r"%3c\s*img", "URL encoded img tag"),
        (r"\\u003c", "Unicode escaped <"),
        (r"\\x3c", "Hex escaped <"),
        
        # Alert/prompt/confirm (common testing payloads)
        (r"\balert\s*\(", "alert() call"),
        (r"\bprompt\s*\(", "prompt() call"),
        (r"\bconfirm\s*\(", "confirm() call"),
    ]
    
    def __init__(self):
        """Initialize the XSS detector with compiled patterns."""
        self.compiled_patterns: List[Tuple[re.Pattern, str]] = [
            (re.compile(pattern, re.IGNORECASE), description)
            for pattern, description in self.XSS_PATTERNS
        ]
        
    def detect(self, content: str) -> List[Tuple[str, str]]:
        """
        Detect XSS patterns in content.
        
        Args:
            content: String content to analyze
            
        Returns:
            List of tuples (matched_content, attack_description)
        """
        if not content:
            return []
            
        detections = []
        
        # Check original content
        self._check_patterns(content, detections)
        
        # Check HTML decoded content
        try:
            decoded = html.unescape(content)
            if decoded != content:
                self._check_patterns(decoded, detections, prefix="Decoded: ")
        except Exception:
            pass
            
        # Check URL decoded content
        try:
            from urllib.parse import unquote
            url_decoded = unquote(content)
            if url_decoded != content:
                self._check_patterns(url_decoded, detections, prefix="URL Decoded: ")
        except Exception:
            pass
            
        # Remove duplicates while preserving order
        seen = set()
        unique_detections = []
        for item in detections:
            if item not in seen:
                seen.add(item)
                unique_detections.append(item)
                
        return unique_detections
    
    def _check_patterns(
        self, 
        content: str, 
        detections: List[Tuple[str, str]], 
        prefix: str = ""
    ):
        """Check content against all patterns and add to detections list."""
        for pattern, description in self.compiled_patterns:
            matches = pattern.findall(content)
            for match in matches:
                matched_text = match if isinstance(match, str) else str(match)
                detections.append((matched_text, f"{prefix}{description}"))
    
    def is_malicious(self, content: str) -> bool:
        """
        Quick check if content contains any XSS patterns.
        
        Args:
            content: String content to check
            
        Returns:
            True if XSS patterns detected, False otherwise
        """
        return len(self.detect(content)) > 0
    
    def analyze_parameters(self, params: dict) -> List[Tuple[str, str, str]]:
        """
        Analyze multiple parameters for XSS.
        
        Args:
            params: Dictionary of parameter names to values
            
        Returns:
            List of tuples (param_name, matched_content, attack_description)
        """
        results = []
        
        for param_name, param_value in params.items():
            if isinstance(param_value, str):
                detections = self.detect(param_value)
                for matched, description in detections:
                    results.append((param_name, matched, description))
                    
        return results
