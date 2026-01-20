"""
SQL Injection (SQLi) Detector
Detects SQL injection patterns in request parameters.
"""

import re
from typing import List, Tuple, Optional


class SQLiDetector:
    """
    Detects SQL injection attacks using regex pattern matching.
    
    Covers common SQLi patterns including:
    - UNION-based injection
    - Boolean-based blind injection
    - Comment-based bypass
    - Stacked queries
    - Common SQL keywords abuse
    """
    
    # SQL injection patterns with their descriptions (case-insensitive)
    SQLI_PATTERNS = [
        # UNION-based injection
        (r"\bUNION\b.*\bSELECT\b", "UNION SELECT injection"),
        (r"\bUNION\b.*\bALL\b.*\bSELECT\b", "UNION ALL SELECT injection"),
        
        # Boolean-based blind injection
        (r"\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "OR numeric comparison injection"),
        (r"\bOR\b\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+['\"]?", "OR string comparison injection"),
        (r"\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "AND numeric comparison injection"),
        (r"'.*\bOR\b.*'", "Quote-based OR injection"),
        
        # Comment-based bypass
        (r"--\s*$", "SQL comment bypass (double dash)"),
        (r"#\s*$", "SQL comment bypass (hash)"),
        (r"/\*.*\*/", "SQL block comment"),
        
        # Dangerous SQL keywords
        (r"\bDROP\b\s+\b(TABLE|DATABASE|INDEX)\b", "DROP statement injection"),
        (r"\bDELETE\b\s+\bFROM\b", "DELETE statement injection"),
        (r"\bINSERT\b\s+\bINTO\b", "INSERT statement injection"),
        (r"\bUPDATE\b\s+\w+\s+\bSET\b", "UPDATE statement injection"),
        (r"\bEXEC\b\s*\(", "EXEC function call"),
        (r"\bEXECUTE\b\s+", "EXECUTE statement"),
        
        # Information gathering
        (r"\bSELECT\b.*\bFROM\b.*\binformation_schema\b", "Information schema enumeration"),
        (r"\bSELECT\b.*\b(@@version|@@datadir|@@basedir)\b", "MySQL variable extraction"),
        (r"\bSELECT\b.*\bsys\.\b", "System table access"),
        
        # Stacked queries
        (r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b", "Stacked query injection"),
        
        # Time-based blind injection
        (r"\bSLEEP\s*\(\s*\d+\s*\)", "SLEEP function (time-based)"),
        (r"\bBENCHMARK\s*\(", "BENCHMARK function (time-based)"),
        (r"\bWAITFOR\b\s+\bDELAY\b", "WAITFOR DELAY (time-based)"),
        
        # Common payloads
        (r"'\s*OR\s+'1'\s*=\s*'1", "Classic OR '1'='1' injection"),
        (r"1\s*=\s*1", "Tautology injection (1=1)"),
        (r"'\s*;\s*--", "Quote-semicolon-comment injection"),
    ]
    
    def __init__(self):
        """Initialize the SQLi detector with compiled regex patterns."""
        self.compiled_patterns: List[Tuple[re.Pattern, str]] = [
            (re.compile(pattern, re.IGNORECASE), description)
            for pattern, description in self.SQLI_PATTERNS
        ]
        
    def detect(self, content: str) -> List[Tuple[str, str]]:
        """
        Detect SQL injection patterns in content.
        
        Args:
            content: String content to analyze
            
        Returns:
            List of tuples (matched_content, attack_description)
        """
        if not content:
            return []
            
        detections = []
        
        for pattern, description in self.compiled_patterns:
            matches = pattern.findall(content)
            for match in matches:
                matched_text = match if isinstance(match, str) else match[0]
                detections.append((matched_text, description))
                
        return detections
    
    def is_malicious(self, content: str) -> bool:
        """
        Quick check if content contains any SQLi patterns.
        
        Args:
            content: String content to check
            
        Returns:
            True if SQLi patterns detected, False otherwise
        """
        return len(self.detect(content)) > 0
    
    def analyze_parameters(self, params: dict) -> List[Tuple[str, str, str]]:
        """
        Analyze multiple parameters for SQLi.
        
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
