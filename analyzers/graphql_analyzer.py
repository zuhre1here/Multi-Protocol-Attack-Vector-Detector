"""
GraphQL Protocol Analyzer
Detects complexity attacks and malicious queries in GraphQL traffic.
"""

import re
import json
from typing import List, Optional, Dict, Any

from .base_analyzer import BaseAnalyzer, AnalysisResult
from ..core.packet import Packet, Protocol
from ..core.logger import SecurityLogger
from ..detectors.sqli_detector import SQLiDetector


class GraphQLAnalyzer(BaseAnalyzer):
    """
    Analyzer for GraphQL traffic.
    
    Detects:
    - Query depth attacks (deeply nested queries)
    - Query complexity attacks (expensive queries)
    - Field duplication attacks
    - Introspection abuse
    - SQLi in variables
    """
    
    # Default thresholds
    DEFAULT_MAX_DEPTH = 10
    DEFAULT_MAX_COMPLEXITY = 1000
    DEFAULT_MAX_ALIASES = 50
    
    def __init__(
        self, 
        logger: Optional[SecurityLogger] = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_complexity: int = DEFAULT_MAX_COMPLEXITY,
        max_aliases: int = DEFAULT_MAX_ALIASES
    ):
        """
        Initialize GraphQL analyzer with configurable thresholds.
        
        Args:
            logger: SecurityLogger instance
            max_depth: Maximum allowed query depth
            max_complexity: Maximum allowed query complexity score
            max_aliases: Maximum allowed field aliases
        """
        super().__init__(logger)
        self.max_depth = max_depth
        self.max_complexity = max_complexity
        self.max_aliases = max_aliases
        self.sqli_detector = SQLiDetector()
        
    @property
    def protocol_name(self) -> str:
        return "GraphQL"
    
    def can_handle(self, packet: Packet) -> bool:
        """Check if packet is GraphQL traffic."""
        if packet.protocol == Protocol.GRAPHQL:
            return True
        
        # Check Content-Type header
        content_type = packet.headers.get("Content-Type", "").lower()
        if "graphql" in content_type:
            return True
        
        # Check for GraphQL-specific paths
        if packet.path and "/graphql" in packet.path.lower():
            return True
        
        # Check body for GraphQL query structure
        if packet.body and ("query" in packet.body or "mutation" in packet.body):
            return True
        
        return False
    
    def analyze(self, packet: Packet) -> List[AnalysisResult]:
        """
        Analyze GraphQL request for attacks.
        
        Args:
            packet: GraphQL packet to analyze
            
        Returns:
            List of detected attacks
        """
        results = []
        
        # Parse the query from the body
        query, variables = self._parse_graphql_body(packet.body)
        
        if not query:
            return results
        
        # Check query depth
        depth_result = self._check_depth(query)
        if depth_result:
            results.append(depth_result)
            self.log_finding(packet, depth_result)
        
        # Check query complexity
        complexity_result = self._check_complexity(query)
        if complexity_result:
            results.append(complexity_result)
            self.log_finding(packet, complexity_result)
        
        # Check for alias abuse
        alias_result = self._check_aliases(query)
        if alias_result:
            results.append(alias_result)
            self.log_finding(packet, alias_result)
        
        # Check for introspection abuse
        introspection_result = self._check_introspection(query)
        if introspection_result:
            results.append(introspection_result)
            self.log_finding(packet, introspection_result)
        
        # Check variables for SQLi
        if variables:
            sqli_results = self._check_variables_sqli(variables)
            for result in sqli_results:
                results.append(result)
                self.log_finding(packet, result)
        
        return results
    
    def _parse_graphql_body(self, body: str) -> tuple:
        """Parse GraphQL query and variables from request body."""
        if not body:
            return None, None
        
        try:
            # Try to parse as JSON (most common format)
            data = json.loads(body)
            query = data.get("query", "")
            variables = data.get("variables", {})
            return query, variables
        except json.JSONDecodeError:
            # Assume the body is a raw GraphQL query
            return body, None
    
    def _calculate_depth(self, query: str) -> int:
        """
        Calculate the depth of a GraphQL query.
        Simple approach: count nested braces.
        """
        max_depth = 0
        current_depth = 0
        
        for char in query:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _calculate_complexity(self, query: str) -> int:
        """
        Calculate query complexity score.
        
        Scoring:
        - Each field: 1 point
        - Each nested level: multiplier
        - Each argument: 2 points
        """
        complexity = 0
        
        # Count fields (words followed by { or (
        fields = re.findall(r'\w+\s*[{(]', query)
        complexity += len(fields) * 2
        
        # Count all field references
        all_fields = re.findall(r'\b\w+\b(?=\s*[:{]|\s+\w|\s*$)', query)
        complexity += len(all_fields)
        
        # Add depth multiplier
        depth = self._calculate_depth(query)
        complexity *= (1 + depth * 0.5)
        
        # Count arguments
        args = re.findall(r'\([^)]+\)', query)
        complexity += len(args) * 3
        
        return int(complexity)
    
    def _count_aliases(self, query: str) -> int:
        """Count the number of aliases in the query."""
        # Aliases are defined as: alias: fieldName
        aliases = re.findall(r'\b\w+\s*:\s*\w+', query)
        return len(aliases)
    
    def _check_depth(self, query: str) -> Optional[AnalysisResult]:
        """Check if query exceeds maximum depth."""
        depth = self._calculate_depth(query)
        
        if depth > self.max_depth:
            return AnalysisResult(
                is_malicious=True,
                attack_type="GraphQL Depth Attack",
                severity="HIGH",
                details=f"Query depth ({depth}) exceeds maximum allowed ({self.max_depth})",
                matched_content=f"Depth: {depth}, Query: {query[:200]}...",
                recommendations=[
                    "Implement query depth limiting",
                    "Consider using persisted queries"
                ]
            )
        return None
    
    def _check_complexity(self, query: str) -> Optional[AnalysisResult]:
        """Check if query exceeds maximum complexity."""
        complexity = self._calculate_complexity(query)
        
        if complexity > self.max_complexity:
            return AnalysisResult(
                is_malicious=True,
                attack_type="GraphQL Complexity Attack",
                severity="HIGH",
                details=f"Query complexity ({complexity}) exceeds maximum allowed ({self.max_complexity})",
                matched_content=f"Complexity: {complexity}, Query: {query[:200]}...",
                recommendations=[
                    "Implement query complexity analysis",
                    "Use query cost limiting",
                    "Consider rate limiting by complexity"
                ]
            )
        return None
    
    def _check_aliases(self, query: str) -> Optional[AnalysisResult]:
        """Check for alias abuse (DoS via field duplication)."""
        alias_count = self._count_aliases(query)
        
        if alias_count > self.max_aliases:
            return AnalysisResult(
                is_malicious=True,
                attack_type="GraphQL Alias Abuse",
                severity="MEDIUM",
                details=f"Excessive aliases detected ({alias_count})",
                matched_content=f"Aliases: {alias_count}",
                recommendations=[
                    "Limit the number of allowed aliases per query",
                    "Monitor for batching attacks"
                ]
            )
        return None
    
    def _check_introspection(self, query: str) -> Optional[AnalysisResult]:
        """Check for introspection queries (potential reconnaissance)."""
        introspection_patterns = [
            r'__schema\s*{',
            r'__type\s*\(',
            r'__typename',
            r'__Schema',
            r'__Type',
        ]
        
        for pattern in introspection_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return AnalysisResult(
                    is_malicious=True,
                    attack_type="GraphQL Introspection",
                    severity="LOW",
                    details="Introspection query detected (potential schema reconnaissance)",
                    matched_content=query[:200],
                    recommendations=[
                        "Disable introspection in production",
                        "Monitor introspection requests"
                    ]
                )
        return None
    
    def _check_variables_sqli(self, variables: Dict[str, Any]) -> List[AnalysisResult]:
        """Check GraphQL variables for SQL injection."""
        results = []
        
        def check_value(key: str, value: Any):
            if isinstance(value, str):
                detections = self.sqli_detector.detect(value)
                for matched, description in detections:
                    results.append(AnalysisResult(
                        is_malicious=True,
                        attack_type="SQLi in GraphQL Variables",
                        severity="CRITICAL",
                        details=f"SQL injection in variable '{key}': {description}",
                        matched_content=f"${key}={matched}",
                        recommendations=["Validate all GraphQL variables server-side"]
                    ))
            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(f"{key}.{k}", v)
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    check_value(f"{key}[{i}]", v)
        
        for key, value in variables.items():
            check_value(key, value)
        
        return results
