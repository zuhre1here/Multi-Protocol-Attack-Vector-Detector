"""
Base Analyzer Abstract Class
Defines the interface for all protocol analyzers.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..core.packet import Packet
from ..core.logger import SecurityLogger, get_logger


@dataclass
class AnalysisResult:
    """
    Result of packet analysis.
    
    Attributes:
        is_malicious: Whether the packet contains malicious content
        attack_type: Type of attack detected (if any)
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        details: Detailed description of the finding
        matched_content: The specific malicious content found
        recommendations: List of recommended actions
    """
    is_malicious: bool
    attack_type: Optional[str] = None
    severity: str = "NONE"
    details: str = ""
    matched_content: str = ""
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class BaseAnalyzer(ABC):
    """
    Abstract base class for protocol analyzers.
    
    All protocol-specific analyzers should inherit from this class
    and implement the required methods.
    """
    
    def __init__(self, logger: Optional[SecurityLogger] = None):
        """
        Initialize the analyzer.
        
        Args:
            logger: SecurityLogger instance (uses global if not provided)
        """
        self.logger = logger or get_logger()
        
    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Return the name of the protocol this analyzer handles."""
        pass
    
    @abstractmethod
    def analyze(self, packet: Packet) -> List[AnalysisResult]:
        """
        Analyze a packet for potential attacks.
        
        Args:
            packet: The packet to analyze
            
        Returns:
            List of AnalysisResult objects for each finding
        """
        pass
    
    @abstractmethod
    def can_handle(self, packet: Packet) -> bool:
        """
        Check if this analyzer can handle the given packet.
        
        Args:
            packet: The packet to check
            
        Returns:
            True if this analyzer can process the packet
        """
        pass
    
    def log_finding(self, packet: Packet, result: AnalysisResult):
        """
        Log a security finding.
        
        Args:
            packet: The analyzed packet
            result: The analysis result to log
        """
        if result.is_malicious:
            self.logger.log_attack(
                protocol=self.protocol_name,
                attack_type=result.attack_type or "Unknown",
                source_ip=packet.source_ip,
                malicious_content=result.matched_content,
                severity=result.severity
            )
