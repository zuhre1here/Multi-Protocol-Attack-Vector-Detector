"""
Central Dispatcher
Routes incoming packets to appropriate protocol analyzers.
"""

from typing import List, Dict, Optional, Type

from .packet import Packet, Protocol
from .logger import SecurityLogger, get_logger
from ..analyzers.base_analyzer import BaseAnalyzer, AnalysisResult
from ..analyzers.http_analyzer import HTTPAnalyzer
from ..analyzers.graphql_analyzer import GraphQLAnalyzer
from ..analyzers.websocket_analyzer import WebSocketAnalyzer


class Dispatcher:
    """
    Central dispatcher that routes packets to appropriate analyzers.
    
    Determines protocol based on:
    1. Explicit protocol field in packet
    2. Destination port
    3. Header inspection (Content-Type, Upgrade, etc.)
    """
    
    # Port to protocol mapping
    PORT_PROTOCOL_MAP = {
        80: Protocol.HTTP,
        443: Protocol.HTTPS,
        8080: Protocol.HTTP,
        8443: Protocol.HTTPS,
        4000: Protocol.GRAPHQL,  # Common GraphQL port
        3000: Protocol.HTTP,     # Dev server
        5000: Protocol.HTTP,     # Flask default
        8000: Protocol.HTTP,     # Django default
    }
    
    # WebSocket ports
    WEBSOCKET_PORTS = {8080, 8081, 9000, 3001}
    
    def __init__(self, logger: Optional[SecurityLogger] = None):
        """
        Initialize the dispatcher with analyzers.
        
        Args:
            logger: SecurityLogger instance
        """
        self.logger = logger or get_logger()
        
        # Initialize analyzers
        self.analyzers: List[BaseAnalyzer] = [
            HTTPAnalyzer(self.logger),
            GraphQLAnalyzer(self.logger),
            WebSocketAnalyzer(self.logger),
        ]
        
        self.logger.log_system("Dispatcher initialized with analyzers: " + 
                              ", ".join(a.protocol_name for a in self.analyzers))
        
    def add_analyzer(self, analyzer: BaseAnalyzer):
        """
        Add a custom analyzer to the dispatcher.
        
        Args:
            analyzer: Analyzer instance to add
        """
        self.analyzers.append(analyzer)
        self.logger.log_info(f"Added analyzer: {analyzer.protocol_name}")
        
    def detect_protocol(self, packet: Packet) -> Protocol:
        """
        Detect the protocol of a packet.
        
        Args:
            packet: Packet to analyze
            
        Returns:
            Detected protocol
        """
        # Use explicit protocol if set
        if packet.protocol != Protocol.UNKNOWN:
            return packet.protocol
        
        # Check headers for WebSocket upgrade
        upgrade = packet.headers.get("Upgrade", "").lower()
        if upgrade == "websocket":
            return Protocol.WEBSOCKET
        
        if "Sec-WebSocket-Key" in packet.headers:
            return Protocol.WEBSOCKET
        
        # Check Content-Type for GraphQL
        content_type = packet.headers.get("Content-Type", "").lower()
        if "graphql" in content_type:
            return Protocol.GRAPHQL
        
        # Check path for GraphQL
        if packet.path and "/graphql" in packet.path.lower():
            return Protocol.GRAPHQL
        
        # Check body for GraphQL patterns
        if packet.body:
            if '"query"' in packet.body or '"mutation"' in packet.body:
                try:
                    import json
                    data = json.loads(packet.body)
                    if "query" in data or "mutation" in data:
                        return Protocol.GRAPHQL
                except (json.JSONDecodeError, ValueError):
                    pass
        
        # Check port mapping
        if packet.destination_port in self.WEBSOCKET_PORTS:
            # Could be WebSocket, but need more context
            connection = packet.headers.get("Connection", "").lower()
            if "upgrade" in connection:
                return Protocol.WEBSOCKET
        
        if packet.destination_port in self.PORT_PROTOCOL_MAP:
            return self.PORT_PROTOCOL_MAP[packet.destination_port]
        
        # Default to HTTP for standard web ports
        if packet.destination_port in (80, 443, 8080, 8443):
            return Protocol.HTTPS if packet.destination_port in (443, 8443) else Protocol.HTTP
        
        return Protocol.UNKNOWN
    
    def dispatch(self, packet: Packet) -> List[AnalysisResult]:
        """
        Dispatch a packet to appropriate analyzers and collect results.
        
        Args:
            packet: Packet to analyze
            
        Returns:
            List of analysis results from all applicable analyzers
        """
        # Detect protocol if not already set
        if packet.protocol == Protocol.UNKNOWN:
            packet.protocol = self.detect_protocol(packet)
        
        results = []
        handled = False
        
        # Try each analyzer
        for analyzer in self.analyzers:
            if analyzer.can_handle(packet):
                handled = True
                try:
                    analyzer_results = analyzer.analyze(packet)
                    results.extend(analyzer_results)
                except Exception as e:
                    self.logger.log_info(
                        f"Error in {analyzer.protocol_name} analyzer: {str(e)}"
                    )
        
        if not handled:
            self.logger.log_info(
                f"No analyzer for packet: {packet.protocol.value} from {packet.source_ip}"
            )
        
        return results
    
    def process_batch(self, packets: List[Packet]) -> Dict[str, List[AnalysisResult]]:
        """
        Process a batch of packets.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            Dictionary mapping source IPs to their analysis results
        """
        results_by_ip: Dict[str, List[AnalysisResult]] = {}
        
        for packet in packets:
            results = self.dispatch(packet)
            if results:
                if packet.source_ip not in results_by_ip:
                    results_by_ip[packet.source_ip] = []
                results_by_ip[packet.source_ip].extend(results)
        
        return results_by_ip
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded analyzers."""
        return {
            "total_analyzers": len(self.analyzers),
            "analyzer_types": [a.protocol_name for a in self.analyzers]
        }
