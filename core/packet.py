"""
Packet data structure for simulated network traffic.
Represents an incoming network packet with protocol information.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Any
from enum import Enum


class Protocol(Enum):
    """Supported protocol types."""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    GRAPHQL = "GraphQL"
    WEBSOCKET = "WebSocket"
    UNKNOWN = "Unknown"


@dataclass
class Packet:
    """
    Represents a network packet for analysis.
    
    Attributes:
        source_ip: Source IP address of the packet
        destination_port: Destination port number
        protocol: Protocol type (HTTP, GraphQL, WebSocket, etc.)
        method: HTTP method (GET, POST, etc.) or None for non-HTTP
        path: Request path/endpoint
        headers: Dictionary of headers
        body: Request body content
        query_params: Query string parameters
        raw_data: Raw packet data for WebSocket frames
        metadata: Additional metadata for analysis
    """
    source_ip: str
    destination_port: int
    protocol: Protocol = Protocol.UNKNOWN
    method: Optional[str] = None
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    raw_data: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_all_parameters(self) -> Dict[str, str]:
        """
        Get all parameters from query string, body (if form-encoded), and headers.
        Used for comprehensive attack detection.
        """
        params = {}
        
        # Add query parameters
        params.update(self.query_params)
        
        # Add headers
        for key, value in self.headers.items():
            params[f"header:{key}"] = value
        
        # Add body as a parameter
        if self.body:
            params["body"] = self.body
            
        return params
    
    def __str__(self) -> str:
        return (
            f"Packet(src={self.source_ip}, port={self.destination_port}, "
            f"protocol={self.protocol.value}, method={self.method}, path={self.path})"
        )
