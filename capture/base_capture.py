"""
Base Capture Module
Abstract base class for all traffic capture implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional, Callable, Generator
from enum import Enum
from datetime import datetime
import threading
import queue

from ..core.packet import Packet, Protocol


class CaptureMode(Enum):
    """Capture mode types."""
    PCAP = "pcap"           # Raw packet capture with scapy
    PROXY = "proxy"         # HTTP/HTTPS proxy
    LOG = "log"             # Log file parsing
    MIDDLEWARE = "middleware"  # Application middleware


class BaseCapturer(ABC):
    """
    Abstract base class for traffic capture implementations.
    
    All capture modules must implement:
    - start(): Begin capturing traffic
    - stop(): Stop capturing traffic  
    - capture_packets(): Generator that yields captured packets
    """
    
    def __init__(self, callback: Optional[Callable[[Packet], None]] = None):
        """
        Initialize the capturer.
        
        Args:
            callback: Optional callback function called for each captured packet
        """
        self.callback = callback
        self._running = False
        self._packet_queue: queue.Queue = queue.Queue()
        self._capture_thread: Optional[threading.Thread] = None
        
    @property
    @abstractmethod
    def mode(self) -> CaptureMode:
        """Return the capture mode type."""
        pass
    
    @abstractmethod
    def start(self) -> None:
        """Start capturing traffic."""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop capturing traffic."""
        pass
    
    @abstractmethod
    def _capture_loop(self) -> None:
        """Internal capture loop - runs in separate thread."""
        pass
    
    def capture_packets(self, timeout: float = 1.0) -> Generator[Packet, None, None]:
        """
        Generator that yields captured packets.
        
        Args:
            timeout: Timeout in seconds for getting packets from queue
            
        Yields:
            Captured Packet objects
        """
        while self._running or not self._packet_queue.empty():
            try:
                packet = self._packet_queue.get(timeout=timeout)
                yield packet
            except queue.Empty:
                continue
    
    def _enqueue_packet(self, packet: Packet) -> None:
        """
        Add a packet to the queue and call callback if set.
        
        Args:
            packet: Packet to enqueue
        """
        self._packet_queue.put(packet)
        if self.callback:
            self.callback(packet)
    
    @staticmethod
    def create_packet(
        source_ip: str,
        destination_port: int,
        protocol: Protocol,
        method: Optional[str] = None,
        path: str = "/",
        headers: dict = None,
        body: str = "",
        query_params: dict = None,
        captured_from: str = "unknown"
    ) -> Packet:
        """
        Helper method to create a Packet with timestamp.
        
        Args:
            source_ip: Source IP address
            destination_port: Destination port number
            protocol: Protocol type
            method: HTTP method
            path: Request path
            headers: Request headers
            body: Request body
            query_params: Query parameters
            captured_from: Source of capture (pcap/proxy/log)
            
        Returns:
            Configured Packet object
        """
        return Packet(
            source_ip=source_ip,
            destination_port=destination_port,
            protocol=protocol,
            method=method,
            path=path,
            headers=headers or {},
            body=body,
            query_params=query_params or {},
            metadata={
                "timestamp": datetime.now().isoformat(),
                "captured_from": captured_from
            }
        )
