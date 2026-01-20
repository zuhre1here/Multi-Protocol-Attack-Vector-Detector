"""
PCAP Capture Module
Real-time packet capture using scapy.

IMPORTANT: Requires root/sudo privileges to capture raw packets.

Features:
- Auto-detection of network interfaces
- Interface validation before capture
- Support for all interface types (eth, wlan, enp, wlp, lo)

Usage:
    sudo python3 -m ids.main --capture-pcap                    # Auto-detect interface
    sudo python3 -m ids.main --capture-pcap --interface wlan0  # Specific interface
    sudo python3 -m ids.main --list-interfaces                 # List available
"""

from typing import Optional, Callable, List, Dict
import threading
import os
import re
from urllib.parse import parse_qs, urlparse

from .base_capture import BaseCapturer, CaptureMode
from ..core.packet import Packet, Protocol


# Try to import scapy
try:
    from scapy.all import sniff, TCP, IP, Raw, conf, get_if_list, get_if_addr
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_available_interfaces() -> Dict[str, dict]:
    """
    Get all available network interfaces with their details.
    
    Returns:
        Dictionary of interface name -> details (ip, status, type)
    """
    interfaces = {}
    
    if SCAPY_AVAILABLE:
        try:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    # Determine interface type
                    if iface.startswith(('eth', 'enp', 'ens')):
                        iface_type = "ethernet"
                    elif iface.startswith(('wlan', 'wlp', 'wls')):
                        iface_type = "wifi"
                    elif iface == 'lo':
                        iface_type = "loopback"
                    elif iface.startswith('docker') or iface.startswith('br-'):
                        iface_type = "docker"
                    elif iface.startswith('veth'):
                        iface_type = "virtual"
                    else:
                        iface_type = "other"
                    
                    # Check if interface is up
                    is_up = ip != '0.0.0.0' and ip != ''
                    
                    interfaces[iface] = {
                        "ip": ip if ip else "No IP",
                        "type": iface_type,
                        "is_up": is_up,
                    }
                except:
                    interfaces[iface] = {
                        "ip": "Unknown",
                        "type": "unknown",
                        "is_up": False,
                    }
        except Exception as e:
            pass
    
    # Fallback: Read from /sys/class/net
    if not interfaces:
        try:
            net_path = "/sys/class/net"
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    interfaces[iface] = {
                        "ip": "Unknown",
                        "type": "unknown",
                        "is_up": True,
                    }
        except:
            pass
    
    return interfaces


def get_default_interface() -> Optional[str]:
    """
    Auto-detect the best interface to use.
    
    Priority:
    1. Active WiFi interface (wlan*, wlp*)
    2. Active Ethernet interface (eth*, enp*, ens*)
    3. Any active non-loopback interface
    4. Loopback (lo) as last resort
    
    Returns:
        Interface name or None
    """
    interfaces = get_available_interfaces()
    
    if not interfaces:
        return None
    
    # Priority order
    wifi_interfaces = []
    ethernet_interfaces = []
    other_interfaces = []
    loopback = None
    
    for name, info in interfaces.items():
        if not info.get("is_up", False):
            continue
        
        if info["type"] == "wifi":
            wifi_interfaces.append(name)
        elif info["type"] == "ethernet":
            ethernet_interfaces.append(name)
        elif info["type"] == "loopback":
            loopback = name
        elif info["type"] not in ("docker", "virtual"):
            other_interfaces.append(name)
    
    # Return in priority order
    if wifi_interfaces:
        return wifi_interfaces[0]
    if ethernet_interfaces:
        return ethernet_interfaces[0]
    if other_interfaces:
        return other_interfaces[0]
    if loopback:
        return loopback
    
    # If nothing is up, return first available
    return list(interfaces.keys())[0] if interfaces else None


def print_available_interfaces():
    """Print all available network interfaces."""
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("\n❌ Hiçbir ağ arayüzü bulunamadı!")
        return
    
    print("\n📡 Mevcut Ağ Arayüzleri:")
    print("-" * 55)
    print(f"  {'Interface':<15} {'IP Address':<18} {'Type':<12} {'Status'}")
    print("-" * 55)
    
    for name, info in sorted(interfaces.items()):
        status = "✓ UP" if info.get("is_up") else "✗ DOWN"
        ip = info.get("ip", "Unknown")[:17]
        itype = info.get("type", "unknown")
        print(f"  {name:<15} {ip:<18} {itype:<12} {status}")
    
    print("-" * 55)
    
    default = get_default_interface()
    if default:
        print(f"\n  💡 Önerilen: {default}")
    
    print("\n  Kullanım: sudo python3 -m ids.main --capture-pcap --interface <NAME>")
    print()


def validate_interface(interface: str) -> tuple:
    """
    Validate if an interface exists and is usable.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if interface == "any":
        return True, None
    
    interfaces = get_available_interfaces()
    
    if not interfaces:
        return False, "Hiçbir ağ arayüzü tespit edilemedi."
    
    if interface not in interfaces:
        available = ", ".join(sorted(interfaces.keys()))
        return False, (
            f"'{interface}' arayüzü bulunamadı.\n"
            f"   Mevcut arayüzler: {available}\n"
            f"   Listelemek için: sudo python3 -m ids.main --list-interfaces"
        )
    
    info = interfaces[interface]
    if not info.get("is_up", False) and interface != "lo":
        return False, (
            f"'{interface}' arayüzü aktif değil (DOWN).\n"
            f"   Aktifleştirmek için: sudo ip link set {interface} up"
        )
    
    return True, None


class PcapCapturer(BaseCapturer):
    """
    Real-time packet capture using scapy.
    
    Captures HTTP traffic from network interfaces.
    Requires root/sudo privileges.
    
    Features:
    - Auto-detection of network interfaces
    - Interface validation
    - Support for all interface types
    
    Example:
        capturer = PcapCapturer(interface="wlan0", port=80)
        capturer.start()
        for packet in capturer.capture_packets():
            print(packet)
        capturer.stop()
    """
    
    # Common HTTP ports
    HTTP_PORTS = {80, 8080, 8000, 3000, 5000}
    HTTPS_PORTS = {443, 8443}
    
    def __init__(
        self,
        interface: str = None,  # None = auto-detect
        port: Optional[int] = None,
        bpf_filter: Optional[str] = None,
        callback: Optional[Callable[[Packet], None]] = None,
        verbose: int = 0
    ):
        """
        Initialize PCAP capturer.
        
        Args:
            interface: Network interface (None = auto-detect, "any" = all)
            port: Specific port to filter (None = all HTTP ports)
            bpf_filter: Custom BPF filter string
            callback: Callback for each captured packet
            verbose: Verbosity level (0-3)
        """
        super().__init__(callback)
        
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy kütüphanesi yüklü değil. Lütfen yükleyin:\n"
                "  pip install scapy\n"
                "veya\n"
                "  sudo apt-get install python3-scapy"
            )
        
        # Auto-detect interface if not specified
        if interface is None:
            interface = get_default_interface()
            if interface:
                print(f"  📡 Otomatik tespit: {interface}")
            else:
                raise ValueError(
                    "Aktif ağ arayüzü bulunamadı.\n"
                    "Listelemek için: sudo python3 -m ids.main --list-interfaces"
                )
        
        self.interface = interface
        self.port = port
        self.verbose = verbose
        self.bpf_filter = bpf_filter or self._build_default_filter()
        
    @property
    def mode(self) -> CaptureMode:
        return CaptureMode.PCAP
    
    def _build_default_filter(self) -> str:
        """Build default BPF filter for HTTP traffic."""
        if self.port:
            return f"tcp port {self.port}"
        
        # Capture common HTTP/HTTPS ports
        all_ports = list(self.HTTP_PORTS | self.HTTPS_PORTS)
        port_filter = " or ".join(f"port {p}" for p in all_ports)
        return f"tcp and ({port_filter})"
    
    def start(self) -> None:
        """Start packet capture in background thread."""
        if self._running:
            return
        
        # Validate interface before starting
        is_valid, error_msg = validate_interface(self.interface)
        if not is_valid:
            print(f"\n❌ HATA: {error_msg}")
            return
        
        print(f"  ✓ Interface: {self.interface}")
        print(f"  ✓ Filter: {self.bpf_filter}")
            
        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name=f"PcapCapture-{self.interface}"
        )
        self._capture_thread.start()
        
    def stop(self) -> None:
        """Stop packet capture."""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=2.0)
            
    def _capture_loop(self) -> None:
        """Main capture loop using scapy sniff."""
        try:
            # Suppress scapy warnings
            conf.verb = 0
            
            # Use None for "any" to capture on all interfaces
            iface = self.interface if self.interface != "any" else None
            
            sniff(
                iface=iface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except PermissionError:
            print("\n❌ HATA: Root/sudo yetkisi gerekli!")
            print("   Şu şekilde çalıştırın: sudo python3 -m ids.main --capture-pcap")
            self._running = False
        except OSError as e:
            if "No such device" in str(e):
                print(f"\n❌ HATA: '{self.interface}' arayüzü bulunamadı!")
                print("   Mevcut arayüzleri görmek için: sudo python3 -m ids.main --list-interfaces")
            else:
                print(f"\n❌ Yakalama hatası: {e}")
            self._running = False
        except Exception as e:
            print(f"\n❌ Yakalama hatası: {e}")
            self._running = False
            
    def _process_packet(self, scapy_packet) -> None:
        """Process a captured scapy packet and convert to IDS Packet."""
        if not self._running:
            return
            
        try:
            # Only process TCP packets with payload
            if not scapy_packet.haslayer(TCP) or not scapy_packet.haslayer(IP):
                return
                
            ip_layer = scapy_packet[IP]
            tcp_layer = scapy_packet[TCP]
            
            source_ip = ip_layer.src
            dest_port = tcp_layer.dport
            
            if self.verbose > 2:
                print(f"  📦 Packet: {source_ip} -> port {dest_port}")
            
            # Determine protocol
            if dest_port in self.HTTPS_PORTS:
                protocol = Protocol.HTTPS
            elif dest_port in self.HTTP_PORTS:
                protocol = Protocol.HTTP
            else:
                protocol = Protocol.HTTP
            
            # Extract HTTP data if available
            if scapy_packet.haslayer(HTTPRequest):
                packet = self._parse_http_request(scapy_packet, source_ip, dest_port)
                if packet:
                    self._enqueue_packet(packet)
            elif scapy_packet.haslayer(Raw):
                packet = self._parse_raw_http(scapy_packet, source_ip, dest_port, protocol)
                if packet:
                    self._enqueue_packet(packet)
                    
        except Exception:
            pass
            
    def _parse_http_request(self, scapy_packet, source_ip: str, dest_port: int) -> Optional[Packet]:
        """Parse HTTP request from scapy HTTPRequest layer."""
        try:
            http_layer = scapy_packet[HTTPRequest]
            
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else "GET"
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else "/"
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ""
            
            # Parse query parameters
            query_params = {}
            if "?" in path:
                path_parts = path.split("?", 1)
                path = path_parts[0]
                if len(path_parts) > 1:
                    query_params = {k: v[0] for k, v in parse_qs(path_parts[1]).items()}
            
            # Extract headers
            headers = {"Host": host}
            for field in ["User_Agent", "Content_Type", "Accept", "Cookie"]:
                if hasattr(http_layer, field) and getattr(http_layer, field):
                    header_name = field.replace("_", "-")
                    headers[header_name] = getattr(http_layer, field).decode('utf-8', errors='ignore')
            
            # Get body if POST/PUT
            body = ""
            if scapy_packet.haslayer(Raw) and method in ["POST", "PUT", "PATCH"]:
                body = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Detect GraphQL
            protocol = Protocol.HTTP
            if "/graphql" in path.lower() or "query" in body:
                protocol = Protocol.GRAPHQL
            
            return self.create_packet(
                source_ip=source_ip,
                destination_port=dest_port,
                protocol=protocol,
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_params=query_params,
                captured_from="pcap"
            )
            
        except Exception:
            return None
            
    def _parse_raw_http(
        self, 
        scapy_packet, 
        source_ip: str, 
        dest_port: int,
        protocol: Protocol
    ) -> Optional[Packet]:
        """Parse HTTP from raw TCP payload."""
        try:
            raw_data = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if it looks like HTTP request
            http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            if not any(raw_data.startswith(m + " ") for m in http_methods):
                return None
            
            lines = raw_data.split("\r\n")
            if not lines:
                return None
                
            # Parse request line
            request_line = lines[0].split(" ")
            if len(request_line) < 2:
                return None
                
            method = request_line[0]
            full_path = request_line[1]
            
            # Parse path and query params
            path = full_path
            query_params = {}
            if "?" in full_path:
                path, query_string = full_path.split("?", 1)
                query_params = {k: v[0] for k, v in parse_qs(query_string).items()}
            
            # Parse headers
            headers = {}
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            # Get body
            body = ""
            if body_start > 0 and body_start < len(lines):
                body = "\r\n".join(lines[body_start:])
            
            # Detect GraphQL
            if "/graphql" in path.lower() or ("query" in body and "{" in body):
                protocol = Protocol.GRAPHQL
            
            # Detect WebSocket upgrade
            if headers.get("Upgrade", "").lower() == "websocket":
                protocol = Protocol.WEBSOCKET
            
            return self.create_packet(
                source_ip=source_ip,
                destination_port=dest_port,
                protocol=protocol,
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_params=query_params,
                captured_from="pcap"
            )
            
        except Exception:
            return None


def check_pcap_requirements() -> dict:
    """
    Check if PCAP capture requirements are met.
    
    Returns:
        Dictionary with requirement status
    """
    status = {
        "scapy_installed": SCAPY_AVAILABLE,
        "is_root": os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
        "platform": os.name,
        "interfaces": [],
        "default_interface": None,
        "requirements_met": False,
        "message": ""
    }
    
    if SCAPY_AVAILABLE:
        interfaces = get_available_interfaces()
        status["interfaces"] = list(interfaces.keys())
        status["default_interface"] = get_default_interface()
    
    if not SCAPY_AVAILABLE:
        status["message"] = (
            "scapy kütüphanesi gerekli. Yüklemek için:\n"
            "  pip install scapy"
        )
    elif not status["is_root"]:
        status["message"] = (
            "Root yetkisi gerekli. Şu şekilde çalıştırın:\n"
            "  sudo python3 -m ids.main --capture-pcap"
        )
    elif not status["interfaces"]:
        status["message"] = "Aktif ağ arayüzü bulunamadı."
    else:
        status["requirements_met"] = True
        status["message"] = f"Hazır. Varsayılan arayüz: {status['default_interface']}"
    
    return status
