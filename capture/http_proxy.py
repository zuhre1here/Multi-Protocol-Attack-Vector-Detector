"""
HTTP Proxy Capture Module
Captures HTTP traffic by acting as a proxy server.

No root privileges required for ports > 1024.

Features:
- Multiple port listening
- Interface selection
- HTTP/HTTPS tunneling
- Real-time request analysis
- Graceful shutdown
- Port conflict handling

Usage:
    python3 -m ids.main --capture-proxy --port 8888
    python3 -m ids.main --capture-proxy --ports 8080,8443,8888
    sudo python3 -m ids.main --capture-proxy --ports 80,443  # Root gerekli
    
    Then configure browser/curl to use proxy:
    curl -x http://localhost:8888 http://target.com/api?id=1
"""

from typing import Optional, Callable, List
import threading
import socket
import select
import os
import sys
import signal
import atexit
from urllib.parse import urlparse, parse_qs

from .base_capture import BaseCapturer, CaptureMode
from ..core.packet import Packet, Protocol


# Try to import netifaces (optional)
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


# Privileged ports (require root on Linux)
PRIVILEGED_PORT_LIMIT = 1024


def is_root() -> bool:
    """Check if running as root/administrator."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows doesn't have geteuid
        return False


def is_port_available(host: str, port: int) -> bool:
    """Check if a port is available for binding."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.close()
        return True
    except OSError:
        return False


def check_port_requirements(ports: List[int]) -> dict:
    """
    Check port requirements and permissions.
    
    Returns:
        Dictionary with status information
    """
    privileged_ports = [p for p in ports if p < PRIVILEGED_PORT_LIMIT]
    unprivileged_ports = [p for p in ports if p >= PRIVILEGED_PORT_LIMIT]
    
    needs_root = len(privileged_ports) > 0 and not is_root()
    
    return {
        "privileged_ports": privileged_ports,
        "unprivileged_ports": unprivileged_ports,
        "needs_root": needs_root,
        "is_root": is_root(),
    }


class HTTPProxyCapturer(BaseCapturer):
    """
    HTTP Proxy that captures and analyzes traffic.
    
    Acts as a transparent HTTP proxy server.
    Does NOT require root privileges for ports >= 1024.
    
    Features:
    - Multiple port support
    - Interface selection  
    - HTTPS tunneling (CONNECT method)
    - Real-time request analysis
    - Graceful shutdown
    - Port conflict handling
    
    Example:
        capturer = HTTPProxyCapturer(host="0.0.0.0", ports=[8888, 8889])
        capturer.start()
        for packet in capturer.capture_packets():
            print(packet)
        capturer.stop()
    """
    
    BUFFER_SIZE = 65536
    
    # Default unprivileged ports (don't require root)
    DEFAULT_PORTS = [8888]
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        ports: int | List[int] = None,
        callback: Optional[Callable[[Packet], None]] = None,
        verbose: int = 0,
        skip_unavailable: bool = True
    ):
        """
        Initialize HTTP Proxy capturer.
        
        Args:
            host: Host/interface to bind proxy server
            ports: Port(s) to listen on - can be single int or list
            callback: Callback for each captured packet
            verbose: Verbosity level (0-3)
            skip_unavailable: Skip ports that can't be bound (default: True)
        """
        super().__init__(callback)
        self.host = host
        
        # Handle ports - use defaults if not specified
        if ports is None:
            self.ports = self.DEFAULT_PORTS.copy()
        elif isinstance(ports, int):
            self.ports = [ports]
        else:
            self.ports = list(ports)
        
        self.verbose = verbose
        self.skip_unavailable = skip_unavailable
        self._server_sockets: List[socket.socket] = []
        self._listen_threads: List[threading.Thread] = []
        self._active_ports: List[int] = []
        self._shutdown_event = threading.Event()
        
        # Register cleanup on exit
        atexit.register(self._cleanup)
        
    @property
    def mode(self) -> CaptureMode:
        return CaptureMode.PROXY
    
    def _check_privileges(self) -> bool:
        """Check and warn about privilege requirements."""
        req = check_port_requirements(self.ports)
        
        if req["needs_root"]:
            print(f"\n⚠️  UYARI: Port {req['privileged_ports']} için root/sudo yetkisi gerekli!")
            print(f"   Çözüm 1: sudo python3 -m ids.main --capture-proxy --ports {','.join(map(str, req['privileged_ports']))}")
            print(f"   Çözüm 2: Yüksek portları kullanın: --ports 8080,8443,8888")
            
            if self.skip_unavailable and req["unprivileged_ports"]:
                print(f"\n   → Sadece şu portlar kullanılacak: {req['unprivileged_ports']}")
                self.ports = req["unprivileged_ports"]
                return True
            elif not req["unprivileged_ports"]:
                print("\n   ❌ Kullanılabilir port yok!")
                return False
        
        return True
    
    def start(self) -> None:
        """Start the proxy server on all specified ports."""
        if self._running:
            return
        
        # Check privileges first
        if not self._check_privileges():
            return
        
        if not self.ports:
            print("❌ Hiçbir port belirtilmedi!")
            return
            
        self._running = True
        self._shutdown_event.clear()
        
        print(f"✓ HTTP Proxy başlatılıyor - {self.host}")
        
        for port in self.ports:
            try:
                # Create server socket with reuse options
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Try SO_REUSEPORT if available (Linux 3.9+)
                try:
                    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass  # Not available on this platform
                
                server_socket.bind((self.host, port))
                server_socket.listen(100)
                server_socket.settimeout(1.0)
                
                self._server_sockets.append(server_socket)
                self._active_ports.append(port)
                
                # Start listener thread for this port
                thread = threading.Thread(
                    target=self._listen_loop,
                    args=(server_socket, port),
                    daemon=True,
                    name=f"ProxyListener-{port}"
                )
                self._listen_threads.append(thread)
                thread.start()
                
                print(f"  ✓ Port {port} dinleniyor")
                
            except PermissionError:
                if port < PRIVILEGED_PORT_LIMIT:
                    print(f"  ❌ Port {port}: Root yetkisi gerekli (sudo kullanın)")
                else:
                    print(f"  ❌ Port {port}: İzin reddedildi")
                    
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    print(f"  ❌ Port {port}: Zaten kullanımda")
                    if self.verbose > 0:
                        print(f"     → Kontrol: lsof -i :{port} veya netstat -tlnp | grep {port}")
                else:
                    print(f"  ❌ Port {port}: {e}")
        
        if self._active_ports:
            print(f"\n  📡 Aktif portlar: {self._active_ports}")
            print(f"\n  Proxy kullanımı:")
            for port in self._active_ports:
                print(f"    curl -x http://{self.host}:{port} http://hedef.com/")
            print(f"\n  Durdurmak için: Ctrl+C")
        else:
            print("\n  ❌ Hiçbir port açılamadı!")
            self._running = False
        
    def stop(self) -> None:
        """Stop the proxy server gracefully."""
        if not self._running:
            return
            
        if self.verbose > 0:
            print("\n🛑 Proxy kapatılıyor...")
            
        self._running = False
        self._shutdown_event.set()
        
        self._cleanup()
        
        if self.verbose > 0:
            print("✓ Proxy kapatıldı")
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        # Close all server sockets
        for sock in self._server_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                sock.close()
            except:
                pass
        
        # Wait for threads to finish
        for thread in self._listen_threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        
        self._server_sockets.clear()
        self._listen_threads.clear()
        self._active_ports.clear()
    
    def _capture_loop(self) -> None:
        """
        Internal capture loop - required by base class.
        For HTTPProxyCapturer, the actual capture is done by _listen_loop threads.
        """
        # HTTPProxyCapturer uses multiple threads via _listen_loop
        pass
    
    def _listen_loop(self, server_socket: socket.socket, port: int) -> None:
        """Main proxy server loop for a single port."""
        while self._running and not self._shutdown_event.is_set():
            try:
                client_socket, client_addr = server_socket.accept()
                client_socket.settimeout(10.0)
                
                if self.verbose > 1:
                    print(f"  🔗 Bağlantı: {client_addr[0]}:{client_addr[1]} -> :{port}")
                
                # Handle each connection in a separate thread
                handler_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_addr[0], port),
                    daemon=True
                )
                handler_thread.start()
                
            except socket.timeout:
                continue
            except OSError as e:
                if self._running and e.errno not in (9, 22):  # Bad file descriptor, Invalid argument
                    if self.verbose > 0:
                        print(f"⚠ Proxy hata (port {port}): {e}")
                break
                    
    def _handle_client(
        self,
        client_socket: socket.socket,
        client_ip: str,
        listen_port: int
    ) -> None:
        """Handle a single client connection."""
        server_socket = None
        try:
            # Receive request from client
            request_data = client_socket.recv(self.BUFFER_SIZE)
            if not request_data:
                return
                
            request_str = request_data.decode('utf-8', errors='ignore')
            
            # Parse and analyze the request
            packet = self._parse_request(request_str, client_ip, listen_port)
            if packet:
                self._enqueue_packet(packet)
            
            # Extract target host and port
            target_host, target_port, modified_request = self._extract_target(request_str)
            if not target_host:
                return
            
            # Handle CONNECT method (HTTPS tunneling)
            if request_str.startswith("CONNECT"):
                self._handle_connect(client_socket, target_host, target_port)
                return
            
            # Forward request to target server
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(10.0)
                server_socket.connect((target_host, target_port))
                server_socket.sendall(modified_request.encode('utf-8'))
                
                # Receive and forward response
                while True:
                    response = server_socket.recv(self.BUFFER_SIZE)
                    if not response:
                        break
                    client_socket.sendall(response)
                    
            except Exception as e:
                if self.verbose > 0:
                    print(f"  ⚠ Forward hatası ({target_host}): {e}")
                error_response = f"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy Error: {e}"
                try:
                    client_socket.sendall(error_response.encode())
                except:
                    pass
                
        except Exception as e:
            if self.verbose > 1:
                print(f"  ⚠ Client hatası: {e}")
        finally:
            try:
                if server_socket:
                    server_socket.close()
            except:
                pass
            try:
                client_socket.close()
            except:
                pass
                
    def _handle_connect(
        self, 
        client_socket: socket.socket, 
        target_host: str, 
        target_port: int
    ) -> None:
        """Handle HTTPS CONNECT tunneling."""
        server_socket = None
        try:
            # Connect to target
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10.0)
            server_socket.connect((target_host, target_port))
            
            # Send 200 Connection Established
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            
            if self.verbose > 1:
                print(f"  🔒 HTTPS tunnel: {target_host}:{target_port}")
            
            # Create tunnel
            sockets = [client_socket, server_socket]
            while self._running and not self._shutdown_event.is_set():
                try:
                    readable, _, _ = select.select(sockets, [], [], 1.0)
                    for sock in readable:
                        data = sock.recv(self.BUFFER_SIZE)
                        if not data:
                            return
                        if sock is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                except:
                    break
                        
        except Exception:
            pass
        finally:
            try:
                if server_socket:
                    server_socket.close()
            except:
                pass
                
    def _extract_target(self, request: str) -> tuple:
        """Extract target host and port from HTTP request."""
        lines = request.split("\r\n")
        if not lines:
            return None, None, request
            
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None, None, request
            
        method = parts[0]
        url = parts[1]
        
        # CONNECT method
        if method == "CONNECT":
            host_port = url.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            return host, port, request
        
        # Parse URL
        if url.startswith("http://"):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
                
            # Modify request to use relative path
            lines[0] = f"{method} {path} HTTP/1.1"
            modified_request = "\r\n".join(lines)
            return host, port, modified_request
            
        # Already relative path - get host from headers
        host = None
        port = 80
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host_value = line.split(":", 1)[1].strip()
                if ":" in host_value:
                    host, port_str = host_value.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host = host_value
                break
                
        return host, port, request
        
    def _parse_request(
        self,
        request: str,
        client_ip: str,
        listen_port: int
    ) -> Optional[Packet]:
        """Parse HTTP request into Packet object."""
        try:
            lines = request.split("\r\n")
            if not lines:
                return None
                
            # Parse request line
            request_line = lines[0].split(" ")
            if len(request_line) < 2:
                return None
                
            method = request_line[0]
            full_url = request_line[1]
            
            # Parse URL
            parsed = urlparse(full_url) if full_url.startswith("http") else None
            
            if parsed:
                path = parsed.path or "/"
                query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                dest_port = parsed.port or 80
            else:
                path = full_url
                query_params = {}
                if "?" in full_url:
                    path, query_str = full_url.split("?", 1)
                    query_params = {k: v[0] for k, v in parse_qs(query_str).items()}
                dest_port = 80
            
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
            
            # Detect protocol
            protocol = Protocol.HTTP
            if "/graphql" in path.lower() or ("query" in body and "{" in body):
                protocol = Protocol.GRAPHQL
            elif headers.get("Upgrade", "").lower() == "websocket":
                protocol = Protocol.WEBSOCKET
            
            packet = self.create_packet(
                source_ip=client_ip,
                destination_port=dest_port,
                protocol=protocol,
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_params=query_params,
                captured_from="proxy"
            )
            
            # Add proxy-specific metadata
            packet.metadata["proxy_port"] = listen_port
            
            return packet
            
        except Exception:
            return None
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def get_available_interfaces() -> dict:
    """Get available network interfaces."""
    interfaces = {}
    
    if NETIFACES_AVAILABLE:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ips = [addr['addr'] for addr in addrs[netifaces.AF_INET]]
                    interfaces[iface] = ips
        except Exception:
            pass
    
    if not interfaces:
        # Fallback
        interfaces = {
            "lo": ["127.0.0.1"],
            "eth0": ["(tespit edilemedi)"],
            "wlan0": ["(tespit edilemedi)"],
        }
    
    return interfaces


def print_available_interfaces():
    """Print available network interfaces."""
    print("\n📡 Mevcut Ağ Arayüzleri:")
    print("-" * 40)
    
    interfaces = get_available_interfaces()
    for iface, ips in interfaces.items():
        print(f"  {iface}: {', '.join(ips)}")
    
    print("-" * 40)
    print("  0.0.0.0: Tüm arayüzlerde dinle")
    print()


def get_recommended_ports() -> List[int]:
    """Get recommended unprivileged ports."""
    return [8888, 8080, 8443, 3128]
