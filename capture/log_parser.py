"""
Log Parser Capture Module
Parses web server access logs (Nginx, Apache) for analysis.

No root privileges required.

Supported formats:
- Nginx combined/access log
- Apache common format
- Apache combined format
- Auto-detection

Usage:
    python3 -m ids.main --parse-log /var/log/nginx/access.log
    python3 -m ids.main --parse-log /var/log/apache2/access.log --log-format apache
    python3 -m ids.main --parse-log access.log --watch
"""

from typing import Optional, Callable, Generator, List, Dict
import re
import os
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote
import threading

from .base_capture import BaseCapturer, CaptureMode
from ..core.packet import Packet, Protocol


class LogFormat:
    """Log format definitions."""
    NGINX = "nginx"
    APACHE = "apache"
    APACHE_COMMON = "apache_common"
    AUTO = "auto"


class LogParser(BaseCapturer):
    """
    Web server log file parser.
    
    Supports:
    - Nginx combined format
    - Apache common format
    - Apache combined format
    - Auto-detection
    - Real-time file watching (tail -f mode)
    - Multiple log files
    
    Example:
        parser = LogParser("/var/log/nginx/access.log", watch=True)
        parser.start()
        for packet in parser.capture_packets():
            print(packet)
        parser.stop()
    """
    
    # Nginx combined log format regex
    # 127.0.0.1 - - [20/Jan/2026:15:00:00 +0000] "GET /path?query HTTP/1.1" 200 1234 "referer" "user-agent"
    NGINX_PATTERN = re.compile(
        r'^(?P<remote_addr>\S+)\s+'           # Remote address
        r'\S+\s+'                               # Remote user ident (-)
        r'(?P<remote_user>\S+)\s+'             # Remote user
        r'\[(?P<time>[^\]]+)\]\s+'             # Time
        r'"(?P<method>\S+)\s+'                 # Method
        r'(?P<path>\S+)\s+'                    # Path
        r'HTTP/[\d.]+"\s+'                     # HTTP version
        r'(?P<status>\d+)\s+'                  # Status code
        r'(?P<size>\d+|-)\s*'                  # Response size
        r'(?:"(?P<referer>[^"]*)"\s*)?'        # Referer (optional)
        r'(?:"(?P<user_agent>[^"]*)")?'        # User agent (optional)
    )
    
    # Apache combined log format regex (same as Nginx)
    APACHE_COMBINED_PATTERN = NGINX_PATTERN
    
    # Apache common log format regex
    # 127.0.0.1 - - [20/Jan/2026:15:00:00 +0000] "GET /path HTTP/1.1" 200 1234
    APACHE_COMMON_PATTERN = re.compile(
        r'^(?P<remote_addr>\S+)\s+'
        r'\S+\s+'
        r'(?P<remote_user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+'
        r'(?P<path>\S+)\s+'
        r'HTTP/[\d.]+"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|-)'
    )
    
    # Pattern for detecting format
    FORMAT_PATTERNS = {
        LogFormat.NGINX: NGINX_PATTERN,
        LogFormat.APACHE: APACHE_COMBINED_PATTERN,
        LogFormat.APACHE_COMMON: APACHE_COMMON_PATTERN,
    }
    
    def __init__(
        self,
        log_paths: str | List[str],
        watch: bool = False,
        log_format: str = LogFormat.AUTO,
        callback: Optional[Callable[[Packet], None]] = None,
        verbose: int = 0
    ):
        """
        Initialize log parser.
        
        Args:
            log_paths: Path(s) to the log file(s) - can be single path or list
            watch: If True, watch for new entries (like tail -f)
            log_format: Log format (nginx, apache, apache_common, auto)
            callback: Callback for each parsed packet
            verbose: Verbosity level (0-3)
        """
        super().__init__(callback)
        
        # Handle single path or list
        if isinstance(log_paths, str):
            self.log_paths = [Path(log_paths)]
        else:
            self.log_paths = [Path(p) for p in log_paths]
        
        self.watch = watch
        self.log_format = log_format
        self.verbose = verbose
        self._file_positions: Dict[str, int] = {}
        self._detected_formats: Dict[str, str] = {}
        self._watch_threads: List[threading.Thread] = []
        
    @property
    def mode(self) -> CaptureMode:
        return CaptureMode.LOG
    
    def _detect_format(self, sample_line: str) -> str:
        """
        Auto-detect log format from a sample line.
        
        Args:
            sample_line: A sample log line
            
        Returns:
            Detected format name
        """
        # Try each pattern
        for format_name, pattern in self.FORMAT_PATTERNS.items():
            if pattern.match(sample_line):
                return format_name
        
        return LogFormat.NGINX  # Default fallback
    
    def _get_pattern_for_file(self, file_path: Path) -> re.Pattern:
        """Get the appropriate regex pattern for a file."""
        str_path = str(file_path)
        
        if self.log_format == LogFormat.AUTO:
            if str_path in self._detected_formats:
                format_name = self._detected_formats[str_path]
            else:
                # Read first line to detect format
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline().strip()
                        format_name = self._detect_format(first_line)
                        self._detected_formats[str_path] = format_name
                        if self.verbose > 0:
                            print(f"  📋 Format tespit edildi: {format_name} -> {file_path}")
                except Exception:
                    format_name = LogFormat.NGINX
        else:
            format_name = self.log_format
        
        return self.FORMAT_PATTERNS.get(format_name, self.NGINX_PATTERN)
    
    def start(self) -> None:
        """Start parsing log file(s)."""
        if self._running:
            return
        
        # Validate all paths exist
        for path in self.log_paths:
            if not path.exists():
                raise FileNotFoundError(f"Log dosyası bulunamadı: {path}")
        
        self._running = True
        
        if self.watch:
            # Seek to end for watch mode
            for path in self.log_paths:
                self._file_positions[str(path)] = path.stat().st_size
            
            print(f"✓ Log izleniyor (tail -f modu): {len(self.log_paths)} dosya")
            for path in self.log_paths:
                print(f"  📄 {path}")
            
            # Start watch thread for each file
            for path in self.log_paths:
                thread = threading.Thread(
                    target=self._watch_file,
                    args=(path,),
                    daemon=True
                )
                self._watch_threads.append(thread)
                thread.start()
        else:
            # Parse entire file(s) once
            print(f"✓ Log dosyaları okunuyor: {len(self.log_paths)} dosya")
            self._parse_all_files()
            self._running = False
            
    def stop(self) -> None:
        """Stop parsing."""
        self._running = False
        for thread in self._watch_threads:
            thread.join(timeout=2.0)
        self._watch_threads.clear()
    
    def _capture_loop(self) -> None:
        """
        Internal capture loop - required by base class.
        For LogParser, the actual capture is done by _watch_file threads.
        This method is not used directly but required for ABC compliance.
        """
        # LogParser uses multiple threads via _watch_file instead of a single capture loop
        # This is just to satisfy abstract method requirement
        pass
    
    def _watch_file(self, file_path: Path) -> None:
        """Watch a single file for new entries."""
        str_path = str(file_path)
        pattern = self._get_pattern_for_file(file_path)
        
        while self._running:
            try:
                current_size = file_path.stat().st_size
                
                if current_size > self._file_positions.get(str_path, 0):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self._file_positions.get(str_path, 0))
                        for line in f:
                            if not self._running:
                                break
                            packet = self._parse_line(line.strip(), pattern, str_path)
                            if packet:
                                self._enqueue_packet(packet)
                        self._file_positions[str_path] = f.tell()
                        
                elif current_size < self._file_positions.get(str_path, 0):
                    # File was truncated/rotated
                    self._file_positions[str_path] = 0
                    if self.verbose > 0:
                        print(f"  🔄 Log rotasyonu tespit edildi: {file_path}")
                    
                time.sleep(0.5)
                
            except Exception as e:
                if self._running and self.verbose > 0:
                    print(f"⚠ Log okuma hatası ({file_path}): {e}")
                time.sleep(1.0)
    
    def _parse_all_files(self) -> None:
        """Parse all log files."""
        for path in self.log_paths:
            if self.verbose > 0:
                print(f"  📄 İşleniyor: {path}")
            self._parse_file(path)
    
    def _parse_file(self, file_path: Path) -> None:
        """Parse entire log file."""
        pattern = self._get_pattern_for_file(file_path)
        str_path = str(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not self._running:
                    break
                packet = self._parse_line(line.strip(), pattern, str_path)
                if packet:
                    self._enqueue_packet(packet)
                    
    def _parse_line(
        self,
        line: str,
        pattern: re.Pattern,
        source_file: str = ""
    ) -> Optional[Packet]:
        """Parse a single log line."""
        if not line:
            return None
        
        match = pattern.match(line)
        if not match:
            # Try other patterns as fallback
            for fmt, pat in self.FORMAT_PATTERNS.items():
                match = pat.match(line)
                if match:
                    break
            
            if not match:
                if self.verbose > 1:
                    print(f"  ⚠ Parse edilemedi: {line[:50]}...")
                return None
            
        try:
            data = match.groupdict()
            
            source_ip = data['remote_addr']
            method = data['method']
            full_path = unquote(data['path'])  # URL decode
            status = int(data['status'])
            
            # Parse path and query params
            path = full_path
            query_params = {}
            if "?" in full_path:
                path, query_str = full_path.split("?", 1)
                query_params = {k: v[0] for k, v in parse_qs(query_str).items()}
            
            # Build headers from available data
            headers = {}
            if data.get('referer') and data['referer'] != '-':
                headers['Referer'] = data['referer']
            if data.get('user_agent'):
                headers['User-Agent'] = data['user_agent']
            
            # Detect protocol from path
            protocol = Protocol.HTTP
            if "/graphql" in path.lower():
                protocol = Protocol.GRAPHQL
            
            # Add source file to metadata
            packet = self.create_packet(
                source_ip=source_ip,
                destination_port=80,
                protocol=protocol,
                method=method,
                path=path,
                headers=headers,
                body="",  # Not available in access logs
                query_params=query_params,
                captured_from="log"
            )
            
            # Add extra metadata
            packet.metadata["log_file"] = source_file
            packet.metadata["status_code"] = status
            packet.metadata["log_time"] = data.get('time', '')
            
            return packet
            
        except Exception as e:
            if self.verbose > 1:
                print(f"  ⚠ Parse hatası: {e}")
            return None
            
    def parse_once(self) -> Generator[Packet, None, None]:
        """
        Parse all log files once and yield packets.
        
        Yields:
            Parsed Packet objects
        """
        for path in self.log_paths:
            if not path.exists():
                raise FileNotFoundError(f"Log dosyası bulunamadı: {path}")
            
            pattern = self._get_pattern_for_file(path)
            str_path = str(path)
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    packet = self._parse_line(line.strip(), pattern, str_path)
                    if packet:
                        yield packet


def get_supported_formats() -> Dict[str, str]:
    """Get list of supported log formats with descriptions."""
    return {
        "auto": "Otomatik format tespiti",
        "nginx": "Nginx combined/access log format",
        "apache": "Apache combined log format",
        "apache_common": "Apache common log format",
    }
