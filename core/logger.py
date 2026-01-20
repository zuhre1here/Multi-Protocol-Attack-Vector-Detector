"""
Security Event Logger
Logs detected attacks to console and file with structured format.
"""

import logging
from datetime import datetime
from typing import Optional
from pathlib import Path
import sys


class SecurityLogger:
    """
    Handles security event logging to console and file.
    
    Log Format: [Zaman] [Protokol] [Saldırı Tipi] [Kaynak IP] [Zararlı İçerik]
    """
    
    def __init__(self, log_file: str = "security_events.log", log_dir: Optional[str] = None):
        """
        Initialize the security logger.
        
        Args:
            log_file: Name of the log file
            log_dir: Directory for log file (defaults to current directory)
        """
        self.log_file = log_file
        self.log_dir = Path(log_dir) if log_dir else Path.cwd()
        self.log_path = self.log_dir / self.log_file
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Set up logging handlers for console and file."""
        self.logger = logging.getLogger("SecurityIDS")
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with color support
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '\033[91m⚠ ALERT\033[0m %(message)s'
        )
        console_handler.setFormatter(console_format)
        
        # File handler
        file_handler = logging.FileHandler(self.log_path, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_format = logging.Formatter('%(message)s')
        file_handler.setFormatter(file_format)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
    def log_attack(
        self,
        protocol: str,
        attack_type: str,
        source_ip: str,
        malicious_content: str,
        severity: str = "HIGH"
    ):
        """
        Log a detected attack event.
        
        Args:
            protocol: Protocol where attack was detected (HTTP, GraphQL, WebSocket)
            attack_type: Type of attack (SQLi, XSS, Complexity Attack, etc.)
            source_ip: Source IP address of the attacker
            malicious_content: The malicious payload or content detected
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Truncate malicious content if too long
        if len(malicious_content) > 200:
            malicious_content = malicious_content[:200] + "..."
        
        # Escape newlines and special characters
        malicious_content = malicious_content.replace('\n', '\\n').replace('\r', '\\r')
        
        log_message = f"[{timestamp}] [{protocol}] [{attack_type}] [{source_ip}] [{malicious_content}]"
        
        self.logger.info(log_message)
        
    def log_info(self, message: str):
        """Log an informational message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\033[94mℹ INFO\033[0m [{timestamp}] {message}")
        
    def log_system(self, message: str):
        """Log a system message (startup, shutdown, etc.)."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\033[92m✓ SYSTEM\033[0m [{timestamp}] {message}")


# Global logger instance
_logger_instance: Optional[SecurityLogger] = None


def get_logger(log_dir: Optional[str] = None) -> SecurityLogger:
    """Get or create the global logger instance."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SecurityLogger(log_dir=log_dir)
    return _logger_instance
