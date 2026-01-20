"""
IDS Configuration Module
Handles YAML/JSON configuration file loading and management.
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# Try to import yaml
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class CaptureConfig:
    """Capture mode configuration."""
    mode: str = "demo"  # demo, pcap, proxy, log
    interface: str = "any"
    ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8888])
    host: str = "127.0.0.1"
    log_files: List[str] = field(default_factory=list)
    log_format: str = "auto"  # auto, nginx, apache
    watch: bool = False


@dataclass
class OutputConfig:
    """Output configuration."""
    format: str = "text"  # text, json, csv
    log_dir: Optional[str] = None
    log_file: str = "security_events.log"
    verbose: int = 0  # 0=normal, 1=-v, 2=-vv, 3=-vvv


@dataclass
class DetectionConfig:
    """Detection rules configuration."""
    enabled_detectors: List[str] = field(default_factory=lambda: [
        "sqli", "xss", "complexity", "protocol"
    ])
    sqli_sensitivity: str = "high"  # low, medium, high
    xss_sensitivity: str = "high"
    max_query_depth: int = 10  # GraphQL
    max_aliases: int = 50  # GraphQL


@dataclass
class IDSConfig:
    """Main IDS configuration."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    
    @classmethod
    def from_file(cls, config_path: str) -> "IDSConfig":
        """Load configuration from YAML or JSON file."""
        path = Path(config_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Config dosyası bulunamadı: {config_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            if path.suffix in ('.yaml', '.yml'):
                if not YAML_AVAILABLE:
                    raise ImportError(
                        "YAML desteği için PyYAML gerekli:\n"
                        "  pip install pyyaml"
                    )
                data = yaml.safe_load(f)
            elif path.suffix == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Desteklenmeyen config formatı: {path.suffix}")
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IDSConfig":
        """Create config from dictionary."""
        config = cls()
        
        if 'capture' in data:
            for key, value in data['capture'].items():
                if hasattr(config.capture, key):
                    setattr(config.capture, key, value)
        
        if 'output' in data:
            for key, value in data['output'].items():
                if hasattr(config.output, key):
                    setattr(config.output, key, value)
        
        if 'detection' in data:
            for key, value in data['detection'].items():
                if hasattr(config.detection, key):
                    setattr(config.detection, key, value)
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'capture': {
                'mode': self.capture.mode,
                'interface': self.capture.interface,
                'ports': self.capture.ports,
                'host': self.capture.host,
                'log_files': self.capture.log_files,
                'log_format': self.capture.log_format,
                'watch': self.capture.watch,
            },
            'output': {
                'format': self.output.format,
                'log_dir': self.output.log_dir,
                'log_file': self.output.log_file,
                'verbose': self.output.verbose,
            },
            'detection': {
                'enabled_detectors': self.detection.enabled_detectors,
                'sqli_sensitivity': self.detection.sqli_sensitivity,
                'xss_sensitivity': self.detection.xss_sensitivity,
                'max_query_depth': self.detection.max_query_depth,
                'max_aliases': self.detection.max_aliases,
            }
        }
    
    def save(self, config_path: str):
        """Save configuration to file."""
        path = Path(config_path)
        data = self.to_dict()
        
        with open(path, 'w', encoding='utf-8') as f:
            if path.suffix in ('.yaml', '.yml'):
                if not YAML_AVAILABLE:
                    raise ImportError("YAML desteği için: pip install pyyaml")
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
            else:
                json.dump(data, f, indent=2, ensure_ascii=False)


def get_default_config() -> IDSConfig:
    """Get default configuration."""
    return IDSConfig()


def generate_sample_config(output_path: str = "config.yaml"):
    """Generate a sample configuration file."""
    config = get_default_config()
    config.save(output_path)
    return output_path
