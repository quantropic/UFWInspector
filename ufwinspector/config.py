"""Configuration management for UFWInspector."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for UFWInspector."""

    DEFAULT_CONFIG = {
        "log_file": "/var/log/ufw.log",
        "max_entries": 1000,
        "enable_isp_lookup": True,
        "dns_cache_ttl": 86400,  # 24 hours in seconds
    }

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        self.config_dir = os.path.expanduser("~/.config/ufwinspector")
        self.config_file = os.path.join(self.config_dir, "config.json")
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            # Create config directory if it doesn't exist
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Load config if it exists
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
            else:
                # Create default config file
                self.save_config()
        except Exception as e:
            print(f"Error loading configuration: {e}")

    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving configuration: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self.config[key] = value
        self.save_config()

    def update(self, config_dict: Dict[str, Any]) -> None:
        """Update multiple configuration values."""
        self.config.update(config_dict)
        self.save_config()

    def reset(self) -> None:
        """Reset configuration to defaults."""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save_config()


# Global configuration instance
config = Config()
