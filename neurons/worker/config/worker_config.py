"""
Worker Configuration Management
Unified configuration system with worker-specific functionality
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from neurons.shared.config.config_manager import ConfigManager


class WorkerConfig(ConfigManager):
    """Configuration manager for worker component with worker-specific functionality"""

    def __init__(self, config_file: str):
        """
        Initialize worker configuration

        Args:
            config_file: Path to YAML configuration file
        """
        self.config_file = config_file
        config_data = self._load_config()
        super().__init__(config_data)

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        config_path = Path(self.config_file)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                raise ValueError("Configuration file must contain a YAML dictionary")

            return config

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load configuration: {e}")

    def get_worker_id(self) -> str:
        """
        Generate stable worker ID based on system fingerprint.
        Uses standardized WorkerIDGenerator for consistency.

        Returns:
            Stable 16-character worker ID string
        """
        from neurons.worker.utils.worker_id_generator import WorkerIDGenerator

        return WorkerIDGenerator.generate_worker_id()

    def get_worker_name(self) -> Optional[str]:
        """
        Get the user-configured worker name.

        Returns:
            The worker name, or None if not configured.
        """
        return self.get_optional("worker_name")

    def get_logging_config(self) -> Dict[str, Any]:
        """
        Get logging configuration from YAML file.

        Returns:
            A dictionary with logging configuration.

        Raises:
            KeyError: If logging configuration is not found in config file
        """
        return self.get("logging")

    def get_capabilities(self) -> List[str]:
        """
        Auto-detect worker capabilities based on configuration.

        Returns:
            List of capability strings (e.g., ['cpu_matrix', 'gpu_matrix'])
        """
        capabilities = []

        # Always supports CPU matrix computation
        capabilities.append("cpu_matrix")

        # Check for GPU capability
        try:
            if self.get("gpu.enable"):
                capabilities.append("gpu_matrix")
        except KeyError:
            # GPU configuration is optional - skip if not present
            pass

        return capabilities

    def get_system_fingerprint(self) -> str:
        """Generate a system fingerprint for worker identification"""
        from neurons.worker.utils.worker_id_generator import WorkerIDGenerator

        return WorkerIDGenerator.get_system_fingerprint()
