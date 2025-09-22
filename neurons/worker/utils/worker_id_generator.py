"""
Worker ID Generation and Management
Provides globally unique worker ID generation with name-based computation
"""

import hashlib
import platform
import socket
import time
import uuid
from typing import Any, Dict, Optional


class WorkerIDGenerator:
    """Generate globally unique worker IDs based on configuration and system properties"""

    def __init__(self):
        """Initialize worker ID generator"""
        pass

    @staticmethod
    def generate_worker_id(system_fingerprint: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate stable worker ID based on system properties only

        The worker ID format: {system_hash} (16 characters)
        - system_hash: First 16 characters of SHA256(system_fingerprint)

        Worker operates independently and doesn't know miner hotkey.
        Uniqueness across miners is handled at validator level using (hotkey, worker_id) pairs.

        Args:
            system_fingerprint: System hardware/network fingerprint (optional)

        Returns:
            Stable worker ID string based on system properties
        """
        # Generate system fingerprint hash
        if system_fingerprint is None:
            system_fingerprint = WorkerIDGenerator._get_system_fingerprint()

        system_input = WorkerIDGenerator._serialize_fingerprint(system_fingerprint)
        system_hash = hashlib.sha256(system_input.encode()).hexdigest()[:16]

        return system_hash

    @staticmethod
    def _get_system_fingerprint() -> Dict[str, Any]:
        """
        Get stable system fingerprint for worker ID generation

        Returns:
            System fingerprint dictionary containing stable hardware info
        """
        fingerprint = {}

        try:
            # Core hardware provides stable identification
            fingerprint["platform"] = platform.platform()
            fingerprint["machine"] = platform.machine()
            fingerprint["processor"] = platform.processor()

            # Primary network interface MAC provides hardware-level identification
            try:
                import psutil

                primary_mac = None
                net_interfaces = psutil.net_if_addrs()

                interface_priority = [
                    "eth0",
                    "en0",
                    "ens",
                    "eno",
                    "enp",
                    "wlan0",
                    "wlo",
                ]

                for priority_prefix in interface_priority:
                    for interface, addrs in net_interfaces.items():
                        if interface.startswith(priority_prefix):
                            for addr in addrs:
                                if (
                                    addr.family == psutil.AF_LINK
                                    and addr.address != "00:00:00:00:00:00"
                                ):
                                    primary_mac = addr.address
                                    break
                    if primary_mac:
                        break

                if not primary_mac:
                    for interface, addrs in net_interfaces.items():
                        if not interface.startswith("lo"):
                            for addr in addrs:
                                if (
                                    addr.family == psutil.AF_LINK
                                    and addr.address != "00:00:00:00:00:00"
                                ):
                                    primary_mac = addr.address
                                    break
                        if primary_mac:
                            break

                fingerprint["primary_mac"] = primary_mac or hex(uuid.getnode())

            except ImportError:
                fingerprint["primary_mac"] = hex(uuid.getnode())

            try:
                import subprocess
                import sys

                if sys.platform.startswith("linux"):
                    try:
                        result = subprocess.run(
                            ["cat", "/etc/machine-id"],
                            capture_output=True,
                            text=True,
                            timeout=2,
                        )
                        if result.returncode == 0:
                            fingerprint["machine_id"] = result.stdout.strip()
                    except:
                        pass

                elif sys.platform == "darwin":
                    try:
                        result = subprocess.run(
                            ["system_profiler", "SPHardwareDataType"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split("\n"):
                                if "Hardware UUID" in line:
                                    fingerprint["hardware_uuid"] = line.split(":")[
                                        1
                                    ].strip()
                                    break
                    except:
                        pass

                elif sys.platform.startswith("win"):
                    try:
                        result = subprocess.run(
                            ["wmic", "baseboard", "get", "serialnumber"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            lines = [
                                l.strip()
                                for l in result.stdout.split("\n")
                                if l.strip()
                            ]
                            if len(lines) > 1:
                                fingerprint["motherboard_serial"] = lines[1]
                    except:
                        pass
            except:
                pass

        except Exception:
            fingerprint = {"platform": "unknown", "primary_mac": hex(uuid.getnode())}

        return fingerprint

    @staticmethod
    def _serialize_fingerprint(fingerprint: Dict[str, Any]) -> str:
        """
        Serialize fingerprint dictionary to consistent string

        Args:
            fingerprint: System fingerprint dictionary

        Returns:
            Serialized fingerprint string
        """
        # Sort keys for consistency
        sorted_items = []
        for key in sorted(fingerprint.keys()):
            value = fingerprint[key]
            if isinstance(value, list):
                value = ",".join(sorted(str(v) for v in value))
            sorted_items.append(f"{key}:{value}")

        return "|".join(sorted_items)

    @staticmethod
    def validate_worker_id(worker_id: str) -> bool:
        """
        Validate worker ID format

        Args:
            worker_id: Worker ID to validate

        Returns:
            True if valid format, False otherwise
        """
        if not isinstance(worker_id, str):
            return False

        # Expected format: 16-character hexadecimal string
        if len(worker_id) != 16:
            return False

        try:
            int(worker_id, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def verify_worker_id_for_system(
        worker_id: str, system_fingerprint: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Verify if worker ID corresponds to current system

        Args:
            worker_id: Worker ID to verify
            system_fingerprint: System fingerprint to check against

        Returns:
            True if worker ID matches current system
        """
        if not WorkerIDGenerator.validate_worker_id(worker_id):
            return False

        # Generate expected worker ID for this system
        expected_worker_id = WorkerIDGenerator.generate_worker_id(system_fingerprint)

        return worker_id == expected_worker_id

    @staticmethod
    def should_regenerate_worker_id(
        current_worker_id: str, system_fingerprint: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if worker ID should be regenerated due to system change

        Args:
            current_worker_id: Current worker ID
            system_fingerprint: Current system fingerprint

        Returns:
            True if worker ID needs regeneration
        """
        if not current_worker_id or not WorkerIDGenerator.validate_worker_id(
            current_worker_id
        ):
            return True

        # Validate worker ID against current hardware fingerprint
        return not WorkerIDGenerator.verify_worker_id_for_system(
            current_worker_id, system_fingerprint
        )

    def update_worker_name(self, new_worker_name: str) -> None:
        """
        Update worker name (worker_id remains unchanged)

        Args:
            new_worker_name: New worker name
        """
        # Name changes without affecting worker_id
        self.config_manager.set("worker_name", new_worker_name)
        self.config_manager.save()
