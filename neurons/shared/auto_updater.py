"""
Auto Updater Module
Handles automatic version checking and updating from GitHub releases
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.request import Request, urlopen

from loguru import logger


class AutoUpdater:
    """Auto updater for ByteLeap Miner/Worker"""

    GITHUB_REPO = "byteleapai/byteleap-Miner"
    GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    CHECK_INTERVAL = 3600  # Check every hour (3600 seconds)

    def __init__(self, current_version: str, project_root: Path):
        """
        Initialize auto updater

        Args:
            current_version: Current version string (e.g., "0.0.4")
            project_root: Project root directory path
        """
        self.current_version = current_version
        self.project_root = project_root
        self._check_task = None
        self._should_stop = False

    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings

        Args:
            version1: First version string (e.g., "0.0.4")
            version2: Second version string (e.g., "0.0.5")

        Returns:
            -1 if version1 < version2
            0 if version1 == version2
            1 if version1 > version2
        """
        # Remove 'v' prefix if present
        v1 = version1.lstrip("v").split(".")
        v2 = version2.lstrip("v").split(".")

        # Pad to same length
        max_len = max(len(v1), len(v2))
        v1 += ["0"] * (max_len - len(v1))
        v2 += ["0"] * (max_len - len(v2))

        # Compare each part
        for p1, p2 in zip(v1, v2):
            try:
                n1, n2 = int(p1), int(p2)
                if n1 < n2:
                    return -1
                elif n1 > n2:
                    return 1
            except ValueError:
                # String comparison for non-numeric parts
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1

        return 0

    async def check_for_updates(self) -> Optional[Dict]:
        """
        Check for available updates from GitHub releases

        Returns:
            Dictionary with update info if available, None otherwise
            {
                "version": "0.0.5",
                "download_url": "https://...",
                "changelog": "..."
            }
        """
        try:
            # Create request with user agent
            req = Request(
                self.GITHUB_API_URL, headers={"User-Agent": "ByteLeap-AutoUpdater"}
            )

            # Fetch latest release info
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())

            latest_version = data.get("tag_name", "").lstrip("v")
            if not latest_version:
                logger.warning("Failed to get latest version info")
                return None

            # Compare versions
            if self._compare_versions(self.current_version, latest_version) >= 0:
                logger.debug(f"Current version {self.current_version} is already the latest")
                return None

            # Get download URL for source code zip
            download_url = data.get("zipball_url")
            if not download_url:
                logger.warning("Failed to get download URL")
                return None

            return {
                "version": latest_version,
                "download_url": download_url,
                "changelog": data.get("body", ""),
                "release_url": data.get("html_url", ""),
            }

        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return None

    def _download_file(self, url: str, dest_path: Path) -> bool:
        """
        Download file from URL

        Args:
            url: Download URL
            dest_path: Destination file path

        Returns:
            True if successful, False otherwise
        """
        try:
            req = Request(url, headers={"User-Agent": "ByteLeap-AutoUpdater"})

            with urlopen(req, timeout=30) as response:
                with open(dest_path, "wb") as f:
                    # Download in chunks
                    chunk_size = 8192
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)

            logger.info(f"Download completed: {dest_path}")
            return True

        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def _extract_zip(self, zip_path: Path, extract_to: Path) -> Optional[Path]:
        """
        Extract ZIP file

        Args:
            zip_path: Path to ZIP file
            extract_to: Directory to extract to

        Returns:
            Path to extracted directory, or None if failed
        """
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(extract_to)

            # Find the extracted directory (GitHub zips extract to a subdirectory)
            extracted_dirs = [
                d for d in extract_to.iterdir() if d.is_dir() and d.name.startswith("byteleapai-")
            ]

            if not extracted_dirs:
                logger.error("Extracted directory not found")
                return None

            return extracted_dirs[0]

        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return None

    def _compare_config_files(
        self, old_config_dir: Path, new_config_dir: Path
    ) -> Dict[str, list]:
        """
        Compare configuration files between old and new versions

        Args:
            old_config_dir: Old config directory
            new_config_dir: New config directory

        Returns:
            Dictionary with added, removed, and common config files
        """
        import yaml

        old_configs = {f.name: f for f in old_config_dir.glob("*.yaml")}
        new_configs = {f.name: f for f in new_config_dir.glob("*.yaml")}

        added = set(new_configs.keys()) - set(old_configs.keys())
        removed = set(old_configs.keys()) - set(new_configs.keys())
        common = set(old_configs.keys()) & set(new_configs.keys())

        differences = {"added": list(added), "removed": list(removed), "modified": []}

        # Check for modified configs
        for config_name in common:
            try:
                with open(old_configs[config_name], "r", encoding="utf-8") as f:
                    old_data = yaml.safe_load(f)
                with open(new_configs[config_name], "r", encoding="utf-8") as f:
                    new_data = yaml.safe_load(f)

                # Compare keys
                if old_data and new_data:
                    old_keys = set(self._flatten_dict_keys(old_data))
                    new_keys = set(self._flatten_dict_keys(new_data))

                    if old_keys != new_keys:
                        differences["modified"].append(
                            {
                                "file": config_name,
                                "added_keys": list(new_keys - old_keys),
                                "removed_keys": list(old_keys - new_keys),
                            }
                        )

            except Exception as e:
                logger.warning(f"Failed to compare config file {config_name}: {e}")

        return differences

    def _flatten_dict_keys(self, d: dict, parent_key: str = "") -> list:
        """
        Flatten nested dictionary keys

        Args:
            d: Dictionary to flatten
            parent_key: Parent key prefix

        Returns:
            List of flattened keys
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict_keys(v, new_key))
            else:
                items.append(new_key)
        return items

    async def download_and_install_update(self, update_info: Dict) -> bool:
        """
        Download and install update

        Args:
            update_info: Update information from check_for_updates

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Downloading new version {update_info['version']}...")

        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            zip_path = temp_path / "update.zip"

            # Download update
            if not self._download_file(update_info["download_url"], zip_path):
                return False

            # Extract update
            extracted_dir = self._extract_zip(zip_path, temp_path)
            if not extracted_dir:
                return False

            logger.info(f"Extraction completed: {extracted_dir}")

            # Compare config files
            old_config_dir = self.project_root / "config"
            new_config_dir = extracted_dir / "config"

            if old_config_dir.exists() and new_config_dir.exists():
                config_diff = self._compare_config_files(old_config_dir, new_config_dir)

                if (
                    config_diff["added"]
                    or config_diff["removed"]
                    or config_diff["modified"]
                ):
                    logger.warning("=" * 60)
                    logger.warning("Configuration files have changed, please review:")
                    logger.warning("=" * 60)

                    if config_diff["added"]:
                        logger.warning(f"Added config files: {', '.join(config_diff['added'])}")

                    if config_diff["removed"]:
                        logger.warning(f"Removed config files: {', '.join(config_diff['removed'])}")

                    if config_diff["modified"]:
                        for mod in config_diff["modified"]:
                            logger.warning(f"Config file {mod['file']} has changes:")
                            if mod["added_keys"]:
                                logger.warning(
                                    f"  Added keys: {', '.join(mod['added_keys'])}"
                                )
                            if mod["removed_keys"]:
                                logger.warning(
                                    f"  Removed keys: {', '.join(mod['removed_keys'])}"
                                )

                    logger.warning("=" * 60)
                    logger.warning(
                        "Please backup your config files and update according to prompts"
                    )
                    logger.warning("=" * 60)

            # Backup current config
            backup_dir = self.project_root / "config_backup"
            if old_config_dir.exists():
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                shutil.copytree(old_config_dir, backup_dir)
                logger.info(f"Config backed up to: {backup_dir}")

            # Copy new files (excluding config directory)
            logger.info("Updating files...")
            for item in extracted_dir.iterdir():
                if item.name == "config":
                    continue  # Skip config directory

                dest = self.project_root / item.name
                if dest.exists():
                    if dest.is_dir():
                        shutil.rmtree(dest)
                    else:
                        dest.unlink()

                if item.is_dir():
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

            logger.success(f"Update completed! New version: {update_info['version']}")
            logger.info(f"Release notes: {update_info['release_url']}")

            return True

    def restart_process(self, script_args: list):
        """
        Restart current process with new code

        Args:
            script_args: Arguments to pass to new process
        """
        logger.info("Starting new process...")

        # Get current Python executable and script
        python_exe = sys.executable
        script_path = sys.argv[0]

        # Start new process
        subprocess.Popen(
            [python_exe, script_path] + script_args,
            cwd=str(self.project_root),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        logger.info("New process started, current process will exit...")

    async def check_update_on_startup(self, auto_install: bool = True) -> bool:
        """
        Check for updates on startup

        Args:
            auto_install: Whether to automatically install updates

        Returns:
            True if update was installed, False otherwise
        """
        logger.info(f"Checking for updates... Current version: {self.current_version}")

        update_info = await self.check_for_updates()

        if not update_info:
            logger.info("Already running the latest version")
            return False

        logger.warning("=" * 60)
        logger.warning(f"New version available: {update_info['version']}")
        logger.warning(f"Current version: {self.current_version}")
        logger.warning(f"Release notes: {update_info['release_url']}")
        logger.warning("=" * 60)

        if auto_install:
            success = await self.download_and_install_update(update_info)
            if success:
                logger.warning("Update completed, please check config and restart")
                return True
            else:
                logger.error("Update failed, continuing with current version")

        return False

    async def start_periodic_check(self):
        """Start periodic update checking (every hour)"""
        self._should_stop = False
        logger.info(f"Starting periodic update check (every {self.CHECK_INTERVAL} seconds)")

        while not self._should_stop:
            try:
                await asyncio.sleep(self.CHECK_INTERVAL)

                if self._should_stop:
                    break

                update_info = await self.check_for_updates()

                if update_info:
                    logger.warning("=" * 60)
                    logger.warning(f"New version available: {update_info['version']}")
                    logger.warning(f"Current version: {self.current_version}")
                    logger.warning(f"Release notes: {update_info['release_url']}")
                    logger.warning("Please update when convenient")
                    logger.warning("=" * 60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic update check failed: {e}")

    def stop_periodic_check(self):
        """Stop periodic update checking"""
        self._should_stop = True
        logger.info("Stopping periodic update check")
