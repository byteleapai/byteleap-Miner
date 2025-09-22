"""
GPU Server Client
IPC client for communication with CUDA GPU server via Unix Domain Socket
"""

import json
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import bittensor as bt
from loguru import logger


class GPUServerError(Exception):
    """GPU server communication error"""

    pass


class GPUServerClient:
    """
    IPC client for communication with GPU server via Unix Domain Socket

    Manages lifecycle of GPU server binary and handles communication
    through socket interface matching ByteLeap GPU project.
    """

    # IPC constants
    SOCKET_PATH = "/tmp/gpu_tensor.sock"

    # Timeouts and intervals
    CONNECTION_TIMEOUT = 300  # Match command timeout for consistency
    COMMAND_TIMEOUT = 300
    PING_INTERVAL = 60
    STARTUP_TIMEOUT = 30

    # GPU server lifecycle
    RESTART_DELAY = 5

    def __init__(self, config):
        """
        Initialize GPU server client

        Args:
            config: Configuration manager containing GPU server settings
        """
        self.config = config
        # GPU server binary configuration from config
        self.gpu_binary_path = config.get("gpu.binary_path")
        self.socket_path = config.get("gpu.socket_path")
        self.enable_gpu = config.get("gpu.enable")
        self.auto_start = config.get("gpu.auto_start")

        # Runtime state
        self.gpu_process: Optional[subprocess.Popen] = None
        self.is_connected = False
        self.last_ping_time = 0
        self.connection_lock = threading.Lock()

        # GPU information cache
        self.gpu_info: Optional[Dict[str, Any]] = None
        self.gpu_uuids: List[str] = []

        logger.debug(f"🧮 GPU client init | binary={self.gpu_binary_path}")

    def _resolve_binary_path(self, binary_path: str) -> Path:
        """
        Resolve binary path intelligently:
        1. If absolute path, use as-is
        2. If relative path, try relative to current directory
        3. If not found, try relative to project root (where this script is typically run from)
        """
        path = Path(binary_path)

        # If absolute path, return as-is
        if path.is_absolute():
            return path

        # If relative path exists from current directory, use it
        if path.exists():
            return path

        # Try to find project root by looking for characteristic files
        # Start from current file location and walk up
        current_file = Path(__file__)
        search_path = current_file.parent

        # Walk up directory tree to find project root
        for i in range(10):  # Limit search depth
            # Look for project indicators (bin directory, setup files, etc.)
            potential_binary = search_path / binary_path.lstrip("./")
            if potential_binary.exists():
                return potential_binary

            # Check for project root indicators
            has_bin = (search_path / "bin").is_dir()
            has_setup = (search_path / "setup.py").exists()
            has_claude = (search_path / "CLAUDE.md").exists()

            if has_bin or has_setup or has_claude:
                potential_binary = search_path / binary_path.lstrip("./")
                return potential_binary

            parent = search_path.parent
            if parent == search_path:  # Reached filesystem root
                break
            search_path = parent

        # Fall back to original path if nothing found
        return path

    def is_available(self) -> bool:
        """Check if GPU server is available and connected"""
        if not self.enable_gpu:
            return False

        with self.connection_lock:
            return self.is_connected and self._is_server_responsive()

    def start_gpu_server(self) -> bool:
        """
        Start GPU server binary if not already running

        Returns:
            True if server is running, False otherwise
        """
        if not self.enable_gpu:
            logger.info("⚠️ GPU disabled by config")
            return False

        with self.connection_lock:
            # Check if already running and responsive
            if (
                self.gpu_process
                and self._is_process_alive()
                and self._is_server_responsive()
            ):
                logger.debug("GPU server running and responsive")
                return True

            # Clean up any existing process
            self._cleanup_gpu_process()

            # Validate binary path with intelligent resolution
            binary_path = self._resolve_binary_path(self.gpu_binary_path)
            if not binary_path.exists():
                logger.error(f"❌ GPU binary not found | path={binary_path}")
                logger.error(f"❌ Working directory: {Path.cwd()}")
                return False

            if not binary_path.is_file() or not os.access(binary_path, os.X_OK):
                logger.error(f"❌ GPU binary not executable | path={binary_path}")
                return False

            try:
                # Start GPU server process
                logger.debug(f"GPU server starting | path={binary_path}")

                # Start GPU server with socket path (ensure absolute path)
                absolute_binary_path = binary_path.resolve()
                cmd = [str(absolute_binary_path), "--socket", self.socket_path]

                self.gpu_process = subprocess.Popen(
                    cmd,
                    cwd=str("/tmp"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,  # Create new process group
                )

                # Wait for server to start and become responsive
                start_time = time.time()
                while time.time() - start_time < self.STARTUP_TIMEOUT:
                    # Check if process is still alive
                    if self.gpu_process.poll() is not None:
                        # Process has terminated
                        stdout, stderr = self.gpu_process.communicate()
                        logger.error(f"❌ GPU process terminated unexpectedly")
                        logger.error(
                            f"❌ GPU stdout: {stdout.decode() if stdout else 'None'}"
                        )
                        logger.error(
                            f"❌ GPU stderr: {stderr.decode() if stderr else 'None'}"
                        )
                        return False

                    if self._is_server_responsive():
                        self.is_connected = True
                        logger.debug("✅ GPU server started and responsive")

                        # Cache GPU information
                        self._refresh_gpu_info()
                        return True

                    time.sleep(1)

                # Server didn't become responsive in time
                logger.error("❌ GPU server unresponsive within timeout")
                self._cleanup_gpu_process()
                return False

            except Exception as e:
                logger.error(f"❌ GPU server start error | error={e}")
                self._cleanup_gpu_process()
                return False

    def stop_gpu_server(self) -> None:
        """Stop GPU server gracefully"""
        with self.connection_lock:
            self._cleanup_gpu_process()
            self.is_connected = False
            logger.info("⏹️ GPU server stopped")

    def connect(self) -> bool:
        """
        Connect to GPU server (start if needed)

        Returns:
            True if connected successfully, False otherwise
        """
        if not self.enable_gpu:
            return False

        # Try to connect to existing server first
        if self._is_server_responsive():
            self.is_connected = True
            self._refresh_gpu_info()
            return True

        # Try to start server if auto_start is enabled
        if self.auto_start:
            return self.start_gpu_server()

        # If auto_start disabled, still attempt to reconnect to externally started server
        logger.debug("⚠️ GPU not running | auto_start=disabled | retry_on_next")
        self.is_connected = False
        return False

    def get_gpu_info(self) -> Optional[Dict[str, Any]]:
        """
        Get GPU information from server (lightweight, no GPU occupation)

        Returns:
            GPU information dict or None if unavailable
        """
        if not self.enable_gpu:
            return None

        # Skip the complex is_available() check if we're already connected
        if not self.is_connected:
            if not self.connect():
                return None

        try:
            # Match CUDA program API format
            request = {"command": "get_gpu_info"}

            response = self._send_command(request)

            if response and response.get("success"):
                # Extract GPU info from CUDA program response format
                gpu_count = response.get("gpu_count", 0)
                gpus = response.get("gpus", [])

                # Convert to internal format
                gpu_uuids = [gpu.get("uuid", "") for gpu in gpus]

                self.gpu_info = {
                    "gpu_count": gpu_count,
                    "gpu_uuids": gpu_uuids,
                    "gpu_details": gpus,
                }
                self.gpu_uuids = gpu_uuids
                logger.debug(f"GPU info | count={gpu_count}")
                return self.gpu_info
            else:
                logger.error(f"❌ GPU info error | resp={response}")
                return None

        except Exception as e:
            logger.error(f"❌ GPU info error | error={e}")
            self._handle_communication_error()
            return None

    def submit_challenge(
        self, task_params: Dict[str, Any], timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Submit GPU matrix challenge to server (will occupy all available GPUs during computation)

        Args:
            task_params: Challenge parameters including seed, matrix_size, etc.
            timeout: Optional timeout in seconds (defaults to COMMAND_TIMEOUT)

        Returns:
            Challenge result data
        """
        if not self.is_available():
            if not self.connect():
                return {
                    "success": False,
                    "error": "GPU server not available",
                    "results": [],
                }

        try:
            # Convert seed to hex string if it's bytes
            seed = task_params.get("seed", "")
            if isinstance(seed, bytes):
                seed = seed.hex()

            request = {
                "command": "submit_challenge",
                "task": {
                    "seed": seed,
                    "target_gpu_id": task_params.get(
                        "target_gpu_id", -1
                    ),  # All available GPUs by default
                    "matrix_size": task_params.get("matrix_size", 1024),
                    "mode": task_params.get("mode", 0),  # GPU computation mode
                    "matrix_iterations": task_params.get(
                        "matrix_iterations", 1
                    ),  # Number of iterations
                },
            }

            logger.info(f"📤 GPU challenge | size={request['task']['matrix_size']}")

            response = self._send_command(
                request, timeout=timeout or self.COMMAND_TIMEOUT
            )

            if response and response.get("success"):
                results = response.get("results", [])
                logger.info(f"✅ GPU challenge complete | results={len(results)}")
                return response
            else:
                error_msg = (
                    response.get("error", "unknown") if response else "No response"
                )
                logger.error(f"❌ GPU challenge fail | error={error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "results": [],
                }

        except Exception as e:
            logger.error(f"❌ GPU submit error | error={e}")
            self._handle_communication_error()
            return {
                "success": False,
                "error": str(e),
                "results": [],
            }

    def get_result_values(
        self,
        gpu_uuid: str,
        coordinates: List[List[int]] = None,
        rows: List[int] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get coordinate values or full row data from GPU result

        Args:
            gpu_uuid: Target GPU UUID
            coordinates: List of [row, col] coordinate pairs for spot checks
            rows: List of row indices for full row requests
            timeout: Optional timeout in seconds

        Returns:
            Response with coordinate values in List[float] format
            Data layout: [coord_values...][row1_values...][row2_values...]
        """
        if not self.is_available():
            if not self.connect():
                return {"success": False, "error": "GPU server not available"}

        try:
            coord_queries = coordinates or []
            row_queries = rows or []

            logger.debug(
                f"🔎 GPU query | coords={len(coord_queries)} rows={len(row_queries)} uuid={gpu_uuid}"
            )

            all_values = []

            # Get coordinate values using get_result_coords API
            if coord_queries:
                coord_request = {
                    "command": "get_result_coords",
                    "gpu_uuid": gpu_uuid,
                    "queries": coord_queries,
                }

                coord_response = self._send_command(
                    coord_request, timeout=timeout or self.COMMAND_TIMEOUT
                )

                if not coord_response or not coord_response.get("success"):
                    error_msg = (
                        coord_response.get("error", "unknown")
                        if coord_response
                        else "No response"
                    )
                    logger.error(f"❌ GPU coord query fail | error={error_msg}")
                    return {
                        "success": False,
                        "error": f"Coordinate query failed: {error_msg}",
                    }

                all_values.extend(coord_response.get("values", []))

            # Get row data using get_result_rows API
            matrix_size = None
            if row_queries:
                row_request = {
                    "command": "get_result_rows",
                    "gpu_uuid": gpu_uuid,
                    "row_indices": row_queries,
                }

                row_response = self._send_command(
                    row_request, timeout=timeout or self.COMMAND_TIMEOUT
                )

                if not row_response or not row_response.get("success"):
                    error_msg = (
                        row_response.get("error", "Unknown error")
                        if row_response
                        else "No response"
                    )
                    logger.error(f"GPU row query failed: {error_msg}")
                    return {"success": False, "error": f"Row query failed: {error_msg}"}

                matrix_size = row_response.get("matrix_size")
                row_data = row_response.get("rows", {})

                # Append row data in order
                for row_idx in row_queries:
                    if str(row_idx) in row_data:
                        all_values.extend(row_data[str(row_idx)])
                    else:
                        logger.error(f"Missing row data for row {row_idx}")
                        return {
                            "success": False,
                            "error": f"Missing row data for row {row_idx}",
                        }

            logger.debug(
                f"Retrieved {len(all_values)} values from GPU: "
                f"{len(coord_queries)} coords + {len(row_queries)} rows"
            )

            # Return unified response format
            response = {
                "success": True,
                "values": all_values,
                "gpu_uuid": gpu_uuid,
            }

            if matrix_size:
                response["matrix_size"] = matrix_size

            return response

        except Exception as e:
            logger.error(f"Error querying GPU coordinate/row values: {e}")
            self._handle_communication_error()
            return {"success": False, "error": f"Communication error: {e}"}

    def clear_result_cache(
        self, gpu_uuid: Optional[str] = None, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Clear cached computation results from GPU memory

        Args:
            gpu_uuid: Specific GPU UUID to clear. If None, clears all caches.
            timeout: Optional timeout in seconds

        Returns:
            Response indicating success/failure of cache clearing
        """
        if not self.is_available():
            if not self.connect():
                return {"success": False, "error": "GPU server not available"}

        try:
            # Match GPU server clear_result_cache API format
            request = {"command": "clear_result_cache"}
            if gpu_uuid:
                request["gpu_uuid"] = gpu_uuid

            logger.debug(f"Clearing result cache for GPU: {gpu_uuid or 'all GPUs'}")

            response = self._send_command(
                request, timeout=timeout or self.COMMAND_TIMEOUT
            )

            if response and response.get("success"):
                cleared_count = response.get("cleared_count", 0)
                target_gpu = gpu_uuid or "all GPUs"
                logger.debug(f"Cache cleared for {target_gpu}: {cleared_count} entries")
                return response
            else:
                error_msg = (
                    response.get("error", "Unknown error")
                    if response
                    else "No response"
                )
                logger.error(f"Cache clear failed: {error_msg}")
                return {"success": False, "error": error_msg}

        except Exception as e:
            logger.error(f"Error clearing result cache: {e}")
            self._handle_communication_error()
            return {"success": False, "error": f"Communication error: {e}"}

    def ping(self) -> bool:
        """
        Ping GPU server to check connectivity

        Returns:
            True if server is responsive, False otherwise
        """
        try:
            # Match CUDA program ping format
            request = {"command": "ping"}

            response = self._send_command(request, timeout=5)

            # Check for "pong" response as per CUDA program spec
            is_responsive = response and response.get("pong") is True

            if is_responsive:
                self.last_ping_time = time.time()
                self.is_connected = True
            else:
                self.is_connected = False

            return is_responsive

        except Exception as e:
            self.is_connected = False
            return False

    def _send_command(
        self, request: Dict[str, Any], timeout: int = None
    ) -> Optional[Dict[str, Any]]:
        """
        Send command to GPU server via Unix Domain Socket

        Args:
            request: Request data to send
            timeout: Command timeout in seconds

        Returns:
            Response data or None if failed
        """
        if timeout is None:
            timeout = self.COMMAND_TIMEOUT

        try:
            # Create socket connection
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                # Connect to GPU server
                sock.connect(self.socket_path)

                # Serialize request to JSON
                request_json = json.dumps(request)
                request_bytes = request_json.encode("utf-8")

                # Protocol requires length prefix
                length = len(request_bytes)
                sock.sendall(struct.pack("<I", length))

                # Send message data
                sock.sendall(request_bytes)

                # Protocol requires reading length prefix
                length_data = sock.recv(4)
                if len(length_data) != 4:
                    raise GPUServerError("Failed to read response length")

                response_length = struct.unpack("<I", length_data)[0]

                # Sanity check
                if response_length > 16 * 1024 * 1024:
                    raise GPUServerError("Response too large")

                # Read response data
                response_data = b""
                while len(response_data) < response_length:
                    chunk = sock.recv(response_length - len(response_data))
                    if not chunk:
                        break
                    response_data += chunk

                if len(response_data) != response_length:
                    raise GPUServerError("Incomplete response received")

                # Parse JSON response
                response_json = response_data.decode("utf-8")
                response = json.loads(response_json)

                return response

            finally:
                sock.close()

        except socket.timeout:
            logger.warning(f"GPU socket timeout | timeout={timeout}s")
            return None
        except (socket.error, json.JSONDecodeError, Exception) as e:
            logger.error(f"❌ GPU communication error | error={e}")
            return None

    def _is_process_alive(self) -> bool:
        """Check if GPU server process is alive"""
        if not self.gpu_process:
            return False

        try:
            # Check if process is still running
            return self.gpu_process.poll() is None
        except Exception:
            return False

    def _is_server_responsive(self) -> bool:
        """Check if GPU server is responsive via socket connection"""
        try:
            # Check if socket exists
            if not os.path.exists(self.socket_path):
                return False

            # Try a quick ping
            result = self.ping()
            return result

        except (OSError, ValueError, RuntimeError) as e:
            return False

    def _cleanup_gpu_process(self) -> None:
        """Clean up GPU server process"""
        if self.gpu_process:
            try:
                # Try graceful termination first
                self.gpu_process.terminate()

                # Wait a bit for graceful shutdown
                try:
                    self.gpu_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    self.gpu_process.kill()
                    self.gpu_process.wait()

                logger.debug("GPU server process cleaned up")

            except Exception as e:
                logger.warning(f"Error cleaning up GPU process: {e}")

            finally:
                self.gpu_process = None

    def _refresh_gpu_info(self) -> None:
        """Refresh cached GPU information"""
        try:
            info = self.get_gpu_info()
            if info:
                self.gpu_info = info
                self.gpu_uuids = info.get("gpu_uuids", [])
                logger.debug(f"GPU info refreshed | count={len(self.gpu_uuids)}")
        except Exception as e:
            logger.warning(f"⚠️ GPU info refresh error | error={e}")

    def _handle_communication_error(self) -> None:
        """Handle communication error with server"""
        self.is_connected = False
        logger.debug(
            f"⚠️ GPU comm error | retry_next auto_start={'enabled' if self.auto_start else 'disabled'}"
        )

    def get_gpu_uuids(self) -> List[str]:
        """Get list of GPU UUIDs"""
        if not self.gpu_uuids and self.is_available():
            self._refresh_gpu_info()

        return self.gpu_uuids.copy()

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_gpu_server()
