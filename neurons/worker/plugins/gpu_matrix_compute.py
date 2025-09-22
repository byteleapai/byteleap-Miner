"""
GPU Matrix Computation Plugin for Worker
Handles GPU matrix multiplication challenges from validators using CUDA
"""

import time
from typing import Any, Dict, List, Optional

from loguru import logger

from neurons.shared.challenges.gpu_matrix_challenge import GPUMatrixChallenge
from neurons.worker.clients.gpu_client import GPUServerClient, GPUServerError


class GPUMatrixComputePlugin:
    """GPU Matrix computation plugin for worker"""

    def __init__(self, config):
        """Initialize GPU matrix computation plugin"""
        self.plugin_name = "gpu_matrix_compute"
        self.config = config

        # Initialize GPU client
        self.gpu_client = GPUServerClient(config)

        # GPU capabilities cache
        self.gpu_count = 0
        self.gpu_uuids: List[str] = []
        self.gpu_details: List[Dict[str, Any]] = []
        self.last_gpu_info_update = 0
        self.gpu_info_cache_duration = 300
        self.gpu_occupied = False  # Track GPU occupation status

        # Try to connect and get initial GPU info without occupation
        self._refresh_gpu_capabilities()

        if self.is_gpu_available():
            logger.info(
                f"🧮 GPU plugin initialized | gpus={self.gpu_count} uuids={self.gpu_uuids}"
            )
        else:
            logger.warning("⚠️ GPU plugin initialized | gpus=0")

    def can_handle_task(self, task_type: str) -> bool:
        """Check if this plugin can handle the given task type"""
        if not self.is_gpu_available():
            return False

        return task_type in ["gpu_matrix", "gpu_challenge", "gpu_matrix_challenge"]

    def is_gpu_available(self) -> bool:
        """Check if GPU is available for computation"""
        # Use cached GPU info for capabilities check to avoid connection issues
        # Cache prevents excessive connection attempts
        return self.gpu_count > 0 and len(self.gpu_uuids) > 0

    def get_gpu_capabilities(self) -> Dict[str, Any]:
        """Get current GPU capabilities"""
        # Refresh attempts enable recovery from server disconnections
        current_time = time.time()
        if (current_time - self.last_gpu_info_update) > self.gpu_info_cache_duration:
            self._refresh_gpu_capabilities()

        if not self.is_gpu_available():
            return {
                "gpu_available": False,
                "gpu_count": 0,
                "gpu_details": [],
            }

        return {
            "gpu_available": True,
            "gpu_count": self.gpu_count,
            "gpu_details": self.gpu_details.copy() if self.gpu_details else [],
            "last_updated": self.last_gpu_info_update,
        }

    def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute GPU matrix multiplication task (will occupy all GPUs during execution)

        Args:
            task_data: Challenge data from validator containing GPU matrix info

        Returns:
            A dictionary containing the result and cacheable data.
        """
        try:
            logger.info("🧮 GPU challenge start")
            logger.debug(f"🧮 Task data | {task_data}")

            if "data" not in task_data:
                raise ValueError("Missing challenge data in task")

            challenge_data = task_data["data"]

            if not self.is_gpu_available():
                raise GPUServerError("GPU not available for computation")

            self.gpu_occupied = True

            try:
                # Prepare and submit the challenge to the GPU server
                task_params = {
                    "seed": challenge_data["seed"],
                    "matrix_size": challenge_data["matrix_size"],
                    "matrix_iterations": challenge_data.get("iterations", 1),
                }
                start_time = time.time()
                gpu_response = self.gpu_client.submit_challenge(task_params)
                end_time = time.time()
                execution_time_ms = (end_time - start_time) * 1000

                # Process the results using shared challenge logic
                result, cacheable_data = GPUMatrixChallenge.execute_challenge(
                    challenge_data, gpu_response, execution_time_ms
                )

                if "error" in result:
                    raise RuntimeError(
                        f"GPU challenge execution failed: {result['error']}"
                    )

                # Return a single dictionary containing both the result for the validator
                # and the data to be cached by the executor.
                return {
                    "success": True,
                    "result": result,
                    "cache_data": cacheable_data,
                    "execution_time": result.get("computation_time_ms", 0),
                    "plugin": self.plugin_name,
                }

            finally:
                self.gpu_occupied = False

        except Exception as e:
            logger.error(f"❌ GPU computation error | error={e}", exc_info=True)

            return {
                "success": False,
                "error": str(e),
                "result": {},
                "execution_time": float("inf"),
                "plugin": self.plugin_name,
            }

    def get_heartbeat_data(self) -> Dict[str, Any]:
        """
        Get GPU-specific data for heartbeat reporting

        Returns:
            Dictionary containing GPU UUIDs, status and occupation information
        """
        try:
            if not self.is_gpu_available():
                return {
                    "gpu_available": False,
                    "gpu_count": 0,
                    "gpu_uuids": [],
                    "gpu_occupied": False,
                }

            # Retrieve current GPU status
            gpu_info = self.gpu_client.get_gpu_info()
            if not gpu_info:
                return {
                    "gpu_available": False,
                    "gpu_count": 0,
                    "gpu_uuids": [],
                    "gpu_occupied": self.gpu_occupied,
                }

            # Extract GPU UUIDs and relevant information from CUDA format
            gpu_uuids = gpu_info.get("gpu_uuids", [])
            gpu_details = gpu_info.get("gpu_details", [])

            heartbeat_data = {
                "gpu_available": True,
                "gpu_count": len(gpu_uuids),
                "gpu_uuids": gpu_uuids.copy(),
                "gpu_occupied": self.gpu_occupied,  # Report current occupation status
                "gpu_details": [],
            }

            # Add GPU details for inventory tracking
            for i, gpu_uuid in enumerate(gpu_uuids):
                gpu_detail = {
                    "gpu_uuid": gpu_uuid,
                    "device_id": i,
                    "occupied": self.gpu_occupied,
                }

                # Add GPU specifications if available
                if i < len(gpu_details):
                    detail = gpu_details[i]
                    gpu_detail.update(
                        {
                            "model": detail.get("name", "Unknown"),
                            "memory_total": detail.get("memory_total", 0),
                            "memory_free": detail.get("memory_free", 0),
                            "compute_capability": detail.get("compute_capability", ""),
                            "multiprocessor_count": detail.get(
                                "multiprocessor_count", 0
                            ),
                            "clock_rate": detail.get("clock_rate", 0),
                        }
                    )

                heartbeat_data["gpu_details"].append(gpu_detail)

            return heartbeat_data

        except Exception as e:
            logger.warning(f"⚠️ GPU heartbeat error | error={e}")
            return {
                "gpu_available": False,
                "gpu_count": 0,
                "gpu_uuids": [],
                "gpu_occupied": self.gpu_occupied,
                "error": str(e),
            }

    def _refresh_gpu_capabilities(self) -> None:
        """Refresh GPU capabilities cache"""
        try:
            if self.gpu_client.connect():
                gpu_info = self.gpu_client.get_gpu_info()
                if gpu_info:
                    self.gpu_uuids = gpu_info.get("gpu_uuids", [])
                    self.gpu_details = gpu_info.get("gpu_details", [])
                    self.gpu_count = len(self.gpu_uuids)
                    self.last_gpu_info_update = time.time()
                    logger.debug(f"🧮 GPU capabilities | gpus={self.gpu_count}")
                else:
                    self.gpu_count = 0
                    self.gpu_uuids = []
                    self.gpu_details = []
            else:
                self.gpu_count = 0
                self.gpu_uuids = []
                self.gpu_details = []
                # Update timestamp even on connection failure
                self.last_gpu_info_update = time.time()
                logger.debug("⚠️ GPU connect failed | retry_on_refresh")

        except Exception as e:
            logger.warning(f"⚠️ GPU capabilities refresh error | error={e}")
            self.gpu_count = 0
            self.gpu_uuids = []
            self.gpu_details = []
            # Update timestamp even on failure to avoid excessive retry attempts
            self.last_gpu_info_update = time.time()

    def cleanup(self) -> None:
        """Cleanup GPU resources"""
        try:
            if self.gpu_client:
                self.gpu_client.stop_gpu_server()
                logger.debug("🧹 GPU plugin cleanup completed")
        except Exception as e:
            logger.warning(f"⚠️ GPU plugin cleanup error | error={e}")

    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except Exception:
            pass  # Ignore errors during destruction
