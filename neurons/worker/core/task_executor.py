"""
Task Executor Module
Execute various types of compute tasks
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from loguru import logger

from neurons.worker.core.compute_thread_manager import (ComputeThreadManager,
                                                        ComputeType)
from neurons.worker.core.result_cache import ResultCache
from neurons.worker.plugins.cpu_matrix_compute import CPUMatrixComputePlugin
from neurons.worker.plugins.gpu_matrix_compute import GPUMatrixComputePlugin


@dataclass
class TaskInfo:
    """Task information"""

    task_id: str
    task_type: str
    task_data: Dict[str, Any]
    start_time: float
    timeout: float
    status: str  # pending, running, completed, failed, timeout


class TaskExecutor:
    """Execute compute tasks"""

    def __init__(self, config):
        """Initialize task executor"""
        self.config = config
        # Fail-fast with type validation
        from neurons.shared.config.config_manager import ConfigManager

        if not isinstance(config, ConfigManager):
            raise ValueError("TaskExecutor requires ConfigManager-compatible config")

        self.max_concurrent_tasks = config.get_positive_number(
            "max_concurrent_tasks", int
        )
        self.default_timeout = config.get_positive_number("default_task_timeout", int)
        self.active_tasks: Dict[str, TaskInfo] = {}
        self.task_lock = asyncio.Lock()
        self.plugins = {
            "cpu_matrix": CPUMatrixComputePlugin(),
            "gpu_matrix": GPUMatrixComputePlugin(config),
        }
        self.result_cache = ResultCache(config)
        self.completion_callback: Optional[Callable] = None
        self.is_running = False
        self._cleanup_task: Optional[asyncio.Task] = None

        # Compute thread manager
        self.compute_manager = ComputeThreadManager(config.config)

    async def start(self):
        self.is_running = True
        self.compute_manager.start()
        self._cleanup_task = asyncio.create_task(self._cleanup_tasks())

    async def stop(self):
        self.is_running = False
        self.compute_manager.stop()
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        async with self.task_lock:
            for task_info in list(self.active_tasks.values()):
                task_info.status = "cancelled"
            self.active_tasks.clear()

    def set_completion_callback(self, callback: Callable):
        self.completion_callback = callback

    async def execute_task(self, task_data: Dict[str, Any]) -> bool:
        task_id = task_data.get("task_id")
        task_type = task_data.get("task_type")
        timeout = task_data.get("timeout", self.default_timeout)
        if not task_id or not task_type:
            return False
        async with self.task_lock:
            if len(self.active_tasks) >= self.max_concurrent_tasks:
                logger.warning(f"⚠️ Max concurrency reached | reject id={task_id}")
                return False
            task_info = TaskInfo(
                task_id=task_id,
                task_type=task_type,
                task_data=task_data,
                start_time=time.time(),
                timeout=timeout,
                status="pending",
            )
            self.active_tasks[task_id] = task_info
        asyncio.create_task(self._execute_task_async(task_info))
        return True

    async def _execute_task_async(self, task_info: TaskInfo):
        worker_task_received_ts = int(
            task_info.start_time * 1000
        )  # Task received timestamp

        try:
            task_info.status = "running"
            plugin = self.plugins[task_info.task_type]

            # Determine compute type
            compute_type = (
                ComputeType.GPU
                if task_info.task_type == "gpu_matrix"
                else ComputeType.CPU
            )

            # Execute task through compute thread manager
            plugin_response = await self.compute_manager.submit_compute_task(
                task_id=task_info.task_id,
                compute_type=compute_type,
                task_data=task_info.task_data,
                plugin=plugin,
            )

            # Defensive check for None response from plugin
            if plugin_response is None:
                raise RuntimeError(
                    f"Plugin {task_info.task_type} returned None response"
                )

            task_info.status = "completed"

            worker_task_completed_ts = int(
                time.time() * 1000
            )  # Task completed timestamp
            execution_time = time.time() - task_info.start_time
            logger.debug(
                f"Task completed | id={task_info.task_id} duration={execution_time:.2f}s"
            )

            plugin_response["timestamps"] = {
                "worker_task_received_ts": worker_task_received_ts,
                "worker_task_completed_ts": worker_task_completed_ts,
            }

            cacheable_data = plugin_response.pop("cache_data", None)
            validator_hotkey = task_info.task_data.get("validator_hotkey")

            # Normalize plugin response schema for miner consumption
            try:
                if "success" not in plugin_response:
                    # Derive success from error_code if present
                    if "error_code" in plugin_response:
                        plugin_response["success"] = (
                            plugin_response.get("error_code", 1) == 0
                        )
                    else:
                        plugin_response["success"] = True
                if "error_code" not in plugin_response:
                    # Map success to standard success code 0
                    from neurons.shared.protocols import ErrorCodes

                    plugin_response["error_code"] = (
                        ErrorCodes.SUCCESS
                        if plugin_response["success"]
                        else ErrorCodes.CHALLENGE_PROCESSING_FAILED
                    )
            except Exception:
                # Do not fail task completion on normalization errors
                pass

            if validator_hotkey and cacheable_data:
                self.result_cache.add_cacheable_data(validator_hotkey, cacheable_data)

            if self.completion_callback:
                await self.completion_callback(task_info.task_id, plugin_response)

        except Exception as e:
            logger.debug(f"Task failed | id={task_info.task_id} error={e}")
            task_info.status = "failed"
            if self.completion_callback:
                await self.completion_callback(task_info.task_id, {"error": str(e)})
        finally:
            async with self.task_lock:
                if task_info.task_id in self.active_tasks:
                    del self.active_tasks[task_info.task_id]

    async def generate_proofs(
        self, validator_hotkey: str, proof_requests: List[Dict[str, Any]]
    ) -> List[Optional[Dict[str, Any]]]:
        """
        Generates proofs for a list of request items using the unified cache.

        Args:
            validator_hotkey: The hotkey of the validator requesting the proofs.
            proof_requests: A list of individual proof request objects.

        Returns:
            A list of proof result objects, one for each request item.
        """
        proofs = []
        if not validator_hotkey or not proof_requests:
            return []

        for request_item in proof_requests:
            proof = self.result_cache.generate_proof(validator_hotkey, request_item)
            proofs.append(proof)

        # Clear the cache for the validator after all proofs have been generated.
        self.result_cache.clear_cache_for_validator(validator_hotkey)

        return proofs

    async def _cleanup_tasks(self):
        while self.is_running:
            try:
                await asyncio.sleep(60)
                async with self.task_lock:
                    stale_tasks = [
                        tid
                        for tid, info in self.active_tasks.items()
                        if time.time() - info.start_time > info.timeout + 120
                    ]
                    for tid in stale_tasks:
                        logger.warning(f"🧹 Cleaning stale task | id={tid}")
                        self.active_tasks.pop(tid, None)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Task cleanup error | error={e}")
                await asyncio.sleep(30)

    def get_capabilities(self) -> List[str]:
        """
        Get current worker capabilities based on available and functional plugins

        Returns:
            List of capability strings for available plugins
        """
        capabilities = []

        if "cpu_matrix" in self.plugins:
            capabilities.append("cpu_matrix")

        if "gpu_matrix" in self.plugins:
            gpu_plugin = self.plugins["gpu_matrix"]
            if (
                hasattr(gpu_plugin, "is_gpu_available")
                and gpu_plugin.is_gpu_available()
            ):
                capabilities.append("gpu_matrix")

        return capabilities

    def get_gpu_heartbeat_data(self) -> Dict[str, Any]:
        """
        Get GPU information for heartbeat data

        Returns:
            Dictionary containing GPU availability and count information
        """
        if "gpu_matrix" in self.plugins:
            gpu_plugin = self.plugins["gpu_matrix"]
            if hasattr(gpu_plugin, "get_gpu_capabilities"):
                return gpu_plugin.get_gpu_capabilities()

        return {"gpu_available": False, "gpu_count": 0}

    def get_active_task_count(self) -> int:
        """
        Get the number of currently active tasks

        Returns:
            Number of active tasks
        """
        return len(self.active_tasks)

    async def cleanup(self):
        """Clean up task executor resources"""
        await self.stop()
