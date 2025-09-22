"""
CPU Matrix Computation Plugin for Worker
Handles CPU matrix multiplication challenges from validators
"""

from multiprocessing import cpu_count
from typing import Any, Dict, Optional

from loguru import logger

from neurons.shared.challenges.cpu_matrix_challenge import CPUMatrixChallenge
from neurons.shared.protocols import ErrorCodes


class CPUMatrixComputePlugin:
    """CPU Matrix computation plugin for worker"""

    def __init__(self):
        """Initialize CPU matrix computation plugin"""
        self.plugin_name = "cpu_matrix_compute"
        self.cpu_cores = cpu_count()
        logger.info(f"🧮 CPU plugin initialized | cores={self.cpu_cores}")

    def can_handle_task(self, task_type: str) -> bool:
        """Check if this plugin can handle the given task type"""
        return task_type in ["cpu_matrix", "matrix_multiply", "cpu_challenge"]

    def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute CPU matrix multiplication task

        Args:
            task_data: Challenge data from validator containing matrix info

        Returns:
            A dictionary containing the result and cacheable data.
        """
        try:
            logger.info("🧮 CPU challenge start")
            logger.debug(f"🧮 Task data | {task_data}")

            if "data" not in task_data:
                raise ValueError("Missing challenge data in task")

            challenge_data = task_data["data"]

            # Execute the challenge using the shared CPU matrix algorithm
            result, cacheable_data = CPUMatrixChallenge.execute_challenge(
                challenge_data=challenge_data, actual_cores=self.cpu_cores
            )

            if "error" in result:
                raise RuntimeError(result["error"])

            # Return a single dictionary containing both the result for the validator
            # and the data to be cached by the executor.
            return {
                "success": True,
                "error_code": ErrorCodes.SUCCESS,
                "result": result,
                "cache_data": cacheable_data,
                "computation_time_ms": result.get("computation_time_ms", 0),
                "plugin_name": self.plugin_name,
                "cpu_cores_used": self.cpu_cores,
                "challenge_id": task_data.get("challenge_id"),
            }

        except Exception as e:
            error_msg = f"❌ CPU computation error | error={e}"
            logger.error(error_msg)

            return {
                "success": False,
                "error_code": ErrorCodes.CHALLENGE_PROCESSING_FAILED,
                "error_message": error_msg,
                "result": {},
                "computation_time_ms": 0,
                "plugin_name": self.plugin_name,
                "challenge_id": task_data.get("challenge_id"),
            }

    def get_plugin_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            "name": self.plugin_name,
            "description": "CPU Matrix multiplication challenge execution",
            "supported_task_types": ["cpu_matrix", "matrix_multiply", "cpu_challenge"],
            "cpu_cores": self.cpu_cores,
            "capabilities": {
                "matrix_multiplication": True,
                "multi_core_scaling": True,
                "memory_intensive": True,
            },
        }

    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute method required by task executor interface

        Args:
            task_data: Task data from task executor

        Returns:
            Result data with computation time and matrix hash
        """
        # Run the synchronous execute_task in a thread pool
        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.execute_task, task_data)

    def get_performance_info(self) -> Dict[str, Any]:
        """Get performance-related information"""
        return {
            "cpu_cores": self.cpu_cores,
            "estimated_matrix_ops_per_second": self.cpu_cores
            * 1_000_000,  # Rough estimate
            "memory_efficiency": "high",
            "scaling_factor": "linear",
        }
