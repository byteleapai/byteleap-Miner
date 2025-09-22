"""
Compute Thread Manager
Independent CPU/GPU computation thread pools to avoid blocking the main event loop
"""

import asyncio
import threading
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from loguru import logger


class ComputeType(Enum):
    CPU = "cpu"
    GPU = "gpu"


@dataclass
class ComputeTask:
    """Compute task information"""

    task_id: str
    compute_type: ComputeType
    task_data: Dict[str, Any]
    plugin: Any
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    future: Optional[Future] = None


class ComputeThreadManager:
    """
    Independent compute thread manager

    Features:
    - Single thread execution for both CPU and GPU to avoid resource conflicts
    - Prevents duplicate task launches
    - Async result callbacks
    - Main thread continues business logic after thread execution completes
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Prevent resource conflicts
        self.cpu_executor: Optional[ThreadPoolExecutor] = None
        self.gpu_executor: Optional[ThreadPoolExecutor] = None

        self.active_tasks: Dict[str, ComputeTask] = {}
        self.cpu_busy = False
        self.gpu_busy = False
        self.task_lock = threading.Lock()

        self.is_running = False

        # Performance tracking
        self.task_metrics = defaultdict(
            lambda: {"total": 0, "success": 0, "failed": 0, "total_time": 0.0}
        )
        self.start_time = time.time()

        logger.info("🧵 ComputeThreadManager initialized | single-thread CPU/GPU")

    def start(self) -> None:
        """Start compute thread pools"""
        if self.is_running:
            logger.warning("ComputeThreadManager already running")
            return

        logger.info("🚀 ComputeThreadManager start")
        self.cpu_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="CPU-Compute"
        )

        self.gpu_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="GPU-Compute"
        )

        self.is_running = True
        logger.success("✅ ComputeThreadManager started")

    def stop(self) -> None:
        """Stop compute thread pools immediately"""
        if not self.is_running:
            return

        logger.info("⏹️ ComputeThreadManager stop")
        self.is_running = False

        # Prevent blocking on shutdown
        if self.cpu_executor:
            self.cpu_executor.shutdown(wait=False)
            self.cpu_executor = None

        if self.gpu_executor:
            self.gpu_executor.shutdown(wait=False)
            self.gpu_executor = None

        with self.task_lock:
            self.active_tasks.clear()
            self.cpu_busy = False
            self.gpu_busy = False

        logger.success("✅ ComputeThreadManager stopped")

    async def submit_compute_task(
        self,
        task_id: str,
        compute_type: ComputeType,
        task_data: Dict[str, Any],
        plugin: Any,
    ) -> Dict[str, Any]:
        """
        Submit compute task to independent thread pool

        Args:
            task_id: Task identifier
            compute_type: Computation type (CPU/GPU)
            task_data: Task data
            plugin: Execution plugin

        Returns:
            Compute result for continued business logic processing
        """
        if not self.is_running:
            raise RuntimeError("ComputeThreadManager not running")

        # Prevent resource conflicts
        with self.task_lock:
            if task_id in self.active_tasks:
                raise RuntimeError(f"Task {task_id} already exists")

            if compute_type == ComputeType.CPU and self.cpu_busy:
                raise RuntimeError(
                    "CPU computation already running, cannot start concurrent CPU tasks"
                )
            elif compute_type == ComputeType.GPU and self.gpu_busy:
                raise RuntimeError(
                    "GPU computation already running, cannot start concurrent GPU tasks"
                )
            compute_task = ComputeTask(
                task_id=task_id,
                compute_type=compute_type,
                task_data=task_data,
                plugin=plugin,
            )
            self.active_tasks[task_id] = compute_task

            if compute_type == ComputeType.CPU:
                self.cpu_busy = True
            else:
                self.gpu_busy = True

        executor = (
            self.cpu_executor if compute_type == ComputeType.CPU else self.gpu_executor
        )
        if not executor:
            raise RuntimeError(f"No executor available for {compute_type.value}")

        try:
            logger.info(f"📥 Submit compute | type={compute_type.value} id={task_id}")

            compute_task.started_at = time.time()
            future = executor.submit(self._execute_in_thread, compute_task)
            compute_task.future = future

            result = await asyncio.wrap_future(future)

            execution_time = time.time() - compute_task.started_at
            logger.success(
                f"✅ Compute complete | id={task_id} duration={execution_time:.2f}s"
            )

            self._record_task_metric(compute_type.value, True, execution_time)

            return result

        except Exception as e:
            logger.error(f"❌ Compute error | id={task_id} error={e}", exc_info=True)

            execution_time = (
                time.time() - compute_task.started_at if compute_task.started_at else 0
            )
            self._record_task_metric(compute_type.value, False, execution_time)
            raise
        finally:
            with self.task_lock:
                self.active_tasks.pop(task_id, None)
                if compute_type == ComputeType.CPU:
                    self.cpu_busy = False
                else:
                    self.gpu_busy = False

    def _execute_in_thread(self, compute_task: ComputeTask) -> Dict[str, Any]:
        """
        Execute compute task in independent thread

        Args:
            compute_task: Compute task information

        Returns:
            Compute result dictionary

        Raises:
            RuntimeError: When plugin execution fails
        """
        thread_name = threading.current_thread().name
        logger.debug(
            f"🧵 Thread exec | type={compute_task.compute_type.value} id={compute_task.task_id} thread={thread_name}"
        )

        try:
            if hasattr(compute_task.plugin, "execute_task"):
                result = compute_task.plugin.execute_task(compute_task.task_data)
            else:
                raise RuntimeError(
                    f"Plugin {compute_task.plugin} does not have execute_task method"
                )

            if result is None:
                raise RuntimeError(f"Plugin returned None result")

            return result

        except Exception as e:
            logger.error(
                f"❌ Thread exec error | id={compute_task.task_id} error={e}",
                exc_info=True,
            )
            raise RuntimeError(f"Task execution failed: {str(e)}") from e

    def get_active_task_count(self) -> int:
        """Get active task count"""
        with self.task_lock:
            return len(self.active_tasks)

    def get_compute_status(self) -> Dict[str, Any]:
        """Get compute status information"""
        with self.task_lock:
            return {
                "is_running": self.is_running,
                "active_tasks": len(self.active_tasks),
                "cpu_busy": self.cpu_busy,
                "gpu_busy": self.gpu_busy,
            }

    def is_gpu_available(self) -> bool:
        """Check if GPU is available for new tasks"""
        with self.task_lock:
            return not self.gpu_busy

    def is_cpu_available(self) -> bool:
        """Check if CPU is available for new tasks"""
        with self.task_lock:
            return not self.cpu_busy

    def _record_task_metric(
        self, task_type: str, success: bool, execution_time: float
    ) -> None:
        """Record task execution metrics"""
        with self.task_lock:
            metric = self.task_metrics[task_type]
            metric["total"] += 1
            if success:
                metric["success"] += 1
            else:
                metric["failed"] += 1
            metric["total_time"] += execution_time

    def get_metrics(self) -> Dict[str, Any]:
        """Get compute thread manager monitoring metrics"""
        with self.task_lock:
            uptime = time.time() - self.start_time
            metrics = {
                "uptime_seconds": uptime,
                "active_tasks": len(self.active_tasks),
                "cpu_busy": self.cpu_busy,
                "gpu_busy": self.gpu_busy,
                "task_stats": {},
            }

            # Calculate performance metrics
            for task_type, stats in self.task_metrics.items():
                total = stats["total"]
                if total > 0:
                    metrics["task_stats"][task_type] = {
                        "total_tasks": total,
                        "successful_tasks": stats["success"],
                        "failed_tasks": stats["failed"],
                        "success_rate": stats["success"] / total,
                        "average_execution_time": stats["total_time"] / total,
                        "total_execution_time": stats["total_time"],
                    }

            return metrics
