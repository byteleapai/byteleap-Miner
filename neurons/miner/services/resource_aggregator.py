"""
Resource Aggregator Service
Aggregate system resources from multiple workers
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import bittensor as bt


@dataclass
class WorkerMetrics:
    """Worker system metrics with complete system information"""

    worker_id: str
    cpu_count: int
    cpu_usage: float
    memory_total_mb: int
    memory_available_mb: int
    memory_usage: float
    disk_total_gb: int
    disk_free_gb: int
    gpu_count: int
    gpu_info: List[Dict[str, Any]]
    last_updated: float

    # Complete system information for hardware_info table
    full_system_info: Dict[str, Any]


class ResourceAggregator:
    """Aggregate resources from multiple workers"""

    def __init__(self):
        """Initialize resource aggregator"""
        self.worker_metrics: Dict[str, WorkerMetrics] = {}
        self.aggregated_cache: Optional[Dict[str, Any]] = None
        self.cache_timestamp: float = 0
        self.cache_ttl: float = 30

        bt.logging.info("🧭 Resource aggregator initialized")

    def update_worker_metrics(
        self, worker_id: str, system_info: Dict[str, Any]
    ) -> None:
        """Update metrics for a worker including complete system information"""
        try:
            # System information provides resource tracking
            cpu_count = system_info.get("cpu_count", 0)
            cpu_usage = system_info.get("cpu_usage", 0.0)
            memory_total_mb = system_info.get("memory_total", 0)
            memory_available_mb = system_info.get("memory_available", 0)
            memory_usage = system_info.get("memory_usage", 0.0)
            disk_total_gb = system_info.get("disk_total", 0)
            disk_free_gb = system_info.get("disk_free", 0)
            gpu_info = system_info.get("gpu_info", [])
            gpu_count = len(gpu_info) if isinstance(gpu_info, list) else 0

            metrics = WorkerMetrics(
                worker_id=worker_id,
                cpu_count=cpu_count,
                cpu_usage=cpu_usage,
                memory_total_mb=memory_total_mb,
                memory_available_mb=memory_available_mb,
                memory_usage=memory_usage,
                disk_total_gb=disk_total_gb,
                disk_free_gb=disk_free_gb,
                gpu_count=gpu_count,
                gpu_info=gpu_info,
                last_updated=time.time(),
                full_system_info=system_info,
            )

            self.worker_metrics[worker_id] = metrics

            # Invalidate cache
            self.aggregated_cache = None

            bt.logging.debug(f"Metrics updated | worker_id={worker_id}")

        except Exception as e:
            bt.logging.error(
                f"❌ Metrics update error | worker_id={worker_id} error={e}"
            )

    def remove_worker_metrics(self, worker_id: str) -> None:
        """Remove metrics for a worker"""
        if worker_id in self.worker_metrics:
            del self.worker_metrics[worker_id]
            self.aggregated_cache = None
            bt.logging.debug(f"Metrics removed | worker_id={worker_id}")

    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics from all workers"""
        # Check cache
        current_time = time.time()
        if (
            self.aggregated_cache
            and current_time - self.cache_timestamp < self.cache_ttl
        ):
            return self.aggregated_cache

        # Calculate aggregated metrics
        aggregated = self._calculate_aggregated_metrics()

        # Update cache
        self.aggregated_cache = aggregated
        self.cache_timestamp = current_time

        return aggregated

    def get_miner_system_info(self) -> Optional[Dict[str, Any]]:
        """Get miner host system information (not worker aggregation)"""
        try:
            from neurons.shared.utils.system_monitor import \
                EnhancedSystemMonitor

            system_monitor = EnhancedSystemMonitor()
            return system_monitor.get_system_info()
        except Exception as e:
            bt.logging.error(f"❌ Miner system info error | error={e}")
            return None

    def _calculate_aggregated_metrics(self) -> Dict[str, Any]:
        """Calculate aggregated metrics from current worker data"""
        if not self.worker_metrics:
            return {
                "cpu_count": 0,
                "cpu_usage": 0.0,
                "memory_total": 0,
                "memory_available": 0,
                "memory_usage": 0.0,
                "disk_total": 0,
                "disk_free": 0,
                "gpu_count": 0,
                "gpu_info": [],
                "worker_count": 0,
                "online_workers": 0,
            }

        current_time = time.time()
        stale_timeout = 120

        # Filter online workers
        online_workers = [
            metrics
            for metrics in self.worker_metrics.values()
            if current_time - metrics.last_updated < stale_timeout
        ]

        if not online_workers:
            return {
                "cpu_count": 0,
                "cpu_usage": 0.0,
                "memory_total": 0,
                "memory_available": 0,
                "memory_usage": 0.0,
                "disk_total": 0,
                "disk_free": 0,
                "gpu_count": 0,
                "gpu_info": [],
                "worker_count": len(self.worker_metrics),
                "online_workers": 0,
            }

        # Aggregate CPU resources
        total_cpu_cores = sum(w.cpu_count for w in online_workers)
        weighted_cpu_usage = sum(w.cpu_usage * w.cpu_count for w in online_workers)
        avg_cpu_usage = (
            weighted_cpu_usage / total_cpu_cores if total_cpu_cores > 0 else 0.0
        )

        # Aggregate memory resources
        total_memory = sum(w.memory_total_mb for w in online_workers)
        total_memory_available = sum(w.memory_available_mb for w in online_workers)
        weighted_memory_usage = sum(
            w.memory_usage * w.memory_total_mb for w in online_workers
        )
        avg_memory_usage = (
            weighted_memory_usage / total_memory if total_memory > 0 else 0.0
        )

        # Aggregate disk resources
        total_disk = sum(w.disk_total_gb for w in online_workers)
        total_disk_free = sum(w.disk_free_gb for w in online_workers)

        # Aggregate GPU resources
        all_gpu_info = []
        total_gpu_count = 0

        for worker in online_workers:
            total_gpu_count += worker.gpu_count
            for gpu in worker.gpu_info:
                gpu_with_worker = dict(gpu)
                gpu_with_worker["worker_id"] = worker.worker_id
                all_gpu_info.append(gpu_with_worker)

        public_ip = None
        for worker in online_workers:
            worker_ip = (
                worker.system_info.get("public_ip")
                if hasattr(worker, "system_info")
                else None
            )
            if worker_ip:
                public_ip = worker_ip
                break

        return {
            "cpu_count": total_cpu_cores,
            "cpu_usage": avg_cpu_usage,
            "memory_total": total_memory,
            "memory_available": total_memory_available,
            "memory_usage": avg_memory_usage,
            "disk_total": total_disk,
            "disk_free": total_disk_free,
            "gpu_count": total_gpu_count,
            "gpu_info": all_gpu_info,
            "public_ip": public_ip,
            "worker_count": len(self.worker_metrics),
            "online_workers": len(online_workers),
            "workers": [
                {
                    "worker_id": w.worker_id,
                    "cpu_count": w.cpu_count,
                    "cpu_usage": w.cpu_usage,
                    "memory_total_mb": w.memory_total_mb,
                    "gpu_count": w.gpu_count,
                    "last_updated": w.last_updated,
                }
                for w in online_workers
            ],
        }

    def get_workers_info_for_validator(self, worker_manager) -> List[Dict[str, Any]]:
        """Get individual worker information for validator"""
        workers_info = []

        if not worker_manager:
            return workers_info

        for worker_id in worker_manager.get_connected_workers():
            worker_conn = worker_manager.workers.get(worker_id)
            if not worker_conn:
                continue

            worker_metrics = self.worker_metrics.get(worker_id)
            if not worker_metrics:
                system_info = worker_conn.system_info or {}
            else:
                system_info = dict(worker_metrics.full_system_info)
                system_info.update(
                    {
                        "cpu_count": worker_metrics.cpu_count,
                        "cpu_usage": worker_metrics.cpu_usage,
                        "memory_total": worker_metrics.memory_total_mb,
                        "memory_available": worker_metrics.memory_available_mb,
                        "memory_usage": worker_metrics.memory_usage,
                        "disk_total": worker_metrics.disk_total_gb,
                        "disk_free": worker_metrics.disk_free_gb,
                        "gpu_info": worker_metrics.gpu_info,
                    }
                )

            worker_info = {
                "worker_id": worker_id,
                "worker_name": worker_conn.worker_name,
                "capabilities": worker_conn.capabilities,
                "status": worker_conn.status,
                "system_info": system_info,
                "connected_at": worker_conn.connected_at,
                "last_heartbeat": worker_conn.last_heartbeat,
                "current_tasks": list(worker_conn.current_tasks),
            }

            workers_info.append(worker_info)

        return workers_info

    def get_worker_count(self) -> int:
        """Get total number of workers"""
        return len(self.worker_metrics)

    def get_online_worker_count(self) -> int:
        """Get number of online workers"""
        current_time = time.time()
        stale_timeout = 120

        online_count = sum(
            1
            for metrics in self.worker_metrics.values()
            if current_time - metrics.last_updated < stale_timeout
        )

        return online_count

    def get_worker_list(self) -> List[str]:
        """Get list of worker IDs"""
        return list(self.worker_metrics.keys())

    def get_worker_metrics(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific worker"""
        if worker_id not in self.worker_metrics:
            return None

        metrics = self.worker_metrics[worker_id]
        return {
            "worker_id": metrics.worker_id,
            "cpu_count": metrics.cpu_count,
            "cpu_usage": metrics.cpu_usage,
            "memory_total_mb": metrics.memory_total_mb,
            "memory_available_mb": metrics.memory_available_mb,
            "memory_usage": metrics.memory_usage,
            "disk_total_gb": metrics.disk_total_gb,
            "disk_free_gb": metrics.disk_free_gb,
            "gpu_count": metrics.gpu_count,
            "gpu_info": metrics.gpu_info,
            "last_updated": metrics.last_updated,
            "is_stale": time.time() - metrics.last_updated > 120,
        }

    def cleanup_stale_metrics(self, max_age_seconds: int = 300) -> None:
        """Clean up metrics older than max_age_seconds"""
        current_time = time.time()
        stale_workers = []

        for worker_id, metrics in self.worker_metrics.items():
            if current_time - metrics.last_updated > max_age_seconds:
                stale_workers.append(worker_id)

        for worker_id in stale_workers:
            del self.worker_metrics[worker_id]
            bt.logging.info(f"Cleaned up stale metrics for worker {worker_id}")

        if stale_workers:
            self.aggregated_cache = None  # Invalidate cache
