"""
Heartbeat Service
Manages worker heartbeat queue, deduplication, packaging and sending.
"""

import time
from typing import Any, Dict, List, Optional

import bittensor as bt

from neurons.shared.protocols import HeartbeatData, SystemInfo


class HeartbeatService:
    def __init__(
        self,
        wallet: bt.wallet,
        resource_aggregator,
        validator_cache,
        transport,
        heartbeat_cleanup_interval: int = 300,
        max_pending_heartbeats: int = 1000,
        heartbeat_age_seconds: int = 300,
        miner_version: Optional[str] = None,
    ) -> None:
        self.wallet = wallet
        self.resource_aggregator = resource_aggregator
        self.validator_cache = validator_cache
        self.transport = transport
        self.miner_version = miner_version

        self._pending_worker_heartbeats: List[Dict[str, Any]] = []
        self._last_heartbeat_cleanup: float = 0
        self._heartbeat_cleanup_interval = heartbeat_cleanup_interval
        self._max_pending_heartbeats = max_pending_heartbeats
        self._heartbeat_age_seconds = heartbeat_age_seconds

    def queue_worker_heartbeat(self, worker_info: Dict[str, Any]) -> None:
        now = time.time()
        # Drop invalid
        wid = worker_info.get("worker_id")
        if not isinstance(wid, str) or not wid.strip():
            bt.logging.warning("⚠️ Reject heartbeat | reason=invalid worker_id")
            return
        if not isinstance(worker_info.get("system_info"), dict):
            bt.logging.warning(
                f"⚠️ Reject heartbeat | worker_id={wid} reason=invalid system_info"
            )
            return

        # Periodic cleanup
        if now - self._last_heartbeat_cleanup > self._heartbeat_cleanup_interval:
            self._cleanup_old_heartbeats(now)
            self._last_heartbeat_cleanup = now

        # Limit queue size
        if len(self._pending_worker_heartbeats) >= self._max_pending_heartbeats:
            bt.logging.warning(
                f"⚠️ Heartbeat queue full | max={self._max_pending_heartbeats} action=drop_oldest"
            )
            remove_count = max(1, self._max_pending_heartbeats // 10)
            self._pending_worker_heartbeats = self._pending_worker_heartbeats[
                remove_count:
            ]

        self._pending_worker_heartbeats.append(
            {"worker_info": worker_info, "timestamp": now}
        )

    def _cleanup_old_heartbeats(self, current_time: float) -> None:
        cutoff = current_time - self._heartbeat_age_seconds
        before = len(self._pending_worker_heartbeats)
        self._pending_worker_heartbeats = [
            hb
            for hb in self._pending_worker_heartbeats
            if hb.get("timestamp", 0) > cutoff
        ]
        after = len(self._pending_worker_heartbeats)
        if before != after:
            bt.logging.debug(
                f"Heartbeat cleanup | removed={before-after} remaining={after}"
            )

    async def send_scheduled_heartbeat(self) -> int:
        if not self._pending_worker_heartbeats:
            return 0

        # Snapshot and clear queue
        heartbeats = self._pending_worker_heartbeats
        self._pending_worker_heartbeats = []

        if not heartbeats:
            return 0

        try:
            # Deduplicate by worker_id
            dedup_index: Dict[str, int] = {}
            for idx, hb in enumerate(heartbeats):
                winfo = hb.get("worker_info", {})
                wid = winfo.get("worker_id")
                ts = hb.get("timestamp", 0)
                if not wid:
                    continue
                if wid not in dedup_index or ts > heartbeats[dedup_index[wid]].get(
                    "timestamp", 0
                ):
                    dedup_index[wid] = idx

            items = [heartbeats[i] for i in dedup_index.values()]

            workers: List[Any] = []

            # Miner host info
            miner_info = None
            miner_system = self.resource_aggregator.get_miner_system_info()
            if miner_system:
                miner_info = SystemInfo(
                    cpu_count=miner_system.get("cpu_count", 0),
                    cpu_usage=miner_system.get("cpu_usage", 0.0),
                    memory_total=miner_system.get("memory_total", 0),
                    memory_available=miner_system.get("memory_available", 0),
                    memory_usage=miner_system.get("memory_usage", 0.0),
                    disk_total=miner_system.get("disk_total", 0),
                    disk_free=miner_system.get("disk_free", 0),
                    gpu_info=miner_system.get("gpu_info", []),
                    public_ip=miner_system.get("public_ip"),
                    cpu_info=miner_system.get("cpu_info"),
                    memory_info=miner_system.get("memory_info"),
                    system_info=miner_system.get("system_info"),
                    motherboard_info=miner_system.get("motherboard_info"),
                    uptime_seconds=miner_system.get("uptime_seconds"),
                    storage_info=miner_system.get("storage_info"),
                    miner_version=self.miner_version,
                )

            for hb in items:
                w = hb.get("worker_info", {})
                try:
                    sysinfo = SystemInfo(**w.get("system_info", {}))
                    workers.append(
                        {
                            "worker_id": w.get("worker_id"),
                            "worker_name": w.get("worker_name"),
                            "worker_version": w.get("worker_version"),
                            "capabilities": w.get("capabilities", []),
                            "status": w.get("status", "offline"),
                            "system_info": sysinfo.model_dump(),
                            "connected_at": w.get("connected_at", time.time()),
                            "last_heartbeat": hb.get("timestamp"),
                        }
                    )
                except Exception:
                    bt.logging.warning(
                        f"⚠️ Skip malformed worker heartbeat | worker_id={w.get('worker_id')}"
                    )

            heartbeat = HeartbeatData(
                hotkey=self.wallet.hotkey.ss58_address,
                timestamp=time.time(),
                workers=workers,  # pydantic will coerce list of dicts to models
                miner_info=miner_info,
            )

            # Send out
            validators = self.validator_cache.get_validators()
            if not validators:
                return 0

            from neurons.shared.protocols import (ProtocolRegistry,
                                                  ProtocolTypes)

            result = await self.transport.send_to_validators(
                operation="heartbeat",
                synapse_class=ProtocolRegistry.get(ProtocolTypes.HEARTBEAT),
                request_data=heartbeat,
                validators=validators,
                timeout=30,
            )
            if result.success and isinstance(result.data, dict):
                return result.data.get("success_count", 0)
            return 0
        except Exception as e:
            bt.logging.error(f"❌ Heartbeat send error | error={e}")
            return 0
