"""
Worker Manager Service
Manage WebSocket connections with workers and distribute tasks
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import bittensor as bt
import websockets
from websockets import State
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed, WebSocketException

from neurons.miner.services.message_models import (ProofResponseMessage,
                                                   TaskResultMessage,
                                                   WorkerHeartbeatMessage,
                                                   WorkerRegistration)
from neurons.shared.config.config_manager import ConfigManager
from neurons.shared.utils.error_handler import ErrorHandler, WorkerError

# Memory management constants
CONNECTION_CLOSE_DELAY = 0.5  # WebSocket connection cleanup delay

# WebSocket server constants
WS_PING_INTERVAL = 20
WS_PING_TIMEOUT = 30
WS_MAX_MESSAGE_SIZE = 16 * 1024 * 1024


@dataclass
class WorkerConnection:
    """Worker connection information"""

    worker_id: str
    worker_name: str
    worker_version: str
    websocket: ServerConnection
    capabilities: List[str]
    system_info: Dict[str, Any]
    last_heartbeat: float
    connected_at: float
    status: str  # online, busy, offline
    current_tasks: Set[str]


class WorkerManager:
    """Manage worker connections and task distribution"""

    def __init__(self, config: ConfigManager):
        """Initialize worker manager"""
        self.config = config
        self.host = config.get("worker_management.host")
        self.port = config.get_positive_number("worker_management.port", int)
        self.heartbeat_interval = config.get_positive_number(
            "worker_management.heartbeat_interval", int
        )
        self.heartbeat_timeout = config.get_positive_number(
            "worker_management.heartbeat_timeout", int
        )
        self.workers: Dict[str, WorkerConnection] = {}
        self.worker_lock = asyncio.Lock()
        self.websocket_server = None
        self.is_running = False
        self.communication_service = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._pending_proof_requests: Dict[str, asyncio.Future] = {}
        bt.logging.info(f"🧩 Worker manager initialized | addr={self.host}:{self.port}")

    async def _close_worker_connection_properly(
        self, worker_connection: WorkerConnection
    ):
        """Properly close worker WebSocket connection"""
        try:
            if hasattr(worker_connection, "websocket") and worker_connection.websocket:
                if hasattr(worker_connection, "current_tasks"):
                    worker_connection.current_tasks.clear()
                await worker_connection.websocket.close(
                    code=1001, reason="Connection replaced"
                )
                await asyncio.sleep(CONNECTION_CLOSE_DELAY)
                bt.logging.info(
                    f"🔐 Worker {worker_connection.worker_id} connection closed properly"
                )
        except Exception as e:
            bt.logging.warning(
                f"⚠️ Worker close error | id={worker_connection.worker_id} error={e}"
            )

    def set_communication_service(self, communication_service):
        self.communication_service = communication_service

    async def start(self):
        if self.is_running:
            bt.logging.warning("⚠️ Worker manager already running")
            return
        try:
            self.websocket_server = await serve(
                self._handle_worker_connection,
                self.host,
                self.port,
                ping_interval=WS_PING_INTERVAL,
                ping_timeout=WS_PING_TIMEOUT,
                max_size=WS_MAX_MESSAGE_SIZE,
            )
            self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
            self.is_running = True
            bt.logging.info(f"🧩 Worker manager started | ws://{self.host}:{self.port}")
        except Exception as e:
            bt.logging.error(f"❌ Worker manager start error | error={e}")
            raise

    async def stop(self):
        if not self.is_running:
            return
        bt.logging.info("⏹️ Stopping worker manager")
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                bt.logging.debug("Heartbeat monitor cancelled")
        async with self.worker_lock:
            for worker in list(self.workers.values()):
                try:
                    await worker.websocket.close()
                except Exception as e:
                    bt.logging.debug(f"Worker websocket close ignored error: {e}")
            self.workers.clear()
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        self.is_running = False
        bt.logging.info("🧩 Worker manager stopped")

    async def _handle_worker_connection(self, websocket: ServerConnection):
        worker_id = None
        try:
            registration_message = await asyncio.wait_for(websocket.recv(), timeout=30)
            registration_data = json.loads(registration_message)
            # Typed validation for registration
            try:
                reg = WorkerRegistration(**registration_data)
            except Exception as e:
                bt.logging.error(f"❌ Worker registration validation failed: {e}")
                bt.logging.error(f"Registration data: {registration_data}")
                await websocket.close(code=4000, reason="Invalid registration")
                return
            if reg.type != "register":
                await websocket.close(code=4000, reason="Invalid registration")
                return
            worker_id = reg.worker_id
            if not worker_id or not isinstance(worker_id, str) or not worker_id.strip():
                await websocket.close(code=4001, reason="Invalid or missing worker_id")
                return

            worker_name = reg.worker_name or worker_id
            bt.logging.debug(
                f"🧩 Registration received | id={worker_id} name={worker_name}"
            )

            # Enforce worker_version presence
            worker_version = reg.worker_version
            if not isinstance(worker_version, str) or not worker_version.strip():
                await websocket.close(code=4002, reason="Missing worker_version")
                return

            worker_connection = WorkerConnection(
                worker_id=worker_id,
                worker_name=worker_name,
                worker_version=worker_version,
                websocket=websocket,
                capabilities=reg.capabilities,
                system_info=reg.system_info,
                last_heartbeat=time.time(),
                connected_at=time.time(),
                status="online",
                current_tasks=set(),
            )
            async with self.worker_lock:
                if worker_id in self.workers:
                    await self._close_worker_connection_properly(
                        self.workers[worker_id]
                    )
                self.workers[worker_id] = worker_connection
            await websocket.send(
                json.dumps(
                    {"type": "registration_ack", "data": {"status": "registered"}}
                )
            )
            bt.logging.info(
                f"✅ Worker registered | id={worker_id} name={worker_connection.worker_name}"
            )
            await self._handle_worker_messages(worker_connection)
        except Exception as e:
            bt.logging.error(f"❌ Worker connection error | error={e}")
        finally:
            if worker_id:
                async with self.worker_lock:
                    if worker_id in self.workers:
                        del self.workers[worker_id]
                bt.logging.info(f"🧹 Worker cleaned up | id={worker_id}")

    async def _handle_worker_messages(self, worker: WorkerConnection):
        try:
            async for message in worker.websocket:
                try:
                    data = json.loads(message)
                    message_type = data.get("type")
                    bt.logging.debug(
                        f"📥 Worker message | type={message_type} id={worker.worker_id}"
                    )
                    if message_type == "heartbeat":
                        # Typed heartbeat validation
                        try:
                            hb = WorkerHeartbeatMessage(**data)
                        except Exception as e:
                            bt.logging.warning(
                                f"⚠️ Invalid heartbeat payload | id={worker.worker_id} error={e}"
                            )
                            continue
                        await self._handle_heartbeat(worker, hb.model_dump())
                    elif message_type == "task_result":
                        try:
                            tr = TaskResultMessage(**data)
                        except Exception as e:
                            bt.logging.warning(
                                f"⚠️ Invalid task_result payload | id={worker.worker_id} error={e}"
                            )
                            continue
                        await self._handle_task_result(worker, tr)
                    elif message_type == "proof_response":
                        bt.logging.debug(
                            f"🧪 proof_response handler | id={worker.worker_id}"
                        )
                        try:
                            pr = ProofResponseMessage(**data)
                        except Exception as e:
                            bt.logging.warning(
                                f"⚠️ Invalid proof_response payload | id={worker.worker_id} error={e}"
                            )
                            continue
                        await self._handle_proof_response(pr.model_dump())
                    else:
                        bt.logging.warning(
                            f"❓ Unknown worker message | id={worker.worker_id} type={message_type}"
                        )
                except json.JSONDecodeError as e:
                    bt.logging.warning(
                        f"⚠️ Invalid JSON from worker | id={worker.worker_id} error={e}"
                    )
                except Exception as e:
                    bt.logging.error(
                        f"❌ Worker message error | id={worker.worker_id} error={e}"
                    )
        except ConnectionClosed as e:
            bt.logging.info(
                f"🔌 Worker connection closed | id={worker.worker_id} code={e.code} reason={e.reason}"
            )
        except WebSocketException as e:
            bt.logging.warning(f"⚠️ WebSocket error | id={worker.worker_id} error={e}")
        except Exception as e:
            bt.logging.error(
                f"❌ Unexpected error in message loop | id={worker.worker_id} error={e}"
            )

    async def _handle_proof_response(self, data: Dict[str, Any]):
        message_id = data.get("message_id")
        bt.logging.debug(f"Proof response | message_id={message_id}")
        if message_id and message_id in self._pending_proof_requests:
            bt.logging.debug(
                f"🧪 Proof response future | found message_id={message_id}"
            )
            future = self._pending_proof_requests.pop(message_id)
            future.set_result(data.get("data"))
            bt.logging.debug(f"Proof response future set | message_id={message_id}")
        else:
            bt.logging.warning(f"⚠️ Missing proof future | message_id={message_id}")

    async def _handle_heartbeat(self, worker: WorkerConnection, data: Dict[str, Any]):
        worker.last_heartbeat = time.time()
        if worker.status != "busy":
            worker.status = "online"

        heartbeat_data = data.get("data", {})
        if "system_info" in heartbeat_data:
            worker.system_info = heartbeat_data["system_info"]

        if "capabilities" in heartbeat_data:
            worker.capabilities = heartbeat_data["capabilities"]

        if self.communication_service:
            worker_info = {
                "worker_id": worker.worker_id,
                "worker_name": worker.worker_name,
                "worker_version": worker.worker_version,
                "capabilities": worker.capabilities,
                "status": worker.status,
                "system_info": worker.system_info.copy(),
                "connected_at": worker.connected_at,
            }
            await self.communication_service.queue_worker_heartbeat(worker_info)
        await worker.websocket.send(json.dumps({"type": "heartbeat_ack"}))

    async def _handle_task_result(self, worker: WorkerConnection, data: Any):
        # data may be a TaskResultMessage or raw dict
        if hasattr(data, "task_id"):
            task_id = data.task_id
            result_data = data.data.model_dump() if hasattr(data, "data") else {}
        else:
            task_id = data.get("task_id")
            result_data = data.get("data", {})
        # Keep worker busy across two-phase flow (commit -> proof -> submit).
        # Finalization (unset busy) occurs when the challenge pipeline completes
        # or times out, via finalize_task_session().
        if self.communication_service:
            asyncio.create_task(
                self.communication_service.handle_worker_task_result(
                    task_id, result_data, worker.worker_id
                )
            )

    async def finalize_task_session(self, worker_id: str, task_id: str) -> None:
        """Mark task session complete and update worker status.

        Removes the task_id from the worker's current_tasks set and sets status
        to online if no other tasks are running.
        """
        async with self.worker_lock:
            worker = self.workers.get(worker_id)
            if not worker:
                return
            if task_id in worker.current_tasks:
                worker.current_tasks.remove(task_id)
            worker.status = "online" if not worker.current_tasks else "busy"

    async def _heartbeat_monitor(self):
        while self.is_running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                async with self.worker_lock:
                    stale_workers = [
                        worker_id
                        for worker_id, worker in self.workers.items()
                        if time.time() - worker.last_heartbeat > self.heartbeat_timeout
                    ]
                    for worker_id in stale_workers:
                        bt.logging.warning(
                            f"⏳ Worker heartbeat timeout | id={worker_id} action=remove"
                        )
                        try:
                            await self._close_worker_connection_properly(
                                self.workers[worker_id]
                            )
                        except Exception as e:
                            bt.logging.error(
                                f"❌ Worker close error | id={worker_id} error={e}"
                            )
                        finally:
                            self.workers.pop(worker_id, None)
            except asyncio.CancelledError:
                break
            except Exception as e:
                bt.logging.error(f"❌ Heartbeat monitor error | error={e}")
                await asyncio.sleep(10)

    async def distribute_task_to_worker(
        self, task_data: Dict[str, Any], worker_id: str
    ) -> bool:
        async with self.worker_lock:
            worker = self.workers.get(worker_id)
            if not worker or worker.status != "online":
                return False
            try:
                await worker.websocket.send(
                    json.dumps({"type": "task_assignment", "data": task_data})
                )
                worker.current_tasks.add(task_data["task_id"])
                worker.status = "busy"
                return True
            except WebSocketException as e:
                bt.logging.error(
                    f"❌ Send task error | worker_id={worker_id} error={e}"
                )
                return False

    def has_active_workers(self) -> bool:
        """Check if there are any active workers connected"""
        return len(self.workers) > 0 and any(
            worker.status == "online" for worker in self.workers.values()
        )

    def get_idle_worker_percentage(self) -> float:
        """Get percentage of workers that are idle (online)"""
        if not self.workers:
            return 0.0

        online_workers = sum(
            1 for worker in self.workers.values() if worker.status == "online"
        )
        return (online_workers / len(self.workers)) * 100.0

    def has_sufficient_idle_workers(self, threshold_percentage: float) -> bool:
        """Check if sufficient percentage of workers are idle"""
        return self.get_idle_worker_percentage() >= threshold_percentage

    def get_connected_workers(self) -> List[str]:
        """Get list of connected worker IDs"""
        return list(self.workers.keys())

    async def distribute_task_to_idle_worker(self, task_data: Dict[str, Any]) -> bool:
        """Distribute task to any available idle worker"""
        async with self.worker_lock:
            for worker_id, worker in self.workers.items():
                if worker.status == "online":
                    return await self.distribute_task_to_worker(task_data, worker_id)
        return False

    async def distribute_task_to_all(self, task_data: Dict[str, Any]) -> int:
        """Distribute task to all available workers, return number of successful distributions"""
        success_count = 0
        async with self.worker_lock:
            for worker_id, worker in self.workers.items():
                if worker.status == "online":
                    success = await self.distribute_task_to_worker(task_data, worker_id)
                    if success:
                        success_count += 1
        return success_count

    def get_status(self) -> Dict[str, Any]:
        """Get worker manager status information"""
        online_workers = sum(1 for w in self.workers.values() if w.status == "online")
        busy_workers = sum(1 for w in self.workers.values() if w.status == "busy")
        return {
            "total_workers": len(self.workers),
            "online_workers": online_workers,
            "busy_workers": busy_workers,
            "is_running": self.is_running,
        }

    async def get_challenge_proof(
        self,
        worker_id: str,
        validator_hotkey: str,
        challenge_id: str,
        proof_requests: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Request and retrieve a proof from a specific worker using the unified API.

        Args:
            worker_id: ID of the worker to request proof from.
            validator_hotkey: Validator's hotkey.
            challenge_id: Challenge identifier.
            proof_requests: A list of proof request objects, already serialized to dicts.
        """
        async with self.worker_lock:
            worker = self.workers.get(worker_id)
            if not worker or worker.websocket.state != State.OPEN:
                bt.logging.error(
                    f"❌ Worker not available for proof | worker_id={worker_id}"
                )
                return None

        message_id = str(uuid.uuid4())

        request_data = {
            "validator_hotkey": validator_hotkey,
            "challenge_id": challenge_id,
            "requests": proof_requests,
        }

        proof_request_message = {
            "type": "proof_request",
            "message_id": message_id,
            "data": request_data,
        }

        future = asyncio.get_running_loop().create_future()
        self._pending_proof_requests[message_id] = future

        try:
            await worker.websocket.send(json.dumps(proof_request_message))
            bt.logging.info(
                f"📨 Proof request sent | id={message_id} worker_id={worker_id}"
            )
            return await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            bt.logging.error(
                f"⏳ Proof response timeout | id={message_id} worker_id={worker_id}"
            )
            return None
        except Exception as e:
            bt.logging.error(
                f"❌ Proof request error | worker_id={worker_id} error={e}"
            )
            return None
        finally:
            self._pending_proof_requests.pop(message_id, None)
