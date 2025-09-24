"""
Miner Communication Service
Responsible for network communication with validator, including heartbeat reporting and task polling
"""

import asyncio
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import bittensor as bt

if TYPE_CHECKING:
    from neurons.miner.services.resource_aggregator import ResourceAggregator
    from neurons.miner.services.worker_manager import WorkerManager

from neurons.miner.services.challenge_pipeline import ChallengePipeline
from neurons.miner.services.heartbeat_service import HeartbeatService
from neurons.miner.services.session_transport import SessionTransport
from neurons.miner.services.validator_cache import ValidatorCache
from neurons.shared.base_communication import BaseCommunicationService
from neurons.shared.config.config_manager import ConfigManager
from neurons.shared.protocols import (CommunicationResult, ComputeChallenge,
                                      ProtocolRegistry, ProtocolTypes,
                                      TaskRequest, TaskResponse)

# Memory management constants
MAX_PENDING_HEARTBEATS = 1000  # Prevent memory exhaustion
HEARTBEAT_CLEANUP_INTERVAL = 300  # Interval for cleaning old heartbeat data
HEARTBEAT_CLEANUP_AGE_SECONDS = 300  # Age threshold for heartbeat data expiration

# Network timeout constants
DEFAULT_HEARTBEAT_TIMEOUT = 30  # Timeout for heartbeat requests
DEFAULT_TASK_TIMEOUT = 10  # Timeout for task requests
DEFAULT_CHALLENGE_TIMEOUT = 300  # Challenge request timeout
COMM_TASK_SHUTDOWN_TIMEOUT = 1  # Timeout for communication task shutdown

# Loop and retry constants
COMMUNICATION_LOOP_SLEEP_SECONDS = 1  # Sleep interval in communication loop
RETRY_BACKOFF_ATTEMPTS = 5  # Number of retry attempts after communication error


class MinerCommunicationService(BaseCommunicationService):
    """
    Miner communication service for validator network communication

    Responsibilities:
    - Manage heartbeat reporting to validators
    - Poll tasks from validators and distribute to workers
    - Forward worker task results to validators
    - Handle validator discovery and selection
    """

    def __init__(
        self,
        wallet: bt.wallet,
        subtensor: bt.subtensor,
        metagraph: bt.metagraph,
        config: ConfigManager,
        worker_manager: "WorkerManager",
        resource_aggregator: "ResourceAggregator",
        miner_version: Optional[str] = None,
    ):
        """
        Initialize communication service

        Args:
            wallet: Bittensor wallet instance
            subtensor: Bittensor subtensor instance
            metagraph: Bittensor metagraph instance
            config: Complete miner configuration
            worker_manager: Worker manager service for task distribution
            resource_aggregator: Resource aggregator service for system metrics

        Raises:
            ValueError: If configuration values are invalid
            KeyError: If required configuration keys are missing
        """
        super().__init__(wallet, config, "miner")

        from neurons.miner.services.session_cache import SessionCache
        from neurons.shared.crypto import CryptoManager

        self.session_crypto = CryptoManager(wallet)
        self.session_cache = SessionCache(self.session_crypto, config.config)
        self.transport = SessionTransport(
            wallet, self.session_cache, self.session_crypto
        )

        # Miner-specific configuration
        self.netuid = config.get_positive_number("netuid", int)
        self.heartbeat_interval = config.get_positive_number("heartbeat_interval", int)
        self.task_poll_interval = config.get_positive_number("task_poll_interval", int)
        self.max_retries = config.get_positive_number("max_retries", int)

        # Network components
        self.subtensor = subtensor
        self.metagraph = metagraph
        self.wallet = wallet

        self.validator_cache = ValidatorCache(
            subtensor, int(self.netuid), config, metagraph
        )

        # Service state
        self.is_running = False
        self._comm_task: Optional[asyncio.Task] = None
        self._polling_task: Optional[asyncio.Task] = None
        self.worker_manager = worker_manager
        self.resource_aggregator = resource_aggregator

        # Validator polling rotation state
        self._polling_start_index = 0
        self.miner_version = miner_version

        # Services
        self.heartbeat_service = HeartbeatService(
            wallet,
            resource_aggregator,
            self.validator_cache,
            self.transport,
            HEARTBEAT_CLEANUP_INTERVAL,
            MAX_PENDING_HEARTBEATS,
            HEARTBEAT_CLEANUP_AGE_SECONDS,
            miner_version=self.miner_version,
        )
        self.challenge_pipeline = ChallengePipeline(self.transport, worker_manager)

    # Cleanup handled by services

    async def start(self) -> None:
        """
        Start communication service and sync metagraph

        Raises:
            RuntimeError: If service is already running
        """
        if self.is_running:
            bt.logging.warning("⚠️ Communication service already running")
            return

        bt.logging.debug("Validator cache start")
        # Start validator cache background tasks
        await self.validator_cache.start()
        bt.logging.debug("Validator cache started")

        # Direct validators are validated against metagraph

        self.is_running = True
        self._comm_task = asyncio.create_task(self._communication_loop())
        self._polling_task = asyncio.create_task(self._polling_loop())
        bt.logging.info("🚀 Communication service started")

    async def stop(self) -> None:
        """Stop communication service and cleanup resources"""
        if not self.is_running:
            return

        self.is_running = False

        # Cancel both tasks
        tasks_to_cancel = []
        if self._comm_task:
            tasks_to_cancel.append(self._comm_task)
        if self._polling_task:
            tasks_to_cancel.append(self._polling_task)

        for task in tasks_to_cancel:
            task.cancel()

        # Wait for both to finish
        for task in tasks_to_cancel:
            try:
                await asyncio.wait_for(task, timeout=COMM_TASK_SHUTDOWN_TIMEOUT)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        bt.logging.debug("Communication resources cleaned up")

        # Stop validator cache
        await self.validator_cache.stop()
        bt.logging.info("✅ Communication service stopped")

    async def _communication_loop(self) -> None:
        """Main communication loop for heartbeat and other non-polling tasks"""

        last_batch_heartbeat = 0

        while self.is_running:
            try:
                current_time = time.time()

                # Send batched worker heartbeats if any are pending
                if current_time - last_batch_heartbeat >= self.heartbeat_interval:
                    await self._send_scheduled_heartbeat()
                    last_batch_heartbeat = current_time

                # Sleep for heartbeat interval
                await asyncio.sleep(self.heartbeat_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                bt.logging.error(f"❌ Communication loop error | error={e}")
                # Wait before retry
                await asyncio.sleep(RETRY_BACKOFF_ATTEMPTS)

    async def _polling_loop(self) -> None:
        """Dedicated polling loop for task polling with capacity-aware spinning"""

        while self.is_running:
            try:
                # Poll tasks with capacity checking and spinning
                await self._poll_tasks_with_capacity_spinning()

                # Respect configured polling frequency
                await asyncio.sleep(self.task_poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                bt.logging.error(f"❌ Polling loop error | error={e}")
                # Wait before retry
                await asyncio.sleep(RETRY_BACKOFF_ATTEMPTS)

    # Heartbeat sending is delegated to HeartbeatService

    async def queue_worker_heartbeat(self, worker_info: Dict[str, Any]) -> None:
        """
        Queue worker heartbeat for batched delivery

        Args:
            worker_info: Worker information and metrics
        """
        # Delegate to heartbeat service (synchronous enqueue)
        self.heartbeat_service.queue_worker_heartbeat(worker_info)

    async def _send_scheduled_heartbeat(self) -> None:
        """Send batched worker heartbeats to validators"""

        # Delegate to heartbeat service
        try:
            count = await self.heartbeat_service.send_scheduled_heartbeat()
            bt.logging.debug(f"Heartbeat batch forwarded | count={count}")
        except Exception as e:
            bt.logging.error(f"❌ Heartbeats forward error | error={e}")

    async def handle_worker_task_result(
        self, task_id: str, result: Dict[str, Any], worker_id: str
    ):
        """
        Handle task result from worker and forward to validators.
        """
        try:
            # Defensive validation of required parameters
            if not isinstance(task_id, str) or not task_id.strip():
                bt.logging.warning("⚠️ Ignore task result | reason=invalid task_id")
                await self.worker_manager.finalize_task_session(
                    worker_id, task_id or ""
                )
                return
            if not isinstance(worker_id, str) or not worker_id.strip():
                bt.logging.warning(
                    f"⚠️ Ignore task result | task_id={task_id} reason=invalid worker_id"
                )
                await self.worker_manager.finalize_task_session(worker_id, task_id)
                return
            if not isinstance(result, dict):
                bt.logging.warning(
                    f"⚠️ Ignore task result | task_id={task_id} reason=invalid result format"
                )
                await self.worker_manager.finalize_task_session(worker_id, task_id)
                return
            bt.logging.debug(f"Task result | task_id={task_id} worker_id={worker_id}")
            bt.logging.debug(f"Task result data | {self._truncate_log_data(result)}")

            # Check for error conditions - success=False or explicit error_code != 0
            if not result.get("success", False) or result.get("error_code", 0) != 0:
                error_msg = result.get("error", "unknown")
                bt.logging.warning(
                    f"❌ Task failed | task_id={task_id} worker_id={worker_id} error={error_msg}"
                )
                await self.worker_manager.finalize_task_session(worker_id, task_id)
                return

            challenge_result = result.get("result", {})
            if not isinstance(challenge_result, dict):
                bt.logging.error(
                    f"❌ Task result malformed | task_id={task_id} reason=result not dict"
                )
                await self.worker_manager.finalize_task_session(worker_id, task_id)
                return
            if not challenge_result.get("commitments"):
                bt.logging.error(
                    f"❌ Task result missing commitments | task_id={task_id}"
                )
                await self.worker_manager.finalize_task_session(worker_id, task_id)
                return

            # Merge worker timestamps into pipeline state
            worker_timestamps = result.get("timestamps", {})
            self.challenge_pipeline.merge_worker_timestamps(task_id, worker_timestamps)
            await self.challenge_pipeline.handle_task_result(task_id, result, worker_id)
        except Exception as e:
            bt.logging.error(
                f"Error handling worker task result for {task_id}: {e}", exc_info=True
            )

    # Two-phase challenge handling is delegated to ChallengePipeline

    async def _get_effective_validators(self) -> List[Tuple[int, bt.AxonInfo, str]]:
        """
        Get filtered validators for miner communication

        Returns:
            List of (uid, axon, hotkey) tuples ready for communication
        """
        if self.validator_cache:
            # Use validator cache if available
            validators = self.validator_cache.get_validators()
            bt.logging.debug(f"Validator cache | count={len(validators)}")
            return validators
        else:
            # Fallback: empty list
            bt.logging.warning("⚠️ No validator connection configured")
            return []

    async def _poll_tasks_with_capacity_spinning(self) -> None:
        """Poll tasks from validators with capacity spinning and rotating start point"""
        effective_validators = await self._get_effective_validators()

        if not effective_validators:
            bt.logging.debug(
                "Skipping task polling - no effective validators available"
            )
            return

        # Ensure at least one worker is connected; if none, skip.
        if not self.worker_manager.workers:
            bt.logging.debug("Skipping task polling - no workers connected")
            return

        # Wait for full idle capacity (all workers non-busy) before polling
        await self._wait_for_sufficient_capacity()

        # Create rotated validator list for fair distribution
        num_validators = len(effective_validators)
        rotated_validators = (
            effective_validators[self._polling_start_index :]
            + effective_validators[: self._polling_start_index]
        )

        # Update start index for next round (rotate)
        self._polling_start_index = (self._polling_start_index + 1) % num_validators

        idle_percentage = self.worker_manager.get_idle_worker_percentage()
        bt.logging.debug(
            f"Task polling start | validators={num_validators} idle={idle_percentage:.1f}% start_index={self._polling_start_index-1}"
        )

        # Poll all validators sequentially - ensure capacity between validators
        for i, (uid, axon, hotkey) in enumerate(rotated_validators):
            try:
                bt.logging.debug(f"Polling validator {uid} ({i+1}/{num_validators})")
                await self._poll_single_validator(uid, axon, hotkey)
                # Before moving to the next validator, ensure workers are all idle again
                if i < num_validators - 1:
                    await self._wait_for_sufficient_capacity()

            except Exception as e:
                bt.logging.error(f"❌ Poll error | uid={uid} error={e}")

        bt.logging.debug(f"Task polling complete | validators={num_validators}")

    async def _wait_for_sufficient_capacity(self) -> None:
        """Spin-wait until sufficient idle worker capacity is available or timeout"""
        required_idle_percentage = 100.0  # Require all workers to be idle
        check_interval = 1.0  # Check every second
        max_wait_seconds = 60.0
        start = time.monotonic()

        while self.is_running:
            current_idle_percentage = self.worker_manager.get_idle_worker_percentage()

            if current_idle_percentage >= required_idle_percentage:
                return  # Sufficient capacity available

            # Timeout
            if time.monotonic() - start >= max_wait_seconds:
                total_workers = len(self.worker_manager.workers)
                busy_workers = sum(
                    1
                    for w in self.worker_manager.workers.values()
                    if w.status == "busy"
                )
                bt.logging.error(
                    f"Capacity wait timeout | waited={max_wait_seconds:.0f}s current={current_idle_percentage:.1f}% "
                    f"required={required_idle_percentage}% workers={total_workers} busy={busy_workers}"
                )
                raise TimeoutError("Wait for sufficient idle worker capacity timed out")

            # Log capacity status periodically
            total_workers = len(self.worker_manager.workers)
            busy_workers = sum(
                1 for w in self.worker_manager.workers.values() if w.status == "busy"
            )

            bt.logging.debug(
                f"Waiting for capacity | current={current_idle_percentage:.1f}% required={required_idle_percentage}% "
                f"workers={total_workers} busy={busy_workers}"
            )

            # Spin-wait
            await asyncio.sleep(check_interval)

    async def _poll_single_validator(
        self, uid: int, axon: bt.AxonInfo, hotkey: str
    ) -> None:
        """Poll tasks from single validator"""
        if not axon.is_serving:
            return

        try:
            task_response = await self._poll_single_validator_direct(uid, axon, hotkey)

            if task_response:
                # Pass validator source info for challenge response routing
                validator_info = {"uid": uid, "axon": axon, "hotkey": hotkey}
                await self._handle_task_response(task_response, validator_info)

        except Exception as e:
            bt.logging.error(f"❌ Poll error | uid={uid} error={e}")
            raise

    async def _handle_task_response(
        self, task_response: TaskResponse, validator_info: Dict[str, Any]
    ) -> None:
        """Handle task response from validator"""
        task_type = task_response.task_type

        bt.logging.info(f"Task response | type={task_type}")
        bt.logging.debug(
            f"Task response data: {self._truncate_log_data(task_response.task_data)}"
        )

        if task_type == "no_task":
            bt.logging.debug("No tasks available")
        elif task_type == "compute_challenge_batch":
            # Handle batch of challenges
            bt.logging.debug("Processing compute challenge batch")
            if task_response.task_data and "challenges" in task_response.task_data:
                challenges = task_response.task_data["challenges"]
                bt.logging.info(f"Challenge batch | count={len(challenges)}")

                # Process all challenges in parallel
                await self._handle_compute_challenges_batch(challenges, validator_info)
            else:
                bt.logging.error(
                    "❌ Invalid batch challenge format | missing challenges list"
                )
        else:
            bt.logging.error(f"❌ Unknown task type | type={task_type}")

    async def _handle_compute_challenges_batch(
        self, challenges: List[Dict[str, Any]], validator_info: Dict[str, Any]
    ) -> None:
        """Handle batch of compute challenges by distributing to workers"""

        bt.logging.debug(f"Processing challenges batch | count={len(challenges)}")

        # Prepare all challenges
        prepared_tasks = []
        for challenge_data in challenges:
            try:
                # Worker targeting enables selective task assignment
                target_worker_id = challenge_data.pop("target_worker_id", None)
                challenge = ComputeChallenge(**challenge_data)

                # Record challenge source and initial timestamp via pipeline
                self.challenge_pipeline.record_source(
                    challenge.challenge_id, validator_info
                )

                # Prepare task data for worker
                task_data = {
                    "task_id": challenge.challenge_id,
                    "task_type": challenge.challenge_type,
                    "challenge_id": challenge.challenge_id,
                    "data": challenge.data,
                    "timeout": challenge.timeout,
                    "validator_hotkey": validator_info["hotkey"],
                }

                prepared_tasks.append(
                    {
                        "task_data": task_data,
                        "target_worker_id": target_worker_id,
                        "challenge_id": challenge.challenge_id,
                    }
                )
            except Exception as e:
                bt.logging.error(f"❌ Prepare challenge error | error={e}")
                continue

        if not prepared_tasks:
            bt.logging.error("❌ No valid challenges to distribute")
            return

        # Distribute all tasks in parallel
        distribution_tasks = []

        for task_info in prepared_tasks:
            if task_info["target_worker_id"]:
                # Target specific worker
                distribution_tasks.append(
                    self._distribute_to_specific_worker(
                        task_info["task_data"],
                        task_info["target_worker_id"],
                        task_info["challenge_id"],
                    )
                )
            else:
                # Target any available worker
                distribution_tasks.append(
                    self._distribute_to_available_worker(
                        task_info["task_data"], task_info["challenge_id"]
                    )
                )

        # Execute all distributions in parallel

        results = await asyncio.gather(*distribution_tasks, return_exceptions=True)

        # Clear task references
        distribution_tasks.clear()

        # Log results
        success_count = sum(1 for r in results if r is True)
        failure_count = len(results) - success_count

        bt.logging.info(f"Distribution | success={success_count} fail={failure_count}")

        # Log any exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                bt.logging.error(
                    f"❌ Distribution error | challenge_id={prepared_tasks[i]['challenge_id']} error={result}"
                )

    async def _distribute_to_specific_worker(
        self, task_data: Dict[str, Any], worker_id: str, challenge_id: str
    ) -> bool:
        """
        Distribute task to specific worker

        Args:
            task_data: Task information and parameters
            worker_id: Target worker identifier
            challenge_id: Challenge identifier for logging

        Returns:
            True if distribution successful, False otherwise
        """
        try:
            success = await self.worker_manager.distribute_task_to_worker(
                task_data, worker_id
            )
            if success:
                bt.logging.info(
                    f"Distributed | challenge_id={challenge_id} worker_id={worker_id}"
                )
                return True
            else:
                bt.logging.error(
                    f"❌ Distribution failed | challenge_id={challenge_id} worker_id={worker_id}"
                )
                return False
        except Exception as e:
            bt.logging.error(
                f"❌ Distribution exception | challenge_id={challenge_id} worker_id={worker_id} error={e}"
            )
            return False

    async def _distribute_to_available_worker(
        self, task_data: Dict[str, Any], challenge_id: str
    ) -> bool:
        """
        Distribute task to any available idle worker

        Args:
            task_data: Task information and parameters
            challenge_id: Challenge identifier for logging

        Returns:
            True if distribution successful, False otherwise
        """
        try:
            # Find idle worker and distribute task
            success = await self.worker_manager.distribute_task_to_idle_worker(
                task_data
            )
            if success:
                bt.logging.info(
                    f"📤 Distributed | challenge_id={challenge_id} worker=idle"
                )
                return True
            else:
                bt.logging.warning(
                    f"⚠️ No idle worker | challenge_id={challenge_id} action=queue"
                )
                # Task queuing for when workers become available
                return False
        except Exception as e:
            bt.logging.error(
                f"❌ Distribution exception | challenge_id={challenge_id} worker=idle error={e}"
            )
            return False

    def get_communication_status(self) -> Dict[str, Any]:
        """Get current communication service status"""
        return {
            "is_running": self.is_running,
            "validator_count": len(self.validator_cache.get_validators()),
            "pending_worker_heartbeats": len(
                getattr(self.heartbeat_service, "_pending_worker_heartbeats", [])
            ),
        }

    def _truncate_log_data(self, data: Any, max_length: int = 500) -> str:
        """
        Truncate data for logging to prevent excessive output

        Args:
            data: Data to truncate for logging
            max_length: Maximum string length before truncation

        Returns:
            Truncated string representation of data
        """
        try:
            data_str = str(data)
            if len(data_str) <= max_length:
                return data_str

            return (
                data_str[:max_length]
                + f"... [truncated, total length: {len(data_str)}]"
            )
        except Exception:
            return "[data conversion failed]"

    async def _send_to_validators(
        self,
        operation: str,
        synapse_class: type,
        request_data: Any,
        validators: List[Tuple[int, bt.AxonInfo, str]],
        timeout: int = 30,
    ) -> CommunicationResult:
        """Delegate to session transport bulk sender."""
        return await self.transport.send_to_validators(
            operation=operation,
            synapse_class=synapse_class,
            request_data=request_data,
            validators=validators,
            timeout=timeout,
        )

    async def _send_single_request(
        self,
        operation: str,
        synapse_class: type,
        request_data: Any,
        target_hotkey: str,
        axon: bt.AxonInfo,
        timeout: int,
        validator_uid: Optional[int] = None,
        _retry_count: int = 0,
    ) -> CommunicationResult:
        """Delegate to session transport single sender."""
        return await self.transport.send_single_request(
            operation=operation,
            synapse_class=synapse_class,
            request_data=request_data,
            target_hotkey=target_hotkey,
            axon=axon,
            timeout=timeout,
            validator_uid=validator_uid,
            _retry_count=_retry_count,
        )

    async def _poll_single_validator_direct(
        self, uid: int, axon: bt.AxonInfo, hotkey: str
    ) -> Optional[TaskResponse]:
        """Poll tasks from single validator using direct communication"""
        if not axon.is_serving:
            return None

        try:
            task_request = TaskRequest(
                hotkey=self.wallet.hotkey.ss58_address,
                request_type="challenge",
                timestamp=time.time(),
            )

            result = await self._send_single_request(
                operation="task_poll",
                synapse_class=ProtocolRegistry.get(ProtocolTypes.TASK),
                request_data=task_request,
                target_hotkey=hotkey,
                axon=axon,
                timeout=10,
                validator_uid=uid,
            )

            if result.success and result.data:
                task_response = TaskResponse(**result.data)
                if task_response.task_type != "no_task":
                    bt.logging.info(
                        f"📋 Task received | type={task_response.task_type} validator_uid={uid}"
                    )
                return task_response

        except Exception as e:
            bt.logging.error(f"❌ Task poll error | uid={uid} error={e}")

        return None
