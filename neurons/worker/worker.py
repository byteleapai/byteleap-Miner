"""
Worker Main Program
Independent worker service for compute resource management
"""

import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

from neurons.shared.utils.system_monitor import \
    EnhancedSystemMonitor as SystemMonitor
from neurons.worker.communication.websocket_client import WebSocketClient
from neurons.worker.config.worker_config import WorkerConfig
from neurons.worker.core.task_executor import TaskExecutor

# Worker version
WORKER_VERSION = "0.0.2"


class WorkerService:
    """Main worker service"""

    def __init__(self, config_file: str):
        """Initialize worker service"""
        # Load configuration
        self.config = WorkerConfig(config_file)

        self._setup_logging()

        self.worker_id = self.config.get_worker_id()
        self.worker_name = self.config.get_worker_name()

        # Core components
        self.system_monitor = SystemMonitor()
        self.task_executor = TaskExecutor(self.config)
        self.websocket_client = WebSocketClient(self.config)

        # Runtime status
        self.is_running = False
        self._shutdown_event = asyncio.Event()

        # Setup signal handlers
        self._setup_signal_handlers()

        logger.success(
            f"🧩 Worker initialized | id={self.worker_name or self.worker_id}"
        )

    def _setup_logging(self):
        """Setup logging configuration"""
        logger.configure(extra={"project_name": "worker"})

        logger.remove()

        log_level = self.config.get_non_empty_string("logging.level").upper()

        logger.add(
            sink=sys.stdout,
            level=log_level,
            format=self.config.get_non_empty_string("logging.format"),
        )

        log_filepath = Path(self.config.get_non_empty_string("logging.filepath"))
        log_filepath.parent.mkdir(parents=True, exist_ok=True)

        logger.add(
            sink=log_filepath,
            level=log_level,
            format=self.config.get_non_empty_string("logging.format"),
            rotation=self.config.get_non_empty_string("logging.rotation"),
            retention=self.config.get_non_empty_string("logging.retention"),
            enqueue=True,
            backtrace=True,
            diagnose=True,
        )

        logger.info(
            f"🧾 Logging setup | level={log_level} rotation={self.config.get_non_empty_string('logging.rotation')}"
        )

        # Suppress websockets ping/pong debug messages that appear in file but not console
        import logging

        websockets_logger = logging.getLogger("websockets")
        websockets_logger.setLevel(logging.WARNING)

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""

        def signal_handler(signum, frame):
            signal_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
            logger.warning(
                f"Received signal {signum} ({signal_name}), shutting down..."
            )
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start(self):
        """Start worker service"""
        if self.is_running:
            logger.warning("Worker service already running")
            return

        logger.info(f"🚀 Starting worker | id={self.worker_id}")

        try:

            await self.task_executor.start()
            logger.info("🧮 Task executor started")

            await self.websocket_client.connect()
            await self._register_worker()
            self._connect_components()

            self.is_running = True
            logger.success(f"✅ Worker started | id={self.worker_id}")

            await self._main_loop()

        except Exception as e:
            logger.error(
                f"❌ Start error | id={self.worker_id} error={e}", exc_info=True
            )
            await self.stop()
            raise

    async def _register_worker(self):
        """Register worker with miner"""
        # Get initial system info
        system_info = self.system_monitor.get_system_info()
        # Align GPU reporting with heartbeat logic
        try:
            gpu_info = self.task_executor.get_gpu_heartbeat_data()
            plugin_active = bool(
                gpu_info
                and gpu_info.get("gpu_available")
                and gpu_info.get("gpu_count", 0) > 0
                and gpu_info.get("gpu_details")
            )
            if plugin_active:
                system_info["gpu_plugin"] = gpu_info.get("gpu_details", [])
            else:
                nvml_gpus = self.system_monitor.get_gpu_info_nvml()
                if isinstance(nvml_gpus, list) and nvml_gpus:
                    system_info["gpu_info"] = nvml_gpus
        except Exception:
            pass

        registration_data = {
            "type": "register",
            "worker_id": self.worker_id,
            "worker_name": self.worker_name,
            "worker_version": WORKER_VERSION,
            "capabilities": self.config.get_capabilities(),
            "system_info": system_info,
        }

        await self.websocket_client.send_message(registration_data)

        response = await self.websocket_client.wait_for_message(
            "registration_ack", timeout=30
        )
        if response:
            logger.info("✅ Registration acknowledged")
        else:
            raise Exception("Registration timeout")

    def _connect_components(self):
        """Connect components together"""
        self.websocket_client.set_message_handler(
            "task_assignment", self._handle_task_assignment
        )
        self.websocket_client.set_message_handler(
            "heartbeat_request", self._handle_heartbeat_request
        )
        self.websocket_client.set_message_handler(
            "proof_request", self._handle_proof_request
        )

        # Set task completion callback
        self.task_executor.set_completion_callback(self._handle_task_completion)

    async def _main_loop(self):
        """Main worker loop with consolidated heartbeat"""
        heartbeat_interval = self.config.get_positive_number("heartbeat_interval", int)
        reconnect_delay = self.config.get_positive_number("reconnect_interval", int)

        last_heartbeat = 0

        while self.is_running and not self._shutdown_event.is_set():
            try:
                current_time = time.time()

                if not self.websocket_client.is_connected():
                    logger.warning("⚠️ Connection lost | action=reconnect")
                    try:
                        await self.websocket_client.connect()
                        await self._register_worker()
                        logger.success("✅ Reconnected and re-registered")
                        # Reset timer to send heartbeat immediately after reconnect
                        last_heartbeat = 0
                    except Exception as e:
                        logger.error(
                            f"❌ Reconnect failed | error={e} retry_in={reconnect_delay}s"
                        )
                        await asyncio.sleep(reconnect_delay)
                        continue

                # Send periodic heartbeat to maintain connection
                if current_time - last_heartbeat >= heartbeat_interval:
                    await self._send_heartbeat()
                    last_heartbeat = current_time

                # Process websocket messages
                await self.websocket_client.process_messages()

                # Small sleep to prevent busy waiting
                await asyncio.sleep(1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Main loop error | error={e}", exc_info=True)
                # Wait before retry to avoid tight error loop
                await asyncio.sleep(5)

        logger.info("⏹️ Main loop exited")
        await self.stop()

    async def _send_heartbeat(self):
        """Send comprehensive heartbeat with status and system info to miner"""
        try:
            # Get current system information
            system_info = self.system_monitor.get_system_info()

            # Prefer CUDA binary GPU info when available; otherwise, enrich via NVML
            gpu_info = self.task_executor.get_gpu_heartbeat_data()

            plugin_active = bool(
                gpu_info
                and gpu_info.get("gpu_available")
                and gpu_info.get("gpu_count", 0) > 0
                and gpu_info.get("gpu_details")
            )

            if plugin_active:
                # CUDA binary already provides UUIDs and details
                system_info["gpu_plugin"] = gpu_info.get("gpu_details", [])
            else:
                # CUDA unavailable: use NVML to include UUIDs in gpu_info if possible
                try:
                    nvml_gpus = self.system_monitor.get_gpu_info_nvml()
                    if isinstance(nvml_gpus, list) and nvml_gpus:
                        system_info["gpu_info"] = nvml_gpus
                except Exception:
                    pass

            # Determine worker status based on current tasks
            active_task_count = self.task_executor.get_active_task_count()
            worker_status = "busy" if active_task_count > 0 else "online"

            heartbeat_data = {
                "type": "heartbeat",
                "data": {
                    "status": worker_status,
                    "active_tasks": active_task_count,
                    "system_info": system_info,
                    "gpu_info": gpu_info,
                    "capabilities": self.task_executor.get_capabilities(),
                },
            }

            await self.websocket_client.send_message(heartbeat_data)

        except Exception as e:
            logger.error(f"❌ Error sending heartbeat: {e}", exc_info=True)

    async def _handle_task_assignment(self, message: Dict[str, Any]):
        """Handle task assignment from miner"""
        try:
            task_data = message.get("data", {})
            task_id = task_data.get("task_id")

            logger.info(f"Received task assignment | id={task_id}")

            # Execute task
            await self.task_executor.execute_task(task_data)

        except Exception as e:
            logger.error(f"❌ Error handling task assignment: {e}", exc_info=True)

    async def _handle_heartbeat_request(self, message: Dict[str, Any]):
        """Handle heartbeat request from miner"""
        try:
            # Respond immediately
            response_data = {
                "type": "heartbeat_response",
                "worker_id": self.worker_id,
                "timestamp": time.time(),
                "message_id": message.get("message_id"),
            }

            await self.websocket_client.send_message(response_data)

        except Exception as e:
            logger.error(f"Error handling heartbeat request: {e}", exc_info=True)

    async def _handle_task_completion(self, task_id: str, result: Dict[str, Any]):
        """Handle task completion"""
        try:
            # Send result to miner
            result_data = {
                "type": "task_result",
                "worker_id": self.worker_id,
                "task_id": task_id,
                "timestamp": time.time(),
                "data": result,
            }

            await self.websocket_client.send_message(result_data)

        except Exception as e:
            logger.error(f"❌ Error sending task result: {e}", exc_info=True)

    async def _handle_proof_request(self, message: Dict[str, Any]):
        """Handle a unified proof request from the miner."""
        worker_proof_request_received_ts = int(time.time() * 1000)
        response_data = {"success": False, "error": "unknown"}
        message_id = message.get("message_id")

        try:
            request_data = message.get("data", {})
            validator_hotkey = request_data.get("validator_hotkey")
            proof_requests = request_data.get("requests", [])

            if not all([validator_hotkey, proof_requests]):
                raise ValueError(
                    "Missing required fields in proof request: validator_hotkey, requests"
                )

            logger.info(
                f"Received proof request for {len(proof_requests)} items from validator {validator_hotkey}"
            )

            # Generate proofs using the new unified method in the task executor
            proofs = await self.task_executor.generate_proofs(
                validator_hotkey, proof_requests
            )

            # Filter out any None results from failed proof generations
            valid_proofs = [p for p in proofs if p is not None]

            if not valid_proofs:
                raise ValueError("Failed to generate any valid proofs from cache")

            worker_proof_completed_ts = int(time.time() * 1000)

            response_data = {
                "success": True,
                "proofs": valid_proofs,
                "debug": {
                    "phase2_timestamps": {
                        "worker_proof_request_received_ts": worker_proof_request_received_ts,
                        "worker_proof_completed_ts": worker_proof_completed_ts,
                    }
                },
            }

        except Exception as e:
            logger.error(f"Error handling proof request for message {message_id}: {e}")
            response_data["error"] = str(e)

        response = {
            "type": "proof_response",
            "message_id": message_id,
            "data": response_data,
        }
        await self.websocket_client.send_message(response)

    async def stop(self):
        """Stop worker service"""
        if not self.is_running:
            return

        logger.info("⏹️ Stopping worker service")

        # Cleanup task executor and plugins
        await self.task_executor.cleanup()
        await self.websocket_client.disconnect()

        self.is_running = False
        self._shutdown_event.set()

        logger.success("✅ Worker service stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get worker status"""
        return {
            "worker_id": self.worker_id,
            "is_running": self.is_running,
            "websocket_connected": self.websocket_client.is_connected(),
            "active_tasks": self.task_executor.get_active_task_count(),
        }


async def main():
    """Main entry point"""
    # Basic argument parsing
    if len(sys.argv) < 2:
        logger.error("Usage: python worker.py --config <config_file>")
        return

    config_file = sys.argv[1]

    if not Path(config_file).exists():
        # Handle missing configuration file
        logger.error(f"Config file not found: {config_file}")
        return

    # Create and start worker
    worker = None
    try:
        worker = WorkerService(config_file)
        await worker.start()
    except KeyboardInterrupt:
        logger.info("⚠️ Interrupted by user")
    except Exception as e:
        logger.critical(f"❌ Worker failed to start: {e}", exc_info=True)
    finally:
        if worker:
            await worker.stop()


if __name__ == "__main__":
    # Setup a basic logger for initial execution
    logger.configure(extra={"project_name": "worker"})
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{extra[project_name]}:{name}:{line}</cyan> - <level>{message}</level>",
    )

    # Run main async loop
    try:
        asyncio.run(main())
    except Exception as e:
        logger.critical(f"❌ Unhandled exception in event loop: {e}", exc_info=True)
