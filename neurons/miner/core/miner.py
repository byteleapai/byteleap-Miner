"""
Miner Core Controller

Orchestrates worker management, validator communication, and resource aggregation
for compute resource mining operations in the Bittensor network.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import bittensor as bt

# Import unified version
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from __version__ import __version__

from neurons.miner.services.communication import MinerCommunicationService
from neurons.miner.services.worker_manager import WorkerManager
from neurons.shared.auto_updater import AutoUpdater
from neurons.shared.config.config_manager import ConfigManager

# Miner version (using unified version)
MINER_VERSION = __version__


class Miner:
    """
    Main miner controller for compute resource operations

    Responsibilities:
    - Coordinate worker lifecycle management
    - Manage validator communication and discovery
    - Aggregate worker resources for network reporting
    - Handle graceful shutdown and cleanup
    """

    def __init__(
        self,
        config: ConfigManager,
        wallet: bt.wallet,
        subtensor: bt.subtensor,
        metagraph: bt.metagraph,
    ):
        """
        Initialize miner with required components

        Args:
            config: Complete miner configuration
            wallet: Bittensor wallet instance
            subtensor: Bittensor subtensor instance
            metagraph: Initial metagraph instance

        Raises:
            ValueError: If any required parameter is None or invalid
            KeyError: If required configuration keys are missing
        """
        if config is None:
            raise ValueError("config cannot be None")
        if wallet is None:
            raise ValueError("wallet cannot be None")
        if subtensor is None:
            raise ValueError("subtensor cannot be None")
        if metagraph is None:
            raise ValueError("metagraph cannot be None")

        self.config = config
        self.wallet = wallet
        self.subtensor = subtensor
        self.metagraph = metagraph

        # Service components
        self.worker_manager = WorkerManager(config)
        self.communication_service = MinerCommunicationService(
            self.wallet,
            self.subtensor,
            self.metagraph,
            config,
            self.worker_manager,
            miner_version=MINER_VERSION,
        )

        # Runtime status
        self.is_running = False
        self._shutdown_event = asyncio.Event()

        # Auto updater
        project_root = Path(__file__).parent.parent.parent.parent
        self.auto_updater = AutoUpdater(MINER_VERSION, project_root)
        self._update_check_task = None

        # Setup signal handlers
        self._setup_signal_handlers()

        bt.logging.info("✅ Miner initialization complete")

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers"""

        def signal_handler(signum, frame):
            signal_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
            bt.logging.info(f"Miner signal | sig={signum} name={signal_name}")
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start(self) -> None:
        """Start miner"""
        if self.is_running:
            bt.logging.warning("Miner is already running")
            return

        # Check for updates on startup
        try:
            update_installed = await self.auto_updater.check_update_on_startup(
                auto_install=True
            )
            if update_installed:
                bt.logging.warning("Update installed, please check config and restart")
                bt.logging.warning("Program will exit in 5 seconds...")
                await asyncio.sleep(5)
                sys.exit(0)
        except Exception as e:
            bt.logging.warning(f"Startup update check failed: {e}")

        bt.logging.info("🚀 Starting miner")

        try:
            await self.worker_manager.start()

            await self.communication_service.start()

            # Establish inter-service connections
            self._connect_services()

            # Start periodic update check
            self._update_check_task = asyncio.create_task(
                self.auto_updater.start_periodic_check()
            )
            bt.logging.info("Auto updater started")

            self.is_running = True
            bt.logging.info("✅ Miner started")

        except Exception as e:
            bt.logging.error(f"❌ Miner start error | error={e}")
            await self.stop()
            raise

    def _connect_services(self) -> None:
        """Connect service modules"""
        # Connect worker manager to communication service for task distribution
        self.worker_manager.set_communication_service(self.communication_service)

    async def stop(self) -> None:
        """Stop miner"""
        if not self.is_running:
            return

        bt.logging.info("⏹️ Stopping miner")

        # Stop auto updater
        if self._update_check_task:
            self.auto_updater.stop_periodic_check()
            self._update_check_task.cancel()
            try:
                await self._update_check_task
            except asyncio.CancelledError:
                pass
            bt.logging.info("⏹️ Auto updater stopped")

        await self.communication_service.stop()

        await self.worker_manager.stop()

        self.is_running = False
        self._shutdown_event.set()

        bt.logging.info("✅ Miner stopped")

    async def run(self) -> None:
        """Run the miner continuously until stopped."""
        try:
            await self.start()
            bt.logging.info("Miner running | Ctrl+C to stop")

            # Keep running until shutdown event is set
            await self._shutdown_event.wait()

        except KeyboardInterrupt:
            bt.logging.info("⚠️ Miner interrupt | stopping")
        except Exception as e:
            bt.logging.error(f"❌ Miner run error | error={e}")
        finally:
            await self.stop()

    def get_status(self) -> Dict[str, Any]:
        """Get miner status"""
        worker_status = self.worker_manager.get_status()
        aggregated_metrics = {
            "worker_count": worker_status.get("total_workers", 0),
            "online_workers": worker_status.get("online_workers", 0),
            "busy_workers": worker_status.get("busy_workers", 0),
        }

        return {
            "is_running": self.is_running,
            "wallet_address": self.wallet.hotkey.ss58_address,
            "worker_manager": self.worker_manager.get_status(),
            "communication_service": self.communication_service.get_communication_status(),
            "aggregated_metrics": aggregated_metrics,
            "worker_count": len(self.worker_manager.get_connected_workers()),
        }

    def is_healthy(self) -> bool:
        """Check miner health status"""
        if not self.is_running:
            return False

        worker_manager_healthy = self.worker_manager.is_running
        comm_healthy = self.communication_service.is_running
        has_workers = len(self.worker_manager.get_connected_workers()) > 0

        return worker_manager_healthy and comm_healthy and has_workers
