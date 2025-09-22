"""
Miner Core Controller

Orchestrates worker management, validator communication, and resource aggregation
for compute resource mining operations in the Bittensor network.
"""

import asyncio
import signal
import sys
from typing import Any, Dict, List, Optional

import bittensor as bt

from neurons.miner.services.communication import MinerCommunicationService
from neurons.miner.services.resource_aggregator import ResourceAggregator
from neurons.miner.services.worker_manager import WorkerManager
from neurons.shared.config.config_manager import ConfigManager

# Miner version
MINER_VERSION = "0.1.0"


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
        self.resource_aggregator = ResourceAggregator()
        self.communication_service = MinerCommunicationService(
            self.wallet,
            self.subtensor,
            self.metagraph,
            config,
            self.worker_manager,
            self.resource_aggregator,
            miner_version=MINER_VERSION,
        )

        # Runtime status
        self.is_running = False
        self._shutdown_event = asyncio.Event()

        # Setup signal handlers
        self._setup_signal_handlers()

        bt.logging.info("✅ Miner initialization complete")

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers"""

        def signal_handler(signum, frame):
            signal_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
            bt.logging.info(f"⏹️ Miner signal | sig={signum} name={signal_name}")
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start(self) -> None:
        """Start miner"""
        if self.is_running:
            bt.logging.warning("Miner is already running")
            return

        bt.logging.info("🚀 Starting miner")

        try:
            await self.worker_manager.start()

            await self.communication_service.start()

            # Establish inter-service connections
            self._connect_services()

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
            bt.logging.info("⏹️ Miner interrupt | stopping")
        except Exception as e:
            bt.logging.error(f"❌ Miner run error | error={e}")
        finally:
            await self.stop()

    def get_status(self) -> Dict[str, Any]:
        """Get miner status"""
        aggregated_metrics = self.resource_aggregator.get_aggregated_metrics()

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
