#!/usr/bin/env python3
"""
ByteLeap Miner Startup Script
"""
import argparse
import asyncio
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path

import bittensor as bt
import yaml

# Add project root directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from neurons.miner.core.miner import Miner
from neurons.shared.config.config_manager import ConfigManager


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="ByteLeap Bittensor SN128 Miner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Configuration file
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to the miner configuration file (e.g., config/miner_config.yaml)",
    )

    return parser


def setup_logging(config: ConfigManager) -> None:
    """Setup complete logging configuration for miner with rotation"""
    log_dir = config.get("logging.log_dir")
    log_level = config.get("logging.log_level").upper()

    # Set bittensor logging level
    if log_level == "DEBUG":
        bt.logging.enable_debug()
    elif log_level == "INFO":
        bt.logging.enable_info()
    elif log_level == "WARNING":
        bt.logging.enable_warning()
    else:
        bt.logging.enable_default()

    # Create log directory
    os.makedirs(log_dir, exist_ok=True)

    # Create base log filename
    log_filename = "miner.log"
    log_filepath = Path(log_dir) / log_filename

    # Get the root logger used by bittensor
    root_logger = logging.getLogger()

    # Create rotating file handler - rotates at midnight and keeps 7 days
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=log_filepath,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
    )

    # Set suffix for rotated files (YYYY-MM-DD format)
    file_handler.suffix = "%Y-%m-%d"

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)

    # Set log level
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    file_handler.setLevel(log_level_map.get(log_level, logging.INFO))

    # Add handler to root logger
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.DEBUG)  # Allow all levels, handlers will filter

    # Set websockets logging to WARNING to suppress ping/pong debug messages
    websockets_logger = logging.getLogger("websockets")
    websockets_logger.setLevel(logging.WARNING)

    bt.logging.info(
        f"🧾 File logging | path={log_filepath} | level={log_level} | rotation=daily"
    )


def load_config(config_path: str) -> ConfigManager:
    """Load configuration file and return ConfigManager"""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)
        return ConfigManager(config_data)
    except Exception as e:
        bt.logging.error(f"❌ Load config error | error={e}")
        sys.exit(1)


def validate_config(config: ConfigManager) -> bool:
    """Validate configuration validity using fail-fast config methods"""
    bt.logging.debug("Config validation start")
    try:
        # Test required fields by accessing them (will raise KeyError if missing)
        bt.logging.debug("Checking netuid")
        config.get("netuid")

        # Validate network ID
        netuid = config.get("netuid")
        if not isinstance(netuid, int) or netuid < 0:
            bt.logging.error("❌ Config error | netuid must be non-negative int")
            return False

        # Test worker management configuration
        try:
            config.get("worker_management.host")
            config.get("worker_management.port")

            # Validate worker management port
            port = config.get("worker_management.port")
            if not isinstance(port, int) or port < 1024 or port > 65535:
                bt.logging.error(
                    f"Error: worker_management.port must be an integer between 1024-65535"
                )
                return False

        except KeyError:
            pass  # Worker management configuration is optional

        bt.logging.info("✅ Config validation done")
        return True

    except KeyError as e:
        bt.logging.error(f"❌ Config validation failed | error={e}")
        return False


def check_miner_registration(
    wallet: bt.wallet, subtensor: bt.subtensor, metagraph: bt.metagraph
) -> bool:
    """Check if miner is registered on the subnet"""
    try:
        miner_hotkey = wallet.hotkey.ss58_address
        bt.logging.info(f"🔎 Miner registration | hotkey={miner_hotkey}")

        # Check if hotkey exists in metagraph
        if hasattr(metagraph, "hotkeys") and miner_hotkey in metagraph.hotkeys:
            uid = metagraph.hotkeys.index(miner_hotkey)
            bt.logging.info(f"✅ Miner registered | uid={uid}")
            return True
        else:
            bt.logging.error(
                f"❌ Miner not registered | hotkey={miner_hotkey} netuid={metagraph.netuid}"
            )
            bt.logging.warning(
                f"⚠️ Register miner: btcli subnet register --netuid {metagraph.netuid} --wallet.name {wallet.name} --wallet.hotkey {wallet.hotkey_str}"
            )
            return False

    except Exception as e:
        bt.logging.error(f"❌ Miner registration check error | error={e}")
        return False


async def main():
    """Main function"""
    # Parse command line arguments
    parser = create_parser()
    args = parser.parse_args()

    # Initialize bt.logging with colors
    bt.logging.enable_default()

    # Validate configuration file existence
    if not args.config or not os.path.exists(args.config):
        bt.logging.error(f"❌ Config file not found | path={args.config}")
        sys.exit(1)

    # Load configuration
    config = load_config(args.config)

    # Validate configuration
    if not validate_config(config):
        sys.exit(1)

    # Create the bittensor config object from YAML config
    bt_config = bt.config()

    # Set configuration values from config
    bt_config.netuid = config.get("netuid")

    # Create nested config objects without triggering additional config loading
    from munch import DefaultMunch

    bt_config.wallet = DefaultMunch()
    bt_config.wallet.name = config.get("wallet.name")
    bt_config.wallet.hotkey = config.get("wallet.hotkey")
    bt_config.wallet.path = config.get("wallet.path")

    bt_config.subtensor = DefaultMunch()
    bt_config.subtensor.network = config.get("subtensor.network")

    # Setup complete logging configuration (includes bittensor and file logging)
    setup_logging(config)

    # Display configuration information
    bt.logging.info(f"🌐 Netuid | id={config.get('netuid')}")
    bt.logging.info(f"👛 Wallet | name={config.get('wallet.name')}")
    bt.logging.info(f"🔑 Hotkey | name={config.get('wallet.hotkey')}")

    try:
        # Create Bittensor objects
        bt.logging.debug("Creating wallet")
        wallet = bt.wallet(config=bt_config)
        bt.logging.debug("Creating subtensor")
        subtensor = bt.subtensor(config=bt_config)
        bt.logging.debug("Creating metagraph")
        metagraph = bt.metagraph(netuid=config.get("netuid"), subtensor=subtensor)

        # Check miner registration
        bt.logging.debug("Verifying miner registration")
        if not check_miner_registration(wallet, subtensor, metagraph):
            bt.logging.error("Miner registration check failed, exiting...")
            sys.exit(1)

        # Create and start miner
        bt.logging.debug("Creating miner")
        miner = Miner(config, wallet, subtensor, metagraph)
        bt.logging.info("🚀 Starting miner")
        await miner.run()

    except KeyboardInterrupt:
        bt.logging.info("⏹️ Interrupt | shutting down")
    except Exception as e:
        bt.logging.error(f"❌ Runtime error | error={e}")
        sys.exit(1)
    finally:
        bt.logging.info("✅ Miner stopped")


if __name__ == "__main__":
    # Unix/Linux event loop policy (default)

    # Run main program
    asyncio.run(main())
