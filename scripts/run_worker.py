#!/usr/bin/env python3
"""
ByteLeap Worker Startup Script
"""
import argparse
import asyncio
import sys
from pathlib import Path

from loguru import logger

# Add project root directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from neurons.worker.worker import WorkerService


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="ByteLeap Compute Worker - SN128",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Configuration file
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to the worker configuration file (e.g., config/worker_config.yaml)",
    )

    return parser


async def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()

    config_file = Path(args.config)

    # Validate configuration file existence
    if not config_file.exists():
        logger.error(f"❌ Config not found | path={config_file}")
        sys.exit(1)

    # The WorkerService will set up its own detailed logging based on the config file.
    # We just need a basic logger here for pre-startup messages.
    logger.debug(f"🧾 Load config | path={config_file}")

    worker = None
    try:
        # Create and start the worker service
        worker = WorkerService(config_file=str(config_file))
        await worker.start()

    except KeyboardInterrupt:
        logger.info("⏹️ Interrupt | shutting down")
    except Exception as e:
        logger.error(f"❌ Runtime error | error={e}", exc_info=True)
        sys.exit(1)
    finally:
        if worker:
            await worker.stop()
        logger.info("✅ Worker stopped")


if __name__ == "__main__":
    # Setup a basic logger for initial execution
    logger.configure(extra={"project_name": "worker"})
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{extra[project_name]}:{name}:{line}</cyan> - <level>{message}</level>",
    )

    # Unix/Linux event loop policy (default)

    # Run main program
    asyncio.run(main())
