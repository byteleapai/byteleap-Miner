#!/usr/bin/env python3
"""
ByteLeap Worker Startup Script
"""
import subprocess
import os
import re
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


def run_vfio_verify():
    """
    Run the vfio-setup verify command and return its output.
    """
    try:
        BIN_DIR = os.path.join(project_root, 'bin')
        # Execute the verification command
        result = subprocess.run(
            [os.path.join(BIN_DIR, 'vfio-setup'), 'verify'],
            capture_output=True,
            text=True,
            check=True,
            timeout=30  # Set a timeout to prevent hanging
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Don't log detailed errors here, just return None
        return None
    except subprocess.TimeoutExpired:
        # Don't log detailed errors here, just return None
        return None
    except FileNotFoundError:
        # Don't log detailed errors here, just return None
        return None


def validate_output(output):
    """
    Validate the output against the required criteria.
    
    Args:
        output (str): The output from the vfio-setup verify command
        
    Returns:
        dict: A dictionary containing validation results
    """
    if not output:
        return {
            'success': False,
            'errors': ['No output received from vfio-setup command']
        }
    
    results = {
        'success': True,
        'errors': [],
        'warnings': []
    }
    
    # Check if NVIDIA GPUs are bound to vfio-pci
    vfio_pci_pattern = re.compile(r'Driver:\s+([\w-]+)', re.IGNORECASE)
    vfio_pci_matches = vfio_pci_pattern.findall(output)
    
    if not vfio_pci_matches:
        results['success'] = False
        results['errors'].append('No VFIO-PCI driver information found in output')
    elif 'vfio-pci' not in [match.lower() for match in vfio_pci_matches]:
        results['success'] = False
        results['errors'].append('NVIDIA GPUs are not bound to vfio-pci driver')
    
    # Check VFIO-bound NVIDIA GPUs count
    vfio_count_pattern = re.compile(r'VFIO-bound NVIDIA GPUs:\s+(\d+)')
    vfio_count_match = vfio_count_pattern.search(output)
    
    if not vfio_count_match:
        results['success'] = False
        results['errors'].append('No VFIO-bound NVIDIA GPUs count found in output')
    elif int(vfio_count_match.group(1)) < 1:
        results['success'] = False
        results['errors'].append('VFIO-bound NVIDIA GPUs count must be at least 1')
    
    # Check required configuration files
    required_files = [
        '/etc/default/grub',
        '/etc/modprobe.d/vfio.conf',
        '/etc/modprobe.d/nvidia-blacklist.conf',
        '/etc/modules-load.d/vfio.conf'
    ]
    
    for file_path in required_files:
        file_pattern = re.compile(r'✓.*{}'.format(re.escape(file_path)))
        if not file_pattern.search(output):
            results['success'] = False
            results['errors'].append(f'Configuration file {file_path} not found or not properly configured')
    
    return results

def print_validation_results(results):
    """
    Print the validation results in a user-friendly format.
    """
    if results['success']:
        logger.info("✅ VFIO setup verification passed!")
    else:
        logger.error("❌ VFIO setup verification failed. The worker does not meet the running conditions.")
        logger.error("Please run './bin/vfio-setup-linux-amd64 verify' directly to check the detailed configuration issues.")


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
    logger.debug(f"Load config | path={config_file}")
    
    # verify env
    logger.info("Verifying VFIO setup...")
    output = run_vfio_verify()
    
    if output:
        # Validate the output
        results = validate_output(output)
        
        # Print results
        print_validation_results(results)
        
        # Return appropriate exit code
        if results['success']:
            logger.info("Worker is starting...")
        else:
            return
    else:
        logger.error("❌ Failed to run VFIO setup verification.")
        logger.error("Please run './bin/vfio-setup-linux-amd64 verify' directly to check the configuration.")
        return

    worker = None
    try:
        # Create and start the worker service
        worker = WorkerService(config_file=str(config_file))
        await worker.start()

    except KeyboardInterrupt:
        logger.info("Interrupt | shutting down")
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
