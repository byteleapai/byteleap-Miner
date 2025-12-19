import os
import subprocess
import re
import time
from typing import List
from loguru import logger


def _run_shell_command(command: str, check_output: bool = True, timeout: int = 60) -> str:
    """
    Executes a shell command and returns its stdout.
    Raises RuntimeError if the command fails or times out.

    Args:
        command (str): The shell command to execute.
        check_output (bool): If True, raises RuntimeError for non-zero exit codes.
                             If False, allows non-zero exit codes (e.g., for 'systemctl status dead_service').
        timeout (int): Maximum time in seconds to wait for the command to complete.

    Returns:
        str: The standard output of the command.

    Raises:
        RuntimeError: If the command fails or times out.
    """
    print(f"Executing: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=check_output,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.stderr:
            raise RuntimeError(f"Command produced stderr output:\n{result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = (
            f"Command failed with exit code {e.returncode}:\n"
            f"  Command: {e.cmd}\n"
            f"  STDOUT: {e.stdout.strip()}\n"
            f"  STDERR: {e.stderr.strip()}"
        )
        raise RuntimeError(error_msg)
    except subprocess.TimeoutExpired as e:
        error_msg = (
            f"Command timed out after {timeout} seconds:\n"
            f"  Command: {e.cmd}\n"
            f"  STDOUT: {e.stdout.strip()}\n"
            f"  STDERR: {e.stderr.strip()}"
        )
        raise RuntimeError(error_msg)
    except FileNotFoundError:
        error_msg = f"Command '{command.split()[0]}' not found. Is it in your PATH?"
        raise RuntimeError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error executing command '{command}': {e}"
        raise RuntimeError(error_msg)

def get_nvidia_pci_addresses() -> List[str]:
    """
    Detects all NVIDIA GPUs currently bound to the 'nvidia' driver
    and returns their PCI addresses, vendor IDs, and device IDs.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, each containing 'pci_addr', 'vendor_id', and 'device_id' keys.
    """
    nvidia_gpus = []
    pci_devices_path = "/sys/bus/pci/devices/"

    if not os.path.exists(pci_devices_path):
        logger.warning(f"Error: PCI devices path not found at {pci_devices_path}")
        return nvidia_gpus
    
    try:
        for device_dir in os.listdir(pci_devices_path):
            pci_address_full = device_dir
            # Basic regex check for PCI address format D.B.DD.F
            if not re.match(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$", pci_address_full):
                continue

            vendor_path = os.path.join(pci_devices_path, pci_address_full, "vendor")
            device_path = os.path.join(pci_devices_path, pci_address_full, "device")
            class_path = os.path.join(pci_devices_path, pci_address_full, "class")
            driver_path = os.path.join(pci_devices_path, pci_address_full, "driver")

            if not (os.path.exists(vendor_path) and os.path.exists(device_path) and os.path.exists(class_path)):
                continue

            try:
                with open(vendor_path, 'r') as f:
                    vendor_id = f.read().strip()
                with open(device_path, 'r') as f:
                    device_id = f.read().strip()
                with open(class_path, 'r') as f:
                    device_class = f.read().strip()
            except IOError as e:
                logger.warning(f"Warning: Could not read vendor/device/class for {pci_address_full}: {e}")
                continue

            # NVIDIA vendor ID is 0x10de
            # Class codes for VGA/3D/Display controllers usually start with 0x03
            if vendor_id == "0x10de" and device_class.startswith("0x03"):
                # Check if it's currently bound to the 'nvidia' driver
                if os.path.exists(driver_path) and os.path.islink(driver_path):
                    current_driver_link = os.readlink(driver_path)
                    current_driver = os.path.basename(current_driver_link)
                    if current_driver == "nvidia":
                        # Convert full PCI address to short format (remove domain prefix)
                        # from '0000:81:00.0' to '81:00.0' to match vm_manager.py format
                        pci_addr_short = pci_address_full.replace('0000:', '')
                        # Remove '0x' prefix from vendor_id and device_id to match vm_manager.py format
                        vendor_id_no_prefix = vendor_id[2:]
                        device_id_no_prefix = device_id[2:]
                        
                        nvidia_gpus.append({
                            'pci_addr': pci_addr_short,
                            'vendor_id': vendor_id_no_prefix,
                            'device_id': device_id_no_prefix
                        })
    except Exception as e:
        logger.error(f"Error: Could not process PCI devices directory: {e}")
    
    return nvidia_gpus
    

def is_gpu_in_use(pci_address: str) -> bool:
    """
    Checks if a given NVIDIA GPU (by PCI address) is currently in use by any process.
    Requires 'nvidia-smi' to be installed and accessible.

    Args:
        pci_address (str): The PCI address of the GPU (e.g., '81:00.0' or '0000:81:00.0').

    Returns:
        bool: True if the GPU is in use, False otherwise.

    Raises:
        RuntimeError: If nvidia-smi command fails or is not found.
    """
    print(f"  Checking if GPU {pci_address} is in use...")
    try:
        # Use --query-compute-apps to list processes using GPU resources
        # The bus ID in nvidia-smi is typically 00000000:BB:DD.F format (8-digit domain)
        # We need to normalize for comparison.
        smi_output = _run_shell_command(
            "nvidia-smi --query-compute-apps=gpu_bus_id,pid,process_name --format=csv,noheader",
            check_output=False, # nvidia-smi might exit with 1 if no compute processes are running, which is fine
            timeout=15
        )

        # Normalize the input PCI address for comparison with nvidia-smi output
        # nvidia-smi typically uses an 8-digit domain (00000000)
        # First, ensure the PCI address has a domain prefix
        normalized_pci = pci_address
        if ':' in normalized_pci and not normalized_pci.startswith(('0000:', '00000000:')):
            # Add default domain prefix if missing
            normalized_pci = f"0000:{normalized_pci}"
        # Then convert to 8-digit domain for comparison with nvidia-smi output
        normalized_pci_address = normalized_pci.upper().replace('0000:', '00000000:')

        for line in smi_output.splitlines():
            parts = line.strip().split(',')
            if len(parts) >= 3:
                gpu_bus_id_smi = parts[0].strip()
                pid = parts[1].strip()
                process_name = parts[2].strip()

                if gpu_bus_id_smi == normalized_pci_address:
                    print(f"  !!! GPU {pci_address} is currently in use by PID {pid} ({process_name}) !!!")
                    return True
        return False
    except FileNotFoundError as e:
        logger.warning(f"  Warning: nvidia-smi command not found. Cannot reliably check GPU usage. Error: {e}")
    except RuntimeError as e:
        logger.warning(f"  Warning: Failed to query GPU usage with nvidia-smi: {e}. Cannot reliably check GPU usage.")
    except Exception as e:
        logger.error(f"  Unexpected error while checking GPU usage: {e}. Cannot reliably check GPU usage.")
    
    return True


def bind_nvidia_to_vfio(pci_addresses, nvidia_pci_addr_count) -> List[str]:
    """
    Detects all NVIDIA GPUs currently bound to the 'nvidia' driver,
    unbinds them from 'nvidia', and binds them to the 'vfio-pci' driver.
    This prepares them for PCI Passthrough to a virtual machine.

    Args:
        pci_addresses: Can be either:
            - A list of PCI addresses (strings, e.g., ['81:00.0', '85:00.0'])
            - A list of dictionaries (each containing 'pci_addr' key, e.g., [{'pci_addr': '81:00.0', 'vendor_id': '10de', 'device_id': '2501'}])

    Raises:
        RuntimeError: If any critical command fails during setup (e.g., stopping persistenced)
                      or if a specific GPU cannot be unbound due to being in use.

    Returns:
        List[str]: A list of PCI addresses that were successfully bound to 'vfio-pci'.
    """
    # Extract PCI addresses from input data
    extracted_pci_addresses = []
    if isinstance(pci_addresses, list):
        if pci_addresses and isinstance(pci_addresses[0], dict):
            # Input is a list of dictionaries with 'pci_addr' key
            extracted_pci_addresses = [gpu['pci_addr'] for gpu in pci_addresses if 'pci_addr' in gpu]
        else:
            # Input is already a list of strings
            extracted_pci_addresses = pci_addresses
    
    if not extracted_pci_addresses:
        raise ValueError("No valid PCI addresses found in input. Nothing to do.")

    try:
        # 1. Stop nvidia-persistenced service
        logger.info("\nStep 1: Stopping nvidia-persistenced service...")
        _run_shell_command("sudo systemctl stop nvidia-persistenced")
        # Verify service status, might be inactive (dead) and return non-zero exit code
        _run_shell_command("sudo systemctl status nvidia-persistenced", check_output=False, timeout=10)
        logger.info("nvidia-persistenced service stopped.")

        # 2. Load vfio-pci kernel module
        logger.info("\nStep 2: Loading vfio-pci kernel module...")
        _run_shell_command("sudo modprobe vfio-pci")
        logger.info("vfio-pci module loaded.")

        for pci_address in extracted_pci_addresses:
            # Ensure PCI address is in full format (0000:BB:DD.F) for sysfs access
            full_pci_addr = pci_address
            if ':' in full_pci_addr and not full_pci_addr.startswith(('0000:', '00000000:')):
                full_pci_addr = f"0000:{full_pci_addr}"
            
            # 3. Force specify driver_override for vfio-pci
            logger.info(f"\nStep 3:  Setting driver_override for {full_pci_addr} to vfio-pci...")
            _run_shell_command(f"echo 'vfio-pci' | sudo tee /sys/bus/pci/devices/{full_pci_addr}/driver_override")
            logger.info(f"  driver_override set for {full_pci_addr}.")

            # 4. Unbind from nvidia driver
            logger.info(f"\nStep 4:  Unbinding {full_pci_addr} from nvidia driver...")
            _run_shell_command(f"echo '{full_pci_addr}' | sudo tee /sys/bus/pci/drivers/nvidia/unbind")
            logger.info(f"  {full_pci_addr} unbound from nvidia driver.")

            # 5. Bind to vfio-pci driver
            logger.info(f"\nStep 5:  Binding {full_pci_addr} to vfio-pci driver...")
            _run_shell_command(f"echo '{full_pci_addr}' | sudo tee /sys/bus/pci/drivers/vfio-pci/bind")
            logger.info(f"  {full_pci_addr} bound to vfio-pci driver.")

        logger.info("\nStep 6: Verifying all GPUs are bound to vfio-pci driver...")
        for pci_address in extracted_pci_addresses:
            # Ensure PCI address is in full format (0000:BB:DD.F) for sysfs access
            full_pci_addr = pci_address
            if ':' in full_pci_addr and not full_pci_addr.startswith(('0000:', '00000000:')):
                full_pci_addr = f"0000:{full_pci_addr}"
            
            # Check if the GPU is bound to vfio-pci driver
            driver_path = f"/sys/bus/pci/devices/{full_pci_addr}/driver"
            if os.path.exists(driver_path) and os.path.islink(driver_path):
                current_driver_link = os.readlink(driver_path)
                current_driver = os.path.basename(current_driver_link)
                if current_driver == "vfio-pci":
                    logger.info(f"  ✓ {full_pci_addr} is successfully bound to vfio-pci driver.")
                else:
                    logger.error(f"  ✗ {full_pci_addr} is bound to {current_driver}, expected vfio-pci.")
                    raise RuntimeError(f"GPU at {full_pci_addr} failed to bind to vfio-pci driver. Current driver: {current_driver}")
            else:
                logger.error(f"  ✗ {full_pci_addr} has no driver bound to it.")
                raise RuntimeError(f"GPU at {full_pci_addr} has no driver bound to it. Binding to vfio-pci failed.")


        if len(extracted_pci_addresses) < nvidia_pci_addr_count:
        # 7. Start nvidia-persistenced service back up
            logger.info("\nStep 7: Starting nvidia-persistenced service...")
            _run_shell_command("sudo systemctl start nvidia-persistenced")
            # Verify service status, it should be active
            _run_shell_command("sudo systemctl status nvidia-persistenced", check_output=False, timeout=10)
        logger.info("nvidia-persistenced service started.")

    except Exception as e:
        logger.error(f"!!! A critical command failed during vfio-pci binding process: {e} !!!")
        raise Exception(f"Critical command failed: {e}")

    logger.info("\n--- Finished binding process for all NVIDIA GPUs ---")


def bind_gpu_to_nvidia(pci_addresses: list) -> bool:
    """
    Takes a list of PCI addresses, unbinds them from the 'vfio-pci' driver,
    clears their driver_override, and binds them back to the 'nvidia' driver.
    This restores the GPUs for host system usage.

    Args:
        pci_addresses: Can be either:
            - A single PCI address string (e.g., '0000:81:00.0')
            - A list of PCI addresses (strings, e.g., ['81:00.0', '85:00.0'])

    Returns:
        List[str]: A list of PCI addresses that were successfully bound back to the 'nvidia' driver.
    """
    # Normalize input to list
    if isinstance(pci_addresses, str):
        pci_address_list = [pci_addresses]
    elif isinstance(pci_addresses, list):
        pci_address_list = pci_addresses
    else:
        logger.warning(f"Warning: Invalid input type {type(pci_addresses)}. Expected str or list.")
        return []
    
    if not pci_address_list:
        logger.info("No PCI addresses provided. Nothing to do.")
        return []
    
    # List to track successfully bound addresses
    successfully_bound = []
    
    try:
        # 1. Stop nvidia-persistenced service before processing any GPUs
        logger.info("\nStep 1: Stopping nvidia-persistenced service...")
        _run_shell_command("sudo systemctl stop nvidia-persistenced")
        # Verify service status, might be inactive (dead) and return non-zero exit code
        _run_shell_command("sudo systemctl status nvidia-persistenced", check_output=False, timeout=10)
        logger.info("nvidia-persistenced service stopped.")
        
        # Process each PCI address
        for pci_address in pci_address_list:
            # Ensure PCI address is in full format (0000:BB:DD.F) for sysfs access
            full_pci_addr = pci_address
            if ':' in full_pci_addr and not full_pci_addr.startswith(('0000:', '00000000:')):
                full_pci_addr = f"0000:{full_pci_addr}"
            
            logger.info(f"\n--- Starting process to bind GPU {full_pci_addr} back to NVIDIA driver ---")
            
            if not re.match(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$", full_pci_addr):
                logger.warning(f"Warning: Invalid PCI address format: {full_pci_addr}. Skipping.")
                continue
            
            try:
                # IMPORTANT: For this step, the virtual machine using this GPU MUST be completely shut down.
                # If the VM is still running (or even paused but holding the device),
                # the unbind command below will fail with "Device or resource busy".
                logger.info(f"\nStep 2: Unbinding {full_pci_addr} from vfio-pci driver...")
                _run_shell_command(f"echo '{full_pci_addr}' | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind")
                logger.info(f"{full_pci_addr} unbound from vfio-pci driver. (Ensure VM was shut down)")

                # 3. Clear driver_override setting
                logger.info(f"\nStep 3: Clearing driver_override for {full_pci_addr}...")
                _run_shell_command(f"echo '' | sudo tee /sys/bus/pci/devices/{full_pci_addr}/driver_override")
                logger.info(f"driver_override cleared for {full_pci_addr}.")

                # 4. Bind to nvidia driver
                logger.info(f"\nStep 4: Binding {full_pci_addr} to nvidia driver...")
                _run_shell_command(f"echo '{full_pci_addr}' | sudo tee /sys/bus/pci/drivers/nvidia/bind")
                logger.info(f"{full_pci_addr} bound to nvidia driver.")

                # 5. Check if the GPU was successfully bound to nvidia driver
                logger.info(f"\nStep 5: Verifying {full_pci_addr} is bound to nvidia driver...")
                driver_path = f"/sys/bus/pci/devices/{full_pci_addr}/driver"
                if os.path.exists(driver_path) and os.path.islink(driver_path):
                    current_driver_link = os.readlink(driver_path)
                    current_driver = os.path.basename(current_driver_link)
                    if current_driver == "nvidia":
                        logger.info(f"  ✓ {full_pci_addr} is successfully bound to nvidia driver.")
                        successfully_bound.append(pci_address)
                    else:
                        logger.warning(f"  ✗ {full_pci_addr} is bound to {current_driver}, expected nvidia.")
                else:
                    logger.warning(f"  ✗ {full_pci_addr} has no driver bound to it.")

                logger.info(f"\n--- Finished binding process for GPU {full_pci_addr} ---")

            except Exception as e:
                logger.warning(f"!!! Failed to bind {full_pci_addr} back to NVIDIA driver: {e} !!!")
        
        # 6. Start nvidia-persistenced service back up
        logger.info("\nStep 6: Starting nvidia-persistenced service...")
        _run_shell_command("sudo systemctl start nvidia-persistenced")
        # Verify service status, it should be active
        _run_shell_command("sudo systemctl status nvidia-persistenced", check_output=False, timeout=10)
        logger.info("nvidia-persistenced service started.")
     
    except Exception as e:
        logger.error(f"!!! A critical command failed during GPU binding process: {e} !!!")
    
    if len(successfully_bound) == len(pci_address_list):
        logger.info(f"\n--- Successfully bound all {len(pci_address_list)} GPUs back to NVIDIA driver ---")
    else:
        logger.warning(f"\n--- Failed to bind {len(pci_address_list) - len(successfully_bound)} out of {len(pci_address_list)} GPUs back to NVIDIA driver ---")
