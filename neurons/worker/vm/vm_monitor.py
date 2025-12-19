import time
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import libvirt
import psutil
import subprocess
from loguru import logger


class VMMonitor:
    """VM monitoring class, using libvirt official API to get VM performance metrics"""
    
    def __init__(self, domain):
        """Initialize VM monitor
        
        Args:
            domain: libvirt.Domain object representing the VM to monitor
        """
        self.domain = domain
        self.vm_id = domain.UUIDString()
        self.vm_name = domain.name()
        self.last_cpu_stats = None
        self.last_cpu_time = None
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get complete VM system info, returning same data structure as EnhancedSystemMonitor.get_system_info()
        
        Returns:
            Dict[str, Any]: VM system info dictionary
        """
        try:
            # Check VM state
            if self.domain.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
                logger.warning(f"VM {self.vm_name} is not running, cannot get system info")
                return self.get_empty_system_info()
            
            # Build system info dictionary, consistent with EnhancedSystemMonitor.get_system_info()
            system_info = {
                "cpu_count": self.get_cpu_count(),
                "cpu_usage": self.get_cpu_usage(),
                "memory_total": self.get_memory_total(),
                "memory_available": self.get_memory_available(),
                "memory_usage": self.get_memory_usage(),
                "disk_total": self.get_disk_total(),
                "disk_free": self.get_disk_free(),
                "gpu_info": self.get_gpu_info(),
                "cpu_info": self.get_cpu_info(),
                "memory_info": self.get_memory_info(),
                "system_info": self.get_system_platform_info(),
                "motherboard_info": {},  # VMs usually don't need detailed motherboard info
                "uptime_seconds": self.get_system_uptime(),
                "public_ip": None,  # VMs usually use internal IP
                "storage_info": self.get_storage_info(),
            }
            
            return system_info
        
        except Exception as e:
            logger.error(f"Failed to get system info for VM {self.vm_name}: {str(e)}")
            return self.get_empty_system_info()
    
    def get_cpu_count(self) -> int:
        """Get VM CPU core count
        
        Returns:
            int: CPU core count
        """
        try:
            return self.domain.vcpus()[0]
        except Exception as e:
            logger.error(f"Failed to get CPU core count: {str(e)}")
            return 0
    
    def get_cpu_usage(self, interval: float = 0.1) -> float:
        """Get VM CPU usage, behavior similar to psutil.cpu_percent
    
        Args:
            interval: Sampling interval in seconds. None means return usage since last call
            
        Returns:
            float: CPU usage percentage
        """
        try:
            # Get current CPU stats
            current_cpu_stats = self.domain.getCPUStats(True)
            current_time = time.time()
            
            # First call or no previous stats
            if self.last_cpu_stats is None or self.last_cpu_time is None:
                # Save current state
                self.last_cpu_stats = current_cpu_stats
                self.last_cpu_time = current_time
                # Consistent with psutil, first call returns 0.0
                return 0.0
            
            # If interval is specified, wait and get again (blocking mode)
            if interval is not None:
                time.sleep(interval)
                # Get current state again
                current_cpu_stats = self.domain.getCPUStats(True)
                current_time = time.time()
            
            # Calculate CPU usage
            total_cpu_time_diff = 0
            total_system_time_diff = (current_time - self.last_cpu_time) * 1000 * 1000  # Convert to microseconds
            
            for i in range(len(current_cpu_stats)):
                # Ensure index is valid
                if i < len(self.last_cpu_stats):
                    current_time_val = current_cpu_stats[i].get('cpu_time', 0)
                    last_time_val = self.last_cpu_stats[i].get('cpu_time', 0)
                    total_cpu_time_diff += (current_time_val - last_time_val)
            
            # Calculate CPU usage
            cpu_usage = (total_cpu_time_diff / total_system_time_diff) * 100 if total_system_time_diff > 0 else 0.0
            
            # Update last stats
            self.last_cpu_stats = current_cpu_stats
            self.last_cpu_time = current_time
            
            return min(max(cpu_usage, 0.0), 100.0)  # Ensure value is between 0-100
        except Exception as e:
            logger.error(f"Failed to get CPU usage: {str(e)}")
            return 0.0
    
    def get_memory_total(self) -> int:
        """Get total VM memory (MB)
        
        Returns:
            int: Total memory size in MB
        """
        try:
            memory_stats = self.domain.memoryStats()
            return memory_stats.get('actual', 0) // (1024 * 1024)  # Convert to MB
        except Exception as e:
            logger.error(f"Failed to get total memory: {str(e)}")
            return 0
    
    def get_memory_available(self) -> int:
        """Get available VM memory (MB)
        
        Returns:
            int: Available memory size in MB
        """
        try:
            memory_stats = self.domain.memoryStats()
            total = memory_stats.get('actual', 0)
            used = memory_stats.get('used', 0)
            available = total - used
            return available // (1024 * 1024)  # Convert to MB
        except Exception as e:
            logger.error(f"Failed to get available memory: {str(e)}")
            return 0
    
    def get_memory_usage(self) -> float:
        """Get VM memory usage percentage
        
        Returns:
            float: Memory usage percentage
        """
        try:
            memory_stats = self.domain.memoryStats()
            total = memory_stats.get('actual', 0)
            used = memory_stats.get('used', 0)
            
            if total > 0:
                return (used / total) * 100
            return 0.0
        except Exception as e:
            logger.error(f"Failed to get memory usage: {str(e)}")
            return 0.0
    
    def get_disk_total(self) -> int:
        """Get total VM disk capacity (GB)
        
        Returns:
            int: Total disk capacity in GB
        """
        try:
            # Get VM XML configuration
            xml_desc = self.domain.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            
            # Parse disk information
            disk_total = 0
            for disk in root.findall('.//disk'):
                if disk.get('type') == 'file':
                    # For file-type disks, try to get capacity
                    source = disk.find('./source')
                    if source is not None and source.get('file'):
                        # Simplified processing, actual may need to read file size
                        # Or get more info from device node
                        disk_total += 10  # Assume 10GB per disk by default
            
            return disk_total
        except Exception as e:
            logger.error(f"Failed to get total disk capacity: {str(e)}")
            return 0
    
    def get_disk_free(self) -> int:
        """Get available VM disk space (GB)
        
        Returns:
            int: Available disk space in GB
        """
        try:
            # Simplified implementation, actual may need to get through qemu-guest-agent
            # Assume 50% disk usage here
            total = self.get_disk_total()
            return int(total * 0.5)
        except Exception as e:
            logger.error(f"Failed to get available disk space: {str(e)}")
            return 0
    
    def is_guest_agent_available(self) -> bool:
        """
        Check if QEMU Guest Agent is available
        
        Returns:
            bool: True if Guest Agent is available, False otherwise
        """
        if not self.domain:
            return False
        
        try:
            # Use virsh command to get VM name or UUID
            vm_id = self.domain.UUIDString() if hasattr(self.domain, 'UUIDString') else str(self.domain)
            
            # Use virsh qemu-agent-command to send guest-ping command
            cmd = [
                'virsh', 'qemu-agent-command', 
                vm_id, 
                '{"execute":"guest-ping"}',
                '--timeout', '5'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            
            # Check if response contains success flag
            return 'return' in response
        except Exception as e:
            logger.debug(f"QEMU Guest Agent not available: {e}")
            return False

    def execute_guest_command(self, command: str) -> str:
        """
        Execute command in guest VM using virsh and QEMU Guest Agent
        
        Args:
            command: Command to execute in the guest
            
        Returns:
            str: Command output or empty string on failure
        """
        try:
            # Use virsh command to get VM name or UUID
            vm_id = self.domain.UUIDString() if hasattr(self.domain, 'UUIDString') else str(self.domain)
            
            # Fix parameter format: use 'arg' instead of 'args'
            exec_cmd = json.dumps({
                "execute": "guest-exec",
                "arguments": {
                    "path": "/bin/bash",
                    "arg": ["-c", command],  # Changed from 'args' to 'arg'
                    "capture-output": True
                }
            })
            
            # Execute command to get PID
            cmd = ['virsh', 'qemu-agent-command', vm_id, exec_cmd, '--timeout', '5']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            
            if 'return' not in response or 'pid' not in response['return']:
                logger.error(f"Failed to get PID for command: {command}")
                return ''
            
            pid = response['return']['pid']
            
            # Wait for command execution to complete (max 5 seconds)
            max_wait = 5
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                # Check command execution status
                status_cmd = json.dumps({
                    "execute": "guest-exec-status",
                    "arguments": {"pid": pid}
                })
                
                cmd = ['virsh', 'qemu-agent-command', vm_id, status_cmd, '--timeout', '5']
                status_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                status_response = json.loads(status_result.stdout)
                
                if 'return' not in status_response:
                    logger.error(f"Invalid response for command status: {command}")
                    return ''
                
                status = status_response['return']
                if 'exitcode' in status:
                    # Command execution completed
                    if 'out-data' in status:
                        # Decode base64 encoded output
                        import base64
                        return base64.b64decode(status['out-data']).decode('utf-8', errors='ignore')
                    return ''
                
                time.sleep(0.5)
            
            logger.warning(f"Command execution timed out: {command}")
            return ''
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute command {command}: {e.stderr}")
            return ''
        except Exception as e:
            logger.error(f"Error executing command in guest: {str(e)}")
            return ''

    def get_gpu_info(self) -> List[Dict[str, Any]]:
        """Return GPU info using QEMU Guest Agent. Returns empty list if GPU info cannot be retrieved.
        
        Returns:
            List[Dict[str, Any]]: List of GPU information dictionaries with the same structure as
                                EnhancedSystemMonitor.get_gpu_info_nvml()
        """
        try:
            # Check if guest agent is available
            if not self.is_guest_agent_available():
                logger.warning(f"Unable to get GPU info for VM {self.vm_id}: QEMU Guest Agent not available")
                return []
            
            gpu_info = []
            
            # Check if nvidia-smi is available in guest
            nvidia_smi_check = self.execute_guest_command("which nvidia-smi")
            if nvidia_smi_check and "nvidia-smi" in nvidia_smi_check:
                # Use nvidia-smi to get GPU info in CSV format
                nvidia_smi_output = self.execute_guest_command(
                    "nvidia-smi --query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu,uuid "
                    "--format=csv,noheader,nounits"
                )
                
                if nvidia_smi_output:
                    for i, line in enumerate(nvidia_smi_output.strip().split('\n')):
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 8:
                            gpu_entry = {
                                "id": int(parts[0]),
                                "name": parts[1],
                                "memory_total": int(parts[2]),
                                "memory_used": int(parts[3]),
                                "memory_free": int(parts[4]),
                                "memory_util": float(parts[5]),  # Utilization percentage
                                "gpu_util": float(parts[5]),    # GPU utilization percentage
                                "temperature": float(parts[6]),  # Temperature in Celsius
                                "vendor": "NVIDIA",
                                "type": "discrete",
                                "uuid": parts[7]
                            }
                            gpu_info.append(gpu_entry)
            
            return gpu_info
        except Exception as e:
            logger.error(f"Error getting GPU info from guest: {str(e)}")
            return []
    
    def get_cpu_info(self) -> Dict[str, Any]:
        """Get VM CPU information
        
        Returns:
            Dict[str, Any]: CPU information dictionary
        """
        try:
            # Get VM XML configuration
            xml_desc = self.domain.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            
            # Get CPU configuration info
            vcpu = root.find('./vcpu')
            cpu_count = int(vcpu.text) if vcpu is not None and vcpu.text else 0
            
            cpu_info = {
                "logical_cores": cpu_count,
                "physical_cores": cpu_count,  # In VMs, logical cores equal physical cores
                "architecture": "unknown",
                "processor": f"Virtual CPU {cpu_count} cores",
                "frequency_mhz": {
                    "current": 2000,
                    "min": 2000,
                    "max": 2000
                },
                "brand": "Virtual CPU",
                "model": "unknown",
                "family": "unknown"
            }
            
            return cpu_info
        except Exception as e:
            logger.error(f"Failed to get CPU info: {str(e)}")
            return {}
    
    def get_memory_info(self) -> Dict[str, Any]:
        """Get detailed VM memory information
        
        Returns:
            Dict[str, Any]: Memory information dictionary
        """
        try:
            memory_stats = self.domain.memoryStats()
            
            return {
                "total": memory_stats.get('actual', 0) // (1024 * 1024),
                "available": (memory_stats.get('actual', 0) - memory_stats.get('used', 0)) // (1024 * 1024),
                "used": memory_stats.get('used', 0) // (1024 * 1024),
                "percent": self.get_memory_usage(),
                "swap_total": 0,  # Simplified processing
                "swap_used": 0,   # Simplified processing
                "swap_percent": 0.0
            }
        except Exception as e:
            logger.error(f"Failed to get detailed memory info: {str(e)}")
            return {}
    
    def get_system_platform_info(self) -> Dict[str, Any]:
        """Get VM platform information
        
        Returns:
            Dict[str, Any]: Platform information dictionary
        """
        try:
            # Get VM XML configuration
            xml_desc = self.domain.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            
            # Get operating system information
            os_info = root.find('./os')
            os_type = os_info.find('./type') if os_info is not None else None
            
            system_info = {
                "system": "Linux" if os_type is not None and "linux" in os_type.text.lower() else "Unknown",
                "release": "unknown",
                "version": "unknown",
                "machine": "x86_64",  # Assume most VMs are x86_64 architecture
                "processor": "unknown"
            }
            
            return system_info
        except Exception as e:
            logger.error(f"Failed to get platform info: {str(e)}")
            return {}
    
    def get_system_uptime(self) -> Optional[float]:
        """Get VM uptime
        
        Returns:
            Optional[float]: Uptime in seconds
        """
        try:
            # Get VM state information
            state, reason = self.domain.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                # Get boot time
                info = self.domain.info()
                return info[4]  # info[4] contains uptime in seconds
            return None
        except Exception as e:
            logger.error(f"Failed to get uptime: {str(e)}")
            return None
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get VM storage information
        
        Returns:
            Dict[str, Any]: Storage information dictionary
        """
        try:
            # Get VM XML configuration
            xml_desc = self.domain.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            
            storage_devices = []
            
            # Parse disk information
            for disk in root.findall('.//disk'):
                disk_type = disk.get('type')
                device_type = disk.get('device')
                
                if device_type == 'disk':
                    # Get disk source information
                    source = disk.find('./source')
                    target = disk.find('./target')
                    
                    device_info = {
                        "name": target.get('dev') if target is not None else "unknown",
                        "type": disk_type,
                        "size_gb": 10,  # Default value, should actually get from disk size
                        "model": "unknown",
                        "serial": "unknown"
                    }
                    
                    storage_devices.append(device_info)
            
            return {"storage": storage_devices}
        except Exception as e:
            logger.error(f"Failed to get storage info: {str(e)}")
            return {"storage": []}
    
    def get_empty_system_info(self) -> Dict[str, Any]:
        """Return empty system info dictionary, used when VM info cannot be obtained
        
        Returns:
            Dict[str, Any]: Empty system info dictionary
        """
        return {
            "cpu_count": [],
            "cpu_usage": 0.0,
            "memory_total": 0,
            "memory_available": 0,
            "memory_usage": 0.0,
            "disk_total": 0,
            "disk_free": 0,
            "gpu_info": [],
            "cpu_info": {},
            "memory_info": {},
            "system_info": {},
            "motherboard_info": {},
            "uptime_seconds": None,
            "public_ip": None,
            "storage_info": {"storage": []}
        }