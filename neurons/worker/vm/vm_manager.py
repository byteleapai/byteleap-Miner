import os
import re
import pwd
import grp
import json
import subprocess
import time
import uuid
import asyncio
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Dict, Optional, Callable, List

import libvirt
import psutil
from loguru import logger

from neurons.shared.config.config_manager import ConfigManager
from neurons.worker.vm.vm_monitor import VMMonitor
from neurons.worker.vm.vm_tailscale import configure_tailscale_on_vm
from neurons.worker.vm.vm_sshkey import SSHKeyManager
    

class VirtualMachineInfo:
    """Class for storing virtual machine information and status data"""
    def __init__(self,
                 task_id: str,
                 vm_id: str,
                 vm_name: str,
                 status: str = "running",
                 vcpus: int = 0,
                 gpu_count: int = 0,
                 memory: int = 0,
                 disk_size: int = 0,
                 vm_config: dict = {}):
        self.task_id=task_id
        self.vm_id=vm_id
        self.vm_name=vm_name
        self.status=status
        self.vcpus=vcpus
        self.gpu_count=gpu_count
        self.memory=memory
        self.disk_size=disk_size
        self.vm_config=vm_config


class VMManagerPlugin:
    """Manage virtual machines and collect metrics"""
    def __init__(self, config: ConfigManager, task_id: str, worker_id: str):
        self.task_id = task_id
        self.worker_id = worker_id

        self.vms: Dict[str, VirtualMachineInfo] = {}

        # Assume config is available here
        self.config_manager = config
        self.network_name = "default"

        # Initialize libvirt connection
        self.conn = None
        self._initialize_libvirt_connection()

    def _initialize_libvirt_connection(self, timeout=30):
        """Initialize libvirt connection with timeout mechanism to prevent hanging"""
        start_time = time.time()
        try:
            # Execute connection directly without creating additional threads
            # First try to use qemu:///system, which requires root privileges
            try:
                self.conn = libvirt.open("qemu:///system")
            except libvirt.libvirtError as e1:
                # If system-level connection fails, try user session connection
                logger.warning(f"Failed to connect to system libvirt: {str(e1)}, trying user session...")
                self.conn = libvirt.open("qemu:///session")
                
            # Check if timeout occurred
            if time.time() - start_time > timeout:
                raise Exception(f"Failed to connect to libvirt: Connection timeout after {timeout} seconds")
            
            # Check if connection was successfully established
            if self.conn is None:
                raise Exception("Failed to open connection to libvirt: No valid connection returned")
            
            logger.info(f"Successfully connected to libvirt URI: {str(self.conn.getURI())}")
        except Exception as e:
            raise Exception(f"Failed to connect to libvirt: {str(e)}")

    def _create_virtual_machine(self, xml, flags=0):
        """Define a persistent virtual machine domain and then start it."""
        domain_definition = None
        try:
            # 1. Define the VM persistently using defineXML()
            # This makes the VM definition permanent in libvirt, even after shutdown.
            domain_definition = self.conn.defineXML(xml)

            if domain_definition is None:
                raise Exception("Failed to define domain: defineXML returned None")
            
            domain_name = domain_definition.name()
            logger.info(f"Successfully defined persistent domain '{domain_name}'")

            # 2. Start the defined VM
            # Use domain_definition.create() to run the VM.
            # We pass 0 flags as standard practice.
            if domain_definition.create() < 0:
                raise Exception("Failed to start the defined domain.")

            # Optional: Verify the state after starting
            domain_state = domain_definition.state()[0]
            logger.info(f"Successfully started domain '{domain_name}' with state: {domain_state}")
            
            # Return the active domain object
            return domain_definition

        except Exception as e:
            if domain_definition is not None:
                try:
                    domain_name = domain_definition.name()
                    logger.info(f"Cleaning up failed domain '{domain_name}'")
                    domain_definition.undefine()
                    logger.info(f"Successfully undefine domain '{domain_name}'")
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup domain after creation error: {str(cleanup_error)}")
            raise Exception(f"Failed to create/start domain: {str(e)}")
        
    def _lookup_domain_with_timeout(self, vm_id_or_name):
        """Look up virtual machine domain with timeout mechanism to prevent hanging"""
        start_time = time.time()
        try:
            # Look up directly without creating additional threads
            # First try to look up by UUID
            try:
                domain = self.conn.lookupByUUIDString(vm_id_or_name)
            except libvirt.libvirtError:
                # If UUID lookup fails, try lookup by name
                domain = self.conn.lookupByName(vm_id_or_name)
            
            return domain
        except Exception as e:
            raise Exception(f"Failed to lookup domain: {str(e)}")
        
    def _destroy_domain_with_timeout(self, domain, vm_id):
        """Destroy virtual machine domain with timeout mechanism to prevent hanging"""
        try:
            vm_gpu_pci_addresses = self._extract_vm_gpu_pci_addresses(domain)

            state, _ = domain.state()
            if state != libvirt.VIR_DOMAIN_SHUTOFF:
                # Step 1: # Try to destroy the running domain
                try:
                    domain.destroy()
                except libvirt.libvirtError as destroy_error:
                    raise Exception(f"Failed to destroy domain {vm_id}: {str(destroy_error)}")
            
                # Verify virtual machine is is shut off
                if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_SHUTOFF, wait_seconds=30):
                    raise Exception(f"Failed to shutdown domain {vm_id}")

            # Step 2: Undefine the domain to completely remove it from the system
            try:
                domain.undefine()
            except libvirt.libvirtError as undefine_error:
                # Re-raise other libvirt errors from undefine operation
                raise Exception(f"Failed to undefine domain: {str(undefine_error)}")
            
        except Exception as e:
            raise Exception(f"Failed to destroy domain: {str(e)}")
    def _check_and_fix_disk_permissions(self, vm_id):
        """
        Check and fix disk file permissions for a virtual machine
        Ensures disk files are owned by libvirt-qemu:kvm
        """
        try:
            # Look up the virtual machine
            dom = self._lookup_domain_with_timeout(vm_id)
            if not dom:
                logger.warning(f"Virtual machine {vm_id} not found, skipping permission check")
                return
            
            # Get VM XML to find disk path
            xml_desc = dom.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            disk_elements = root.findall('.//disk')
            
            # Fix permissions for all disk files
            for disk in disk_elements:
                if disk.get('type') == 'file':
                    source = disk.find('source')
                    if source is not None and source.get('file'):
                        disk_path = source.get('file')
                        if os.path.exists(disk_path):
                            try:
                                # Get libvirt-qemu and kvm ids
                                libvirt_uid = pwd.getpwnam('libvirt-qemu').pw_uid
                                kvm_gid = grp.getgrnam('kvm').gr_gid
                                
                                # Check current permissions
                                stat_info = os.stat(disk_path)
                                current_uid = stat_info.st_uid
                                current_gid = stat_info.st_gid
                                
                                # Fix permissions if needed
                                if current_uid != libvirt_uid or current_gid != kvm_gid:
                                    logger.info(f"Fixing permissions for disk {disk_path} from {current_uid}:{current_gid} to {libvirt_uid}:{kvm_gid}")
                                    os.chown(disk_path, libvirt_uid, kvm_gid)
                                    logger.info(f"✅ Successfully fixed permissions for disk {disk_path}")
                            except Exception as e:
                                logger.warning(f"Failed to fix permissions for disk {disk_path}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error checking and fixing disk permissions for VM {vm_id}: {str(e)}")
  
    def create_vm(self, vm_params: Dict[str, Any]) -> Dict[str, Any]:
        """Create virtual machine synchronously"""
        vm_id = None
        try:
            # Generate VM name and ID
            vm_name = vm_params.get("vm_name", "")
            image_name = vm_params.get("image_name", "")

            # Get parameters from configuration
            memory = vm_params.get("memory_mb")
            vcpus = vm_params.get("vcpus")
            gpu_count = vm_params.get("gpu_count", 0)
            disk_size = vm_params.get("disk_size", 10)

            sshkey = vm_params.get("sshkey")
            username = vm_params.get("username", "root")
            password = vm_params.get("password", "TempPassw0rd!")
            vm_name = vm_name if vm_name else f"vm_{self.task_id}"
 
            # Get configuration paths
            cloud_init_dir = vm_params.get("cloud_init_dir", "")
            image_path = os.path.join(cloud_init_dir, image_name)
            meta_data_path = os.path.join(cloud_init_dir, f"meta-data")
            user_data_path = os.path.join(cloud_init_dir, f"user-data")
            cloud_init_iso_path = os.path.join(cloud_init_dir, f"cloud-init.iso")
            
            # Ensure cloud_init_dir exists
            if not os.path.exists(cloud_init_dir):
                raise Exception(f"cloud_init dir does not exist: {cloud_init_dir}")
            
            # Check if network is active
            if not self._is_network_active():
                if not self._activate_network():
                    raise Exception("Failed to activate network, virtual machine creation aborted")
            
            # Shutdown NVML after VM creation
            self._nvml_shutdown()

            # stop the GPU's challenge
            self._stop_gpu_challenge(gpu_count)

            # Create disk path
            disk_path = os.path.join(cloud_init_dir, f"{vm_name}_disk.qcow2")
            
            # Create disk synchronously
            self._create_disk(image_path, disk_path, disk_size)
            
            # Generate cloud-init configurations
            self._generate_cloud_init_configs(meta_data_path, user_data_path, vm_name,
                                              sshkey=sshkey, username=username, password=password)
            
            # Create cloud-init ISO
            self._create_cloud_init_iso(cloud_init_iso_path, meta_data_path, user_data_path)
            
            # Generate XML and create virtual machine
            xml = self._generate_vm_xml(vm_name, memory, gpu_count, vcpus, disk_path, cloud_init_iso_path)

            # Create virtual machine using timeout-enabled call
            logger.info("Start create virtual machine...")
            start_time = time.time()
            dom = self._create_virtual_machine(xml, flags=0)
            if dom is None:
                raise Exception("Failed to create virtual machine")
            end_time = time.time()
            execution_time_ms = (end_time - start_time) * 1000

            # Get created vm id
            vm_id = dom.UUIDString()
            logger.info(f"Created virtual machine with ID: {vm_id}")

            # Verify virtual machine is running
            if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_RUNNING, wait_seconds=30):
                raise Exception(f"Failed to verify virtual machine {vm_name} is running after creation")

            # Get VM status information
            system_info = self._get_vm_system_info(dom)
            
            # Since the program is already running in a thread, no additional lock protection is needed
            vm_info = VirtualMachineInfo(
                task_id=self.task_id,
                vm_id=vm_id,
                vm_name=vm_name,
                status="running",
                vcpus=vcpus,
                gpu_count=gpu_count,
                memory=memory,
                disk_size=disk_size,
                vm_config=system_info
            )
            self.vms[vm_id] = vm_info
            
            return {
                "success": True,
                "execution_time": execution_time_ms,
                "result": {
                    "worker_id": self.worker_id,
                    "task_id": self.task_id,
                    "vm_id": vm_id,
                    "vm_name": vm_name,
                    "vm_status": "running",
                    "system_info": system_info
                }
            }
        except Exception as e:
            logger.error(f"Failed to create virtual machine {vm_name}: {e}")
            return {
                "success": False,
                "error_message": str(e),
                "result": {
                    "worker_id": self.worker_id,
                    "task_id": self.task_id,
                    "vm_id": vm_id,
                }
            }
        
    def _create_disk(self, base_image, disk_path, size_gb=10):
        """Create disk synchronously"""
        if not os.path.exists(base_image):
            raise Exception(f"Base image does not exist: {base_image}")
        
        logger.info(f"Creating disk {disk_path} from {base_image}")
        
        # Check and fix base_image permissions first
        try:
            libvirt_uid = pwd.getpwnam('libvirt-qemu').pw_uid
            kvm_gid = grp.getgrnam('kvm').gr_gid
            
            # Check current permissions of base_image
            stat_info = os.stat(base_image)
            current_uid = stat_info.st_uid
            current_gid = stat_info.st_gid
            
            # Fix permissions if needed
            if current_uid != libvirt_uid or current_gid != kvm_gid:
                logger.warning(f"Fixing permissions for base image {base_image} from {current_uid}:{current_gid} to {libvirt_uid}:{kvm_gid}")
                os.chown(base_image, libvirt_uid, kvm_gid)
                logger.info(f"✅ Successfully fixed permissions for base image {base_image}")
        except Exception as e:
            raise Exception(f"Failed to set permissions for base image {base_image}: {str(e)}")
        
        # Execute synchronous command directly
        cmd = f"qemu-img create -f qcow2 -b {base_image} -F qcow2 {disk_path} {size_gb}G"
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, timeout=20)
            logger.debug(f"Disk creation output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create disk: {cmd}, error: {e.stderr}")
            raise Exception(f"Failed to create disk: {cmd}")
        
        # Verify if disk file was created successfully
        if not os.path.exists(disk_path):
            raise Exception(f"Disk creation command succeeded but file not found: {disk_path}")
        
        # Check and fix disk permissions
        try:
            libvirt_uid = pwd.getpwnam('libvirt-qemu').pw_uid
            kvm_gid = grp.getgrnam('kvm').gr_gid
            os.chown(disk_path, libvirt_uid, kvm_gid)
            logger.info(f"✅ Set correct permissions for newly created disk {disk_path}")
        except Exception as e:
            raise Exception(f"Failed to set permissions for new disk {disk_path}: {str(e)}")
        
    def _generate_cloud_init_configs(self, meta_data_path, user_data_path, vm_name,
                                     sshkey=None, username=None, password=None):
        """
        Generate cloud-init configuration files
        
        Args:
            meta_data_path: Path to meta-data file
            user_data_path: Path to user-data file
            vm_name: Virtual machine name
            sshkey: SSH public key (optional)
            username: Username for password authentication (optional)
            password: Password for password authentication (optional)
        """
        # Implementation of logic to generate meta-data and user-data files
        with open(meta_data_path, 'w') as f:
            f.write(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")
        
        # Start building user-data content
        user_data_content = ["#cloud-config"]
        
        has_ssh_key = bool(sshkey)
        has_credentials = bool(username and password)
        
        user_data_content.append("ssh_pwauth: true")
        
        user_data_content.append("users:")
        user_data_content.append(f"  - name: {username}")
        user_data_content.append("    sudo: ALL=(ALL) NOPASSWD:ALL")
        user_data_content.append("    shell: /bin/bash")
        user_data_content.append("    lock_passwd: false")
        
        if has_ssh_key:
            user_data_content.append(f"    ssh_authorized_keys:")
            user_data_content.append(f"      - {sshkey}")
        
        if has_credentials:
            user_data_content.append("chpasswd:")
            user_data_content.append("  list: |")
            user_data_content.append(f"    {username}:{password}")
            user_data_content.append("  expire: false")
        
        if username == "root" and has_credentials:
            user_data_content.append("runcmd:")
            user_data_content.append("  - sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config")
            user_data_content.append("  - sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config")
            user_data_content.append("  - systemctl restart sshd")
        
        # Write user-data file
        with open(user_data_path, 'w') as f:
            f.write("\n".join(user_data_content))
        
        # Set correct permissions for cloud-init files
        try:
            os.chmod(meta_data_path, 0o644)
            os.chmod(user_data_path, 0o644)
        except Exception as e:
            logger.warning(f"Failed to set permissions for cloud-init files: {e}")
        
    def _create_cloud_init_iso(self, iso_path, meta_data_path, user_data_path):
        """Create cloud-init ISO image"""
        # Use genisoimage or mkisofs command to create ISO
        cmd = f"genisoimage -output {iso_path} -volid cidata -joliet -rock {meta_data_path} {user_data_path}"
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, timeout=20)
            logger.info("genisoimage sucess")
        except subprocess.CalledProcessError:
            # Try using mkisofs as alternative
            cmd = f"mkisofs -output {iso_path} -volid cidata -joliet -rock {meta_data_path} {user_data_path}"
            try:
                result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, timeout=20)
                logger.debug(f"mkisofs output: {result.stdout}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create cloud-init ISO: {cmd}, error: {e.stderr}")
                raise Exception(f"Failed to create cloud-init ISO: {cmd}")
        
        # Set correct permissions for cloud-init ISO
        try:
            os.chmod(iso_path, 0o644)
            libvirt_uid = pwd.getpwnam('libvirt-qemu').pw_uid
            kvm_gid = grp.getgrnam('kvm').gr_gid
            os.chown(iso_path, libvirt_uid, kvm_gid)
        except Exception as e:
            raise Exception(f"Failed to set permissions/owner for cloud-init ISO: {e}")
        
    def _generate_vm_xml(self, name, memory_mb, gpu_count, vcpus, disk_path, cloud_init_iso=None, enable_qemu_guest_agent=True):
        """Generate XML definition for virtual machine, supporting GPU passthrough"""
        use_kvm = os.path.exists('/dev/kvm')
        domain_type = 'kvm' if use_kvm else 'qemu'
        emulator = '/usr/bin/qemu-system-x86_64'
        
        # Ensure all paths use absolute paths
        disk_abs_path = os.path.abspath(disk_path)
        
        # Create root element
        domain = ET.Element('domain', {'type': domain_type})
        
        # Basic configuration
        ET.SubElement(domain, 'name').text = name
        ET.SubElement(domain, 'memory', {'unit': 'MiB'}).text = str(memory_mb)
        ET.SubElement(domain, 'currentMemory', {'unit': 'MiB'}).text = str(memory_mb)
        ET.SubElement(domain, 'vcpu', {'placement': 'static'}).text = str(vcpus)
        
        # OS configuration
        os_elem = ET.SubElement(domain, 'os')
        ET.SubElement(os_elem, 'type', {'arch': 'x86_64', 'machine': 'pc-q35-4.2'}).text = 'hvm'
        ET.SubElement(os_elem, 'boot', {'dev': 'hd'})
        
        # Features
        features = ET.SubElement(domain, 'features')
        ET.SubElement(features, 'acpi')
        ET.SubElement(features, 'apic')
        ET.SubElement(features, 'pae')
        
        # CPU configuration
        cpu = ET.SubElement(domain, 'cpu', {'mode': 'host-model', 'check': 'partial'})
        ET.SubElement(cpu, 'model', {'fallback': 'allow'})
        
        # Clock and power management
        ET.SubElement(domain, 'clock', {'offset': 'utc'})
        ET.SubElement(domain, 'on_poweroff').text = 'destroy'
        ET.SubElement(domain, 'on_reboot').text = 'restart'
        ET.SubElement(domain, 'on_crash').text = 'destroy'
        ET.SubElement(domain, 'on_shutdown').text = 'preserve'
        
        # Devices configuration
        devices = ET.SubElement(domain, 'devices')
        
        # Add GPU passthrough configuration
        if isinstance(gpu_count, int) and gpu_count > 0:
            logger.info("Configuring GPU passthrough...")
            
            # Get available GPU devices
            available_gpus = self._detect_available_gpu_pci_ids()

            if not available_gpus:
                raise Exception("No NVIDIA GPU detected, cannot enable GPU passthrough")

            if gpu_count > len(available_gpus):
                raise Exception(f"Requested {gpu_count} GPUs, but only {len(available_gpus)} available")
            
            used_gpus = available_gpus[:gpu_count]

            # Add device configuration for each GPU
            for gpu in used_gpus:
                pci_addr = gpu['pci_addr']
                
                # Split PCI address (format: bus:slot.function)
                bus, slot_func = pci_addr.split(':')
                slot, func = slot_func.split('.')
                
                # Add PCI device to XML
                hostdev = ET.SubElement(devices, 'hostdev', {'mode': 'subsystem', 'type': 'pci', 'managed': 'yes'})
                source = ET.SubElement(hostdev, 'source')
                ET.SubElement(source, 'address', {
                    'domain': '0x0000',
                    'bus': f'0x{bus}',
                    'slot': f'0x{slot}',
                    'function': f'0x{func}'
                })
                ET.SubElement(hostdev, 'rom', {'bar': 'on', 'file': ''})
            
            # Add controller for VFIO devices
            ET.SubElement(devices, 'controller', {'type': 'pci', 'index': '0', 'model': 'pcie-root'})
            controller = ET.SubElement(devices, 'controller', {'type': 'pci', 'index': '1', 'model': 'pcie-root-port'})
            ET.SubElement(controller, 'model', {'name': 'pcie-root-port'})
            ET.SubElement(controller, 'target', {'chassis': '1', 'port': '0x10'})
            ET.SubElement(controller, 'address', {
                'type': 'pci',
                'domain': '0x0000',
                'bus': '0x00',
                'slot': '0x02',
                'function': '0x0',
                'multifunction': 'on'
            })
        
        # Add virtio-serial device for QEMU Guest Agent
        if enable_qemu_guest_agent:
            logger.info("Configuring virtio-serial device and QEMU Guest Agent...")
            controller = ET.SubElement(devices, 'controller', {'type': 'virtio-serial', 'index': '0'})
            ET.SubElement(controller, 'address', {
                'type': 'pci',
                'domain': '0x0000',
                'bus': '0x00',
                'slot': '0x06',
                'function': '0x0'
            })
            
            channel = ET.SubElement(devices, 'channel', {'type': 'unix'})
            ET.SubElement(channel, 'source', {'mode': 'bind'})
            ET.SubElement(channel, 'target', {'type': 'virtio', 'name': 'org.qemu.guest_agent.0'})
            ET.SubElement(channel, 'address', {
                'type': 'virtio-serial',
                'controller': '0',
                'bus': '0',
                'port': '1'
            })

        # Emulator
        ET.SubElement(devices, 'emulator').text = emulator
        
        # Main disk
        disk = ET.SubElement(devices, 'disk', {'type': 'file', 'device': 'disk'})
        ET.SubElement(disk, 'driver', {'name': 'qemu', 'type': 'qcow2'})
        ET.SubElement(disk, 'source', {'file': disk_abs_path})
        ET.SubElement(disk, 'target', {'dev': 'vda', 'bus': 'virtio'})
        
        # Add cloud-init ISO using absolute path
        if cloud_init_iso:
            # Check if file exists first
            if not os.path.exists(cloud_init_iso):
                logger.warning(f"Warning: cloud-init ISO file does not exist: {cloud_init_iso}")
            else:
                # Use absolute path to ensure libvirt can access the file correctly
                cloud_init_abs_path = os.path.abspath(cloud_init_iso)
                cdrom = ET.SubElement(devices, 'disk', {'type': 'file', 'device': 'cdrom'})
                ET.SubElement(cdrom, 'driver', {'name': 'qemu', 'type': 'raw'})
                ET.SubElement(cdrom, 'source', {'file': cloud_init_abs_path})
                ET.SubElement(cdrom, 'target', {'dev': 'sdb', 'bus': 'sata'})
                ET.SubElement(cdrom, 'readonly')
        
        # Add network interface and other devices
        interface = ET.SubElement(devices, 'interface', {'type': 'network'})
        ET.SubElement(interface, 'source', {'network': self.network_name})
        ET.SubElement(interface, 'model', {'type': 'virtio'})
        
        serial = ET.SubElement(devices, 'serial', {'type': 'pty'})
        ET.SubElement(serial, 'target', {'port': '0'})
        
        console = ET.SubElement(devices, 'console', {'type': 'pty'})
        ET.SubElement(console, 'target', {'type': 'serial', 'port': '0'})
        
        ET.SubElement(devices, 'input', {'type': 'mouse', 'bus': 'ps2'})
        ET.SubElement(devices, 'input', {'type': 'keyboard', 'bus': 'ps2'})
        
        ET.SubElement(devices, 'graphics', {'type': 'vnc', 'port': '-1', 'autoport': 'yes', 'listen': '0.0.0.0'})
        
        video = ET.SubElement(devices, 'video')
        ET.SubElement(video, 'model', {'type': 'cirrus', 'vram': '16384', 'heads': '1'})
        
        # Convert ElementTree to XML string with proper formatting
        xml_str = ET.tostring(domain, encoding='unicode')
        return xml_str

    def _stop_gpu_challenge(self, gpu_count):
        """Stop the GPU challenge"""
        if isinstance(gpu_count, int) and gpu_count > 0:
            from neurons.worker.clients.gpu_client import GPUServerClient
            gpu_client = GPUServerClient(self.config_manager)

            success = False
            attempt = 0
            max_attempts = 3
            while attempt < max_attempts:
                attempt += 1
                try:
                    if not gpu_client.is_connected:
                        logger.debug("Attempting to connect to existing GPU server...")
                        gpu_client.connect()

                    # Check if GPU server is available
                    if gpu_client.is_available():
                        gpu_client.enable_gpu = False
                        logger.info(f"Attempt {attempt}/{max_attempts}: GPU server detected, attempting to stop GPU challenge...")
                        
                        # Stop GPU server to terminate all running challenges
                        # This will stop challenges submitted by gpu_client.submit_challenge()
                        logger.info("Stopping GPU server...")
                        gpu_client.stop_gpu_server()
                        logger.info("✅ GPU server stopped, GPU challenges terminated")
                        
                        # Clean up GPU processes to ensure complete resource release
                        gpu_client._cleanup_gpu_process()
                        logger.info("✅ GPU processes cleaned up, resources released")
                        success = True

                        # Force kill gpu_tensor.sock process
                        self._kill_process_by_name(gpu_client.SOCKET_PATH)
                        
                        break
                    else:
                        logger.info("GPU server not running or unavailable, no need to stop challenges")
                        success = True
                        break
                except Exception as e:
                    logger.warning(f"Attempt {attempt}/{max_attempts}: Error stopping GPU challenge: {str(e)}")
                    time.sleep(1)

            if not success:
                logger.error("Failed to stop GPU challenge after multiple attempts")

    def _nvml_shutdown(self):
        try:
            try:
                import py3nvml.py3nvml as nvml
                nvml.nvmlShutdown()
            except Exception as e:
                # Ignore errors during shutdown
                logger.debug(f"Failed to shutdown NVML: {str(e)}")
            logger.info("✅ System monitor shutdown completed, NVIDIA resources released")
        except Exception as e:
            logger.debug(f"Failed to shutdown system monitor: {str(e)}")

    def _kill_process_by_name(self, process_name):
        """Kill process by name"""
        try:
            # Use timeout to avoid command hanging
            subprocess.run(
                ["pkill", "-f", process_name],
                check=True,
                timeout=10
            )
            logger.info(f"✅ Process {process_name} killed successfully")
        except Exception as e:
            pass

    def _detect_available_gpu_pci_ids(self):
        """Detect GPU device PCI IDs on host machine"""

        # Get all NVIDIA GPUs
        nvidia_pci_addr = self.get_nvidia_pci_addresses()

        return nvidia_pci_addr

    def get_nvidia_pci_addresses(self) -> List[str]:
        """
        Detects all NVIDIA GPUs currently bound to the 'vfio-pci' driver
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
                    # Check if it's currently bound to the 'vfio-pci' driver
                    if os.path.exists(driver_path) and os.path.islink(driver_path):
                        current_driver_link = os.readlink(driver_path)
                        current_driver = os.path.basename(current_driver_link)
                        if current_driver == "vfio-pci":
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
            
            logger.info(f"Detected {len(nvidia_gpus)} NVIDIA GPUs bound to vfio-pci driver: {nvidia_gpus}")

        except Exception as e:
            logger.error(f"Error: Could not process PCI devices directory: {e}")
        
        return nvidia_gpus

    def _get_gpus_availability(self, gpu_pci_map):
        available_gpus = []
        try:
            import py3nvml.py3nvml as nvml
            nvml.nvmlInit()
            
            device_count = nvml.nvmlDeviceGetCount()
            logger.debug(f"NVML detected {device_count} NVIDIA GPUs")
            
            for i in range(device_count):
                try:
                    handle = nvml.nvmlDeviceGetHandleByIndex(i)
                    
                    # Get PCI address from NVML
                    pci_info = nvml.nvmlDeviceGetPciInfo(handle)
                    raw_bus_id = pci_info.busId
                    if isinstance(raw_bus_id, bytes):
                        raw_bus_id = raw_bus_id.decode('utf-8')
                    
                    nvml_pci_addr = raw_bus_id
                    if ':' in raw_bus_id:
                        parts = raw_bus_id.split(':')
                        if len(parts) == 3:
                            nvml_pci_addr = f"{parts[1]}:{parts[2]}"
                    
                    nvml_pci_addr = nvml_pci_addr.lower()
                    
                    # Get status info
                    util = nvml.nvmlDeviceGetUtilizationRates(handle)
                    mem = nvml.nvmlDeviceGetMemoryInfo(handle)
                    
                    # Match by PCI address
                    if nvml_pci_addr in gpu_pci_map:
                        gpu_util = float(util.gpu)
                        mem_util = float(util.memory)
                        # mem_used_pct = (mem.used / mem.total) * 100 if mem.total > 0 else 0
                        
                        logger.info(f"Get GPU {i} with PCI {nvml_pci_addr}: gpu_util={util.gpu}%, mem_util={util.memory}%")
                        if gpu_util < 1 and mem_util < 1:
                            available_gpus.append(gpu_pci_map[nvml_pci_addr])
                    else:
                        logger.warning(f"NVML detected GPU {i} with PCI {nvml_pci_addr}, but not found in lspci results")
                    
                except Exception as e:
                    logger.warning(f"Error getting status for GPU index {i}: {str(e)}")
                    continue
                    
        except ImportError:
            logger.warning("py3nvml not installed, skipping GPU status retrieval")
        except Exception as e:
            logger.warning(f"Error initializing NVML: {str(e)}")
        finally:
            try:
                nvml.nvmlShutdown()
            except Exception:
                pass
            
        # Convert map to list and return
        return available_gpus

    def _is_network_active(self):
        """Check if network is active"""
        # Simplified implementation, should check libvirt network status in practice
        try:
            net = self.conn.networkLookupByName(self.network_name)
            return net.isActive()
        except Exception:
            return False
        
    def _activate_network(self):
        """Activate network"""
        try:
            net = self.conn.networkLookupByName(self.network_name)
            net.create()
            return True
        except Exception as e:
            logger.error(f"Failed to activate network: {e}")
            return False
        
    def _get_vm_system_info(self, domain):
        """Get virtual machine status information formatted similar to system_monitor.get_system_info()"""
        guest_monitor = VMMonitor(domain)
        try:
            state, _ = domain.state()
            if state != libvirt.VIR_DOMAIN_RUNNING:
                logger.error(f"Virtual machine {domain.name()} is not running")
                return guest_monitor.get_empty_system_info()
            
            system_info = guest_monitor.get_system_info()
            
            return system_info
        except Exception as e:
            logger.error(f"Failed to get VM system info: {e}")
        
        return guest_monitor.get_empty_system_info()
        

    def get_vm_status(self, vm_params: dict) -> Dict[str, Any]:
        """Get virtual machine status"""
        vm_id = vm_params.get("vm_id", "")
        try:
            dom = None
            try:
                dom = self.conn.lookupByUUIDString(vm_id)
            except libvirt.libvirtError:
                try:
                    dom = self.conn.lookupByName(vm_id)
                except libvirt.libvirtError:
                    for domain in self.conn.listAllDomains():
                        if domain.UUIDString() == vm_id or domain.name() == vm_id:
                            dom = domain
                            break
            
            if not dom:
                return {
                    "success": False,
                    "error": f"Virtual machine not found: {vm_id}",
                    "result": {
                        "task_id": self.task_id,
                        "worker_id": self.worker_id,
                        "vm_id": vm_id,
                    }
                }
            
            # Get status
            state, _ = dom.state()
            status = "unknown"
            if state == libvirt.VIR_DOMAIN_RUNNING:
                status = "running"
            elif state == libvirt.VIR_DOMAIN_SHUTOFF:
                status = "stopped"
            elif state == libvirt.VIR_DOMAIN_PAUSED:
                status = "paused"
            
            # Record start time
            start_time = time.time()

            # Get detailed information
            vm_system_info= self._get_vm_system_info(dom)
            
            return {
                "success": True,
                "execution_time": (time.time() - start_time) * 1000,
                "result": {
                    "task_id": self.task_id,
                    "worker_id": self.worker_id,
                    "vm_id": vm_id,
                    "vm_name": dom.name(),
                    "vm_status": status,
                    "vm_system_info": vm_system_info
                }
            }
        except Exception as e:
            logger.error(f"Failed to get VM status: {e}")
            return {
                "success": False,
                "error_message": str(e),
                "result": {
                    "task_id": self.task_id,
                    "worker_id": self.worker_id,
                    "vm_id": vm_id,
                }
            }

    def _get_config_from_xml(self, domain, vm_info):
        """
        Get virtual machine configuration from XML description
        """
        try:
            xml_desc = domain.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            
            vcpu_element = root.find('.//vcpu')
            if vcpu_element is not None:
                vm_info["cpu_count"] = int(vcpu_element.text)
            else:
                vm_info["cpu_count"] = 1 
            
            memory_element = root.find('.//memory')
            if memory_element is not None:
                vm_info["memory_mb"] = int(memory_element.text) // 1024
            else:
                vm_info["memory_mb"] = 0
            
            disk_size = 0
            disk_elements = root.findall('.//disk')
            for disk in disk_elements:
                if disk.get('type') == 'file':
                    source = disk.find('source')
                    if source is not None and source.get('file'):
                        disk_path = source.get('file')
                        try:
                            cmd = ['qemu-img', 'info', '--output=json', disk_path]
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                import json
                                disk_info = json.loads(result.stdout)
                                disk_size = disk_info.get('virtual-size', 0) // (1024 * 1024 * 1024)
                        except Exception:
                            disk_size = 0
                    break
            vm_info["disk_gb"] = disk_size
            
            gpu_count = 0
            hostdev_elements = root.findall('.//hostdev')
            for hostdev in hostdev_elements:
                if hostdev.get('type') == 'pci':
                    source = hostdev.find('source')
                    address = source.find('address') if source else None
                    if address and 'domain' in address.attrib and 'bus' in address.attrib:
                        gpu_count += 1
            vm_info["gpu_count"] = gpu_count
        except Exception as e:
            logger.warning(f"Failed to parse VM XML: {e}")
            vm_info["cpu_count"] = 1
            vm_info["gpu_count"] = 0
            vm_info["memory_mb"] = 0
            vm_info["disk_gb"] = 0
    
    def _verify_vm_state(self, vm_id, expected_state, wait_seconds=10, poll_interval=2):
        """
        Verify if virtual machine reaches the expected state with waiting and polling support
        
        Args:
            vm_id: Virtual machine ID or name
            expected_state: Expected state (e.g., libvirt.VIR_DOMAIN_RUNNING)
            wait_seconds: Maximum waiting time in seconds
            poll_interval: Polling interval in seconds
                
        Returns:
            bool: True if expected state is reached before timeout, False otherwise
        """
        start_time = time.time()
        last_state = None
        
        while time.time() - start_time < wait_seconds:
            try:
                # Look up the virtual machine
                dom = self._lookup_domain_with_timeout(vm_id)
                # Get current state
                current_state, _ = dom.state()
                
                # Log state changes for debugging
                if current_state != last_state:
                    logger.debug(f"VM {vm_id} state changed: {last_state} -> {current_state}")
                    last_state = current_state
                
                # Check if expected state is reached
                if current_state == expected_state:
                    logger.info(f"VM {vm_id} successfully reached expected state: {expected_state}")
                    return True
                    
                # Wait briefly before retrying
                time.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Error checking VM {vm_id} state: {str(e)}")
                # For destroy operations, not finding the VM might be normal
                if expected_state == libvirt.VIR_DOMAIN_SHUTOFF and "no domain with matching name" in str(e).lower():
                    logger.info(f"VM {vm_id} appears to be destroyed (not found)")
                    return True
                time.sleep(poll_interval)
        
        logger.warning(f"VM {vm_id} failed to reach state {expected_state} within {wait_seconds} seconds. Last state: {last_state}")
        return False

    def _extract_vm_gpu_pci_addresses(self, dom):
        """Extract PCI addresses of GPUs configured for the VM"""
        gpu_pci_addresses = []
        try:
            xml_desc = dom.XMLDesc(0)
            root = ET.fromstring(xml_desc)
            hostdev_elements = root.findall('.//hostdev')
            
            for hostdev in hostdev_elements:
                if hostdev.get('type') == 'pci':
                    source = hostdev.find('source')
                    if source is None: continue
                    address = source.find('address')
                    
                    if address is not None:
                        try:
                            def to_hex_int(val):
                                if not val: return 0
                                return int(val, 16)

                            domain = to_hex_int(address.attrib.get('domain', '0'))
                            bus = to_hex_int(address.attrib.get('bus', '0'))
                            slot = to_hex_int(address.attrib.get('slot', '0'))
                            func = to_hex_int(address.attrib.get('function', '0'))
                            
                            pci_addr = f"{domain:04x}:{bus:02x}:{slot:02x}.{func:x}"
                            gpu_pci_addresses.append(pci_addr)
                            
                        except ValueError as ve:
                            logger.error(f"Hex conversion error for device in VM: {ve}")
                            continue
        except Exception as e:
            logger.error(f"Failed to extract GPU PCI addresses: {e}")
        
        return gpu_pci_addresses


    def _get_all_running_vms(self):
        """Get all running virtual machines"""
        running_vms = []
        try:
            domains = self.conn.listAllDomains()
            for dom in domains:
                if dom.isActive():
                    running_vms.append(dom)
        except libvirt.libvirtError as e:
            logger.error(f"Failed to get running VMs: {e}")
        return running_vms

    def _get_gpus_in_use_by_other_vms(self, current_vm_id):
        """Get GPU PCI addresses in use by other running virtual machines"""
        gpus_in_use = set()
        running_vms = self._get_all_running_vms()
        
        for dom in running_vms:
            vm_name = dom.name()
            if vm_name == current_vm_id:
                continue  # Skip the current VM we're trying to start
            
            # Extract GPU PCI addresses used by this VM
            vm_gpus = self._extract_vm_gpu_pci_addresses(dom)
            gpus_in_use.update(vm_gpus)
        
        return gpus_in_use

    def _is_gpu_bound_to_vfio_pci(self, pci_addr: str) -> bool:
        """Check if the GPU with given PCI address is bound to vfio-pci driver"""
        try:
            # Ensure PCI address is in full format (0000:BB:DD.F) for sysfs access
            full_pci_addr = pci_addr
            if ':' in full_pci_addr and not full_pci_addr.startswith(('0000:', '00000000:')):
                full_pci_addr = f"0000:{full_pci_addr}"
            
            # Check if the PCI device exists and is bound to vfio-pci driver
            driver_path = f"/sys/bus/pci/devices/{full_pci_addr}/driver"
            if os.path.exists(driver_path) and os.path.islink(driver_path):
                current_driver_link = os.readlink(driver_path)
                current_driver = os.path.basename(current_driver_link)
                return current_driver == "vfio-pci"
            return False
        except Exception as e:
            logger.error(f"Error checking GPU driver for {pci_addr}: {e}")
            return False

    def start_vm(self, vm_params: str) -> Dict[str, Any]:
        """Start virtual machine"""
        vm_id = vm_params.get("vm_id")
        self._check_and_fix_disk_permissions(vm_id)
        
        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id
            }
        }
        
        try:
            dom = self._lookup_domain_with_timeout(vm_id)
            
            if not dom:
                logger.warning(f"Virtual machine not found: {vm_id}")
                base_response["error_message"] = f"Virtual machine not found: {vm_id}"
                return base_response
            
            state, _ = dom.state()
            start_time = time.time()

            # Already running
            if state == libvirt.VIR_DOMAIN_RUNNING:
                logger.info(f"Virtual machine {vm_id} is already running")
                base_response["success"] = True
                base_response["execution_time"] = (time.time() - start_time) * 1000
                return base_response
            
            # Extract GPU PCI addresses configured for this VM
            vm_gpu_pci_addresses = self._extract_vm_gpu_pci_addresses(dom)

            # Check if configured GPUs are still available
            if vm_gpu_pci_addresses:
                logger.info(f"Checking availability of {len(vm_gpu_pci_addresses)} GPUs configured for VM {vm_id}")

                gpus_in_use = self._get_gpus_in_use_by_other_vms(vm_id)
                for pci_addr in vm_gpu_pci_addresses:
                    if not self._is_gpu_bound_to_vfio_pci(pci_addr):
                        # Check if GPU is bound to vfio-pci driver
                        logger.error(f"GPU {pci_addr} configured for VM {vm_id} is not bound to vfio-pci driver")
                        base_response["error_message"] = f"GPU {pci_addr} is not available, cannot start VM {vm_id}"
                        return base_response

                    # Check if GPU is in use by another VM
                    if pci_addr in gpus_in_use:
                        logger.error(f"GPU {pci_addr} configured for VM {vm_id} is already in use by another virtual machine")
                        base_response["error_message"] = f"GPU {pci_addr} is already in use by another virtual machine, cannot start VM {vm_id}"
                        return base_response

            # Shutdown NVML after VM creation
            self._nvml_shutdown()

            # Create virtual machine
            dom.create()

            # Verify virtual machine is running
            if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_RUNNING, wait_seconds=30):
                logger.warning(f"VM {vm_id} start API call succeeded but verification failed")
                base_response["error_message"] = f"Virtual machine {vm_id} failed to start"
                return base_response
            
            if vm_id in self.vms:
                self.vms[vm_id].status = "running"
            
            logger.info(f"Successfully started virtual machine {vm_id}")

            base_response["success"] = True
            base_response["execution_time"] = (time.time() - start_time) * 1000
            base_response["result"]["vm_status"] = "running"
            return base_response
        except libvirt.libvirtError as e:
            logger.error(f"Failed to start virtual machine {vm_id}: {e}")
            base_response["error_message"] = str(e)
            return base_response
        
        except Exception as e:
            logger.error(f"Unexpected error starting virtual machine {vm_id}: {e}")
            base_response["error_message"] = str(e)
            return base_response
    
    def stop_vm(self, vm_params: dict) -> Dict[str, Any]:
        """Stop virtual machine (graceful shutdown)"""
        vm_id = vm_params.get("vm_id")
        self._check_and_fix_disk_permissions(vm_id)

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id
            }
        }

        try:
            # Look up virtual machine using timeout-enabled call
            dom = None
            try:
                dom = self._lookup_domain_with_timeout(vm_id)
            except Exception as e:
                logger.warning(f"Warning: Failed to lookup VM by ID or name: {e}")
                base_response["error_message"] = f"Warning: Failed to lookup VM by ID or name: {e}"
                return base_response
            
            if not dom:
                base_response["error_message"] = f"Virtual machine not found: {vm_id}"
                return base_response
            
            # Record start time
            start_time = time.time()

            # Already stopped
            state, _ = dom.state()
            if state == libvirt.VIR_DOMAIN_SHUTOFF:
                base_response["success"] = True
                base_response["execution_time"] = (time.time() - start_time) * 1000
                return base_response
            
            # Try graceful shutdown first
            try:
                # Request graceful shutdown
                dom.shutdown()
                
                # Wait for VM to shutdown gracefully (up to 60 seconds)
                timeout = 60
                wait_interval = 2
                elapsed = 0
                
                while elapsed < timeout:
                    time.sleep(wait_interval)
                    elapsed += wait_interval
                    state, _ = dom.state()
                    if state == libvirt.VIR_DOMAIN_SHUTOFF:
                        break
                
                # If VM didn't shutdown gracefully, force shutdown
                if state != libvirt.VIR_DOMAIN_SHUTOFF:
                    logger.warning(f"Virtual machine {vm_id} did not shutdown gracefully, forcing power off")
                    dom.destroy()
                
            except libvirt.libvirtError as shutdown_error:
                # If shutdown fails, try force power off
                logger.warning(f"Graceful shutdown failed: {shutdown_error}, attempting force power off")
                dom.destroy()
            
            # Verify virtual machine is really stopped
            if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_SHUTOFF, wait_seconds=30):
                logger.warning(f"VM {vm_id} stop API call succeeded but verification failed")
                base_response["error_message"] = f"Virtual machine {vm_id} failed to stop"
                return base_response

            # Update status in self.vms if exists
            if vm_id in self.vms:
                self.vms[vm_id].status = "stopped"
            
            logger.info(f"Successfully stopped virtual machine {vm_id}")

            base_response["success"] = True
            base_response["execution_time"] = (time.time() - start_time) * 1000
            base_response["result"]["vm_status"] = "stopped"
            return base_response
        except libvirt.libvirtError as e:
            logger.error(f"Failed to stop virtual machine {vm_id}: {e}")
            base_response["error_message"] = str(e)
            return base_response
        except Exception as e:
            logger.error(f"Unexpected error stopping virtual machine {vm_id}: {e}")
            base_response["error_message"] = str(e)
            return base_response

    def reboot_vm(self, vm_params: dict) -> Dict[str, Any]:
        """
        Reboot a virtual machine
        
        Args:
            vm_id_or_name: VM UUID or name to reboot
            
        Returns:
            Dict containing success status and result/error information
        """
        vm_id = vm_params.get("vm_id")
        self._check_and_fix_disk_permissions(vm_id)

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id
            }
        }

        try:
            logger.info(f"Attempting to reboot virtual machine: {vm_id}")
            
            # Look up the domain with timeout mechanism
            dom = None
            try:
                dom = self._lookup_domain_with_timeout(vm_id)
            except Exception as e:
                raise Exception(f"Failed to lookup VM by ID or name: {e}")
            
            if not dom:
                raise Exception(f"Virtual machine not found: {vm_id}")
            
            # Get VM name
            vm_name = dom.name()
            
            # Record start time for execution time measurement
            start_time = time.time()
            
            # Reboot the VM gracefully first
            try:
                logger.info(f"Attempting graceful reboot of VM '{vm_name}'")
                dom.reboot(libvirt.VIR_DOMAIN_REBOOT_GRACEFUL)
                
                # Wait for VM to reach running state again
                if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_RUNNING, wait_seconds=60):
                    raise Exception(f"VM {vm_name} did not return to running state after graceful reboot")
                
                logger.info(f"Successfully performed graceful reboot of VM '{vm_name}'")
            except Exception as e:
                # If graceful reboot fails, try hard reboot
                logger.warning(f"Graceful reboot failed: {str(e)}, attempting hard reboot")
                dom.reboot(0)  # 0 means VIR_DOMAIN_REBOOT_DEFAULT
                
                # Wait for VM to reach running state again
                if not self._verify_vm_state(vm_id, libvirt.VIR_DOMAIN_RUNNING, wait_seconds=60):
                    raise Exception(f"VM {vm_name} did not return to running state after hard reboot")
                
                logger.info(f"Successfully performed hard reboot of VM '{vm_name}'")
            
            # Update VM status in internal tracking
            if vm_id in self.vms:
                self.vms[vm_id].status = "running"
            
            logger.info(f"VM '{vm_name}' ({vm_id}) rebooted successfully")
            
            base_response["success"] = True
            base_response["execution_time"] = (time.time() - start_time) * 1000
            base_response["result"]["vm_status"] = "running"
            return base_response
        except Exception as e:
            logger.error(f"Failed to reboot virtual machine {vm_id}: {str(e)}")
            base_response["error_message"] = str(e)
            return base_response

    def destroy_vm(self, vm_params: str) -> Dict[str, Any]:
        """Destroy virtual machine"""
        vm_id = vm_params.get("vm_id")
        self._check_and_fix_disk_permissions(vm_id)

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id
            }
        }
        try:
            # Look up virtual machine using timeout-enabled call
            dom = None
            
            # Try looking up by ID
            try:
                dom = self._lookup_domain_with_timeout(vm_id)
            except Exception as e:
                logger.warning(f"Warning: Failed to lookup VM by ID or name: {e}")
                base_response["error_message"] = f"Virtual machine not found: {vm_id}"
                return base_response
            
            if not dom:
                base_response["error_message"] = f"Virtual machine not found: {vm_id}"
                return base_response
            
            # Record start time
            start_time = time.time()

            # Destroy virtual machine using timeout-enabled call
            self._destroy_domain_with_timeout(dom, vm_id)
            logger.info(f"Successfully destroyed virtual machine {vm_id}")
            
            # Since the program is already running in a thread, no additional lock protection is needed
            if vm_id in self.vms:
                del self.vms[vm_id]
            
            base_response["success"] = True
            base_response["execution_time"] = (time.time() - start_time) * 1000
            base_response["result"]["vm_status"] = "destroyed"
            return base_response
        except libvirt.libvirtError as e:
            logger.error(f"Failed to destroy virtual machine {vm_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def add_ssh_key(self, vm_params: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = vm_params.get("vm_id")
        sshkey = vm_params.get("sshkey")
        username = vm_params.get("username")
        key_purpose = vm_params.get("key_purpose")

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id,
                "key_purpose": key_purpose
            }
        }

        result = SSHKeyManager().add_ssh_key(
            task_id=self.task_id,
            vm_id=vm_id,
            sshkey=sshkey,
            username=username,
            key_purpose=key_purpose
        )
        if result["success"]:
            base_response["success"] = True
            base_response["execution_time"] = result.get("execution_time", None)
            base_response["result"]["public_key"] = result.get("public_key", None)
        else:
            base_response["error_message"] = result.get("message", "Unknown error")
        return base_response

    def revoke_ssh_key(self, vm_params: Dict[str, Any]) -> Dict[str, Any]:
        vm_id = vm_params.get("vm_id")
        sshkey = vm_params.get("sshkey")
        username = vm_params.get("username")
        key_purpose = vm_params.get("key_purpose")
        created_task_id = vm_params.get("created_task_id")

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id,
                "key_purpose": key_purpose
            }
        }

        result = SSHKeyManager().revoke_ssh_key(
            task_id=self.task_id,
            vm_id=vm_id,
            sshkey=sshkey,
            username=username,
            key_purpose=key_purpose,
            created_task_id=created_task_id
        )

        if result["success"]:
            base_response["success"] = True
            base_response["execution_time"] = result.get("execution_time", None)
        else:
            base_response["error_message"] = result.get("message", "Unknown error")
        return base_response


    def tailscale_on_vm(self, vm_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configure Tailscale on a virtual machine.
        
        Args:
            vm_params: Dictionary containing VM parameters including vm_id, headscale_url, and auth_key
        
        Returns:
            Dict[str, Any]: Result of Tailscale configuration
        """
        vm_id = vm_params.get("vm_id")
        headscale_url = vm_params.get("headscale_url")
        auth_key = vm_params.get("auth_key")

        base_response = {
            "success": False,
            "result": {
                "worker_id": self.worker_id,
                "task_id": self.task_id,
                "vm_id": vm_id,
            }
        }

        start_time = time.time()
        result = configure_tailscale_on_vm(
            vm_id=vm_id,
            headscale_url=headscale_url,
            auth_key=auth_key
        )

        if result["success"]:
            base_response["success"] = True
            base_response["execution_time"] = (time.time() - start_time) * 1000
            base_response["result"]["ip_address"] = result.get("ip_address", None)
        else:
            base_response["error_message"] = result.get("message", "Unknown error")
        return base_response

async def handle_vm_operation(
        config,
        msg_data: Dict[str, Any],
        send_response: Callable[[str, bool, Optional[str], Optional[Dict]], None]
    ) -> None:
    """Handle VM_OPERATION_V1 messages from VMGW and trigger VM operations.
    
    Supports operations like CREATE_VM, START_VM, STOP_VM, etc.
    """
    operation_data = msg_data.get("data", {})
    operation_type = operation_data.get("operation_type")
    vm_params = operation_data.get("data", {})
    task_id = vm_params.get("task_id")
    worker_id = vm_params.get("worker_id")
    
    if not all([operation_type, task_id, worker_id]):
        logger.warning(f"⚠️ Invalid VM operation request: missing required fields")
        await send_response(operation_type, False, "Missing required fields")
        return
    
    logger.info(f"🔄 Processing VM operation | type={operation_type}")
    
    success = False
    error_message = None
    result_data = {}
    
    # define operation timeouts in seconds
    operation_timeouts = {
        "CREATE_VM_REQUEST_V1": 180,
        "TURNON_VM_REQUEST_V1": 120,
        "TURNOFF_VM_REQUEST_V1": 120,
        "MONITOR_VM_STATS_REQUEST_V1": 30,
        "DESTROY_VM_REQUEST_V1": 180,
        "CREATE_SSHKEY_REQUEST_V1": 60,
        "UPDATE_SSHKEY_REQUEST_V1": 60,
        "GET_ROOT_PWD_REQUEST_V1": 30
    }
    
    timeout = operation_timeouts.get(operation_type, 60)  # default 60 seconds
    
    try:
        # get event loop
        loop = asyncio.get_event_loop()
        
        response_type = None
        if operation_type == "CREATE_VM_REQUEST_V1":
            # create vm with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).create_vm, vm_params),
                timeout=timeout
            )
            response_type = "CREATE_VM_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "TURNON_VM_REQUEST_V1":
            # turn on vm with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).start_vm, vm_params),
                timeout=timeout
            )
            response_type = "TURNON_VM_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "TURNOFF_VM_REQUEST_V1":
            # turn off vm with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).stop_vm, vm_params),
                timeout=timeout
            )
            response_type = "TURNOFF_VM_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "REBOOT_VM_REQUEST_V1":
            # reboot vm with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).reboot_vm, vm_params),
                timeout=timeout
            )
            response_type = "REBOOT_VM_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "DESTROY_VM_REQUEST_V1":
            # destroy vm with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).destroy_vm, vm_params),
                timeout=timeout
            )
            response_type = "DESTROY_VM_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "MONITOR_VM_STATS_REQUEST_V1":
            # monitor vm stats with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).get_vm_status, vm_params),
                timeout=timeout
            )
            response_type = "MONITOR_VM_STATS_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "CREATE_SSHKEY_REQUEST_V1":
            # sshkey create with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).add_ssh_key, vm_params),
                timeout=timeout
            )
            response_type = "CREATE_SSHKEY_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "REVOKE_SSHKEY_REQUEST_V1":
            # sshkey update with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).revoke_ssh_key, vm_params),
                timeout=timeout
            )
            response_type = "REVOKE_SSHKEY_RESPONSE_V1"
            success = result_data.get("success", False)
        elif operation_type == "CONNECT_HEADSCALE_REQUEST_V1":
            # get root password with timeout
            result_data = await asyncio.wait_for(
                loop.run_in_executor(None, VMManagerPlugin(config, task_id, worker_id).tailscale_on_vm, vm_params),
                timeout=timeout
            )
            response_type = "CONNECT_HEADSCALE_RESPONSE_V1"
            success = result_data.get("success", False)
        else:
            logger.warning(f"Unsupported operation type: {operation_type}")
        
        if response_type:
            await send_response(response_type, success, error_message, result_data)

    except asyncio.TimeoutError:
        error_message = f"VM operation timed out after {timeout} seconds"
        logger.error(f"⏱️ VM operation timeout | type={operation_type} timeout={timeout}s")
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Error executing VM operation {operation_type}: {e}", exc_info=True)
    

