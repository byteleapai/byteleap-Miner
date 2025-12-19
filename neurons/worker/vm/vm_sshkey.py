import time
import os
import json
import logging
import subprocess
import threading
import tempfile
from typing import Dict, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class SSHKeyManager:
    def __init__(self, mappings_file=None):
        """
        Initialize SSH Key Manager
        
        """
        pass
    
    def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """
        Get VM IP address
        
        Args:
            vm_id: VM ID or name
            
        Returns:
            VM IP address or None if not found
        """
        try:
            # Implementation to get VM IP address
            cmd = ['virsh', 'domifaddr', vm_id]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse output to find IP address
            for line in result.stdout.strip().split('\n')[2:]:  # Skip header lines
                parts = line.split()
                if len(parts) >= 4 and parts[2] == 'ipv4':
                    return parts[3].split('/')[0]
            
            logger.warning(f"Failed to get IP for VM {vm_id}")
            return None
        except Exception as e:
            logger.error(f"Error getting VM IP: {e}")
            return None
    
    def execute_with_qemu_agent(self, vm_id: str, command: str) -> Dict[str, Any]:
        """
        Execute command in VM using QEMU Guest Agent
        
        Args:
            vm_id: VM ID or name
            command: Command to execute
            
        Returns:
            Dict with success, output and error fields
        """
        try:
            # Build guest-exec command
            exec_cmd = json.dumps({
                'execute': 'guest-exec',
                'arguments': {
                    'path': '/bin/bash',
                    'arg': ['-c', command],
                    'capture-output': True
                }
            })
            
            # Execute guest-exec command to get PID
            cmd = ['virsh', 'qemu-agent-command', vm_id, exec_cmd, '--timeout', '5']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            
            if 'return' not in response or 'pid' not in response['return']:
                return {'success': False, 'output': '', 'error': 'Failed to get command PID'}
            
            pid = response['return']['pid']
            
            # Wait for command to complete (max 10 seconds)
            max_wait = 10
            wait_interval = 0.5
            waited = 0
            
            while waited < max_wait:
                # Query command status
                status_cmd = json.dumps({
                    'execute': 'guest-exec-status',
                    'arguments': {'pid': pid}
                })
                
                cmd = ['virsh', 'qemu-agent-command', vm_id, status_cmd, '--timeout', '5']
                status_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                status_response = json.loads(status_result.stdout)
                
                if 'return' not in status_response:
                    return {'success': False, 'output': '', 'error': 'Invalid status response'}
                
                status = status_response['return']
                if 'exitcode' in status:
                    # Command completed
                    output = ''
                    if 'out-data' in status:
                        import base64
                        output = base64.b64decode(status['out-data']).decode('utf-8', errors='ignore')
                    return {'success': True, 'output': output, 'error': ''}
                
                waited += wait_interval
                import time
                time.sleep(wait_interval)
            
            return {'success': False, 'output': '', 'error': 'Command execution timed out'}
            
        except subprocess.CalledProcessError as e:
            return {'success': False, 'output': e.stdout, 'error': e.stderr}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}
    
    def add_ssh_key(self, task_id: str, vm_id: str, sshkey: str, username: str, key_purpose: str = 'login') -> Dict[str, Any]:
        """
        Add SSH key to VM
        
        Args:
            task_id: Task ID for tracking
            vm_id: VM ID or name
            sshkey: SSH public key content
            username: Username in the VM
            key_purpose: Key purpose ('login' or 'authentication')
            
        Returns:
            Dict with success status, message, and public_key if authentication type
        """
        try:
            # Validate parameters
            if not all([task_id, vm_id, username]):
                return {'success': False, 'message': 'Missing required parameters', 'public_key': None}
            
            if key_purpose not in ['login', 'authentication']:
                return {'success': False, 'message': f'Invalid key_purpose: {key_purpose}', 'public_key': None}
            
            # Determine home directory - fix root user path issue
            home_dir = '/root' if username == 'root' else f'/home/{username}'
            
            # Determine authorized_keys path based on key_purpose
            if key_purpose == 'login':
                authorized_keys_path = f'{home_dir}/.ssh/authorized_keys'
                ssh_dir_path = f'{home_dir}/.ssh'
            elif key_purpose == 'authentication':
                authorized_keys_path = f'{home_dir}/.ssh/authentication/authorized_keys'
                ssh_dir_path = f'{home_dir}/.ssh/authentication'
            
            # Command list to execute - break down into clear steps
            commands = []
            
            # Step 1: Create directory structure if it doesn't exist
            commands.append(f'sudo mkdir -p {ssh_dir_path}')
            commands.append(f'sudo chown {username}:{username} {ssh_dir_path}')
            commands.append(f'sudo chmod 700 {ssh_dir_path}')
            
            # Step 2: Create authorized_keys file if it doesn't exist
            commands.append(f'sudo touch {authorized_keys_path}')
            commands.append(f'sudo chown {username}:{username} {authorized_keys_path}')
            commands.append(f'sudo chmod 600 {authorized_keys_path}')
            
            # Handle authentication keys (generate new key pair)
            if key_purpose == 'authentication':
                # Step 3: Generate new SSH key pair with unique name
                key_filename = f'id_rsa_authentication_{task_id}'
                key_path = f'{ssh_dir_path}/{key_filename}'
                commands.append(f'cd {ssh_dir_path} && sudo -u {username} ssh-keygen -t rsa -b 4096 -N "" -f {key_path} -q')
                
                # Step 4: Check if generated key already exists in authorized_keys
                commands.append(f'if ! sudo grep -q -f {key_path}.pub {authorized_keys_path}; then sudo cat {key_path}.pub >> {authorized_keys_path}; fi')
                
                # Step 5: Output the generated public key
                commands.append(f'cat {key_path}.pub')
            
            # Handle login keys (use provided key)
            else:
                if not sshkey:
                    return {'success': False, 'message': 'Login key cannot be empty', 'public_key': None}
                
                # Step 3: Write provided key to temporary file to avoid quote issues
                temp_key_file = f'/tmp/ssh_key_{task_id}.tmp'
                escaped_sshkey = sshkey.replace("'", "\\'")
                commands.append(f"echo '{escaped_sshkey}' > {temp_key_file}")
                
                # Step 4: Check if key already exists using file comparison
                commands.append(f'if ! sudo grep -q -f {temp_key_file} {authorized_keys_path}; then sudo cat {temp_key_file} >> {authorized_keys_path}; fi')
                
                # Step 5: Clean up temporary file
                commands.append(f'sudo rm -f {temp_key_file}')
            
            # Step 6: Ensure final permissions are correct
            commands.append(f'sudo chown {username}:{username} {authorized_keys_path}')
            commands.append(f'sudo chmod 600 {authorized_keys_path}')
            
            # Combine all commands into a single shell script
            command = ' && '.join(commands)
            
            start_time = time.time()

            # Try QEMU Guest Agent first
            result = self.execute_with_qemu_agent(vm_id, command)
            
            # If QEMU Guest Agent fails, try SSH fallback
            if not result['success']:
                logger.warning(f"QEMU Guest Agent execution failed, trying SSH fallback: {result['error']}")
                
                # Get VM IP
                vm_ip = self.get_vm_ip(vm_id)
                if not vm_ip:
                    return {'success': False, 'message': 'Failed to get VM IP address for SSH fallback', 'public_key': None}
                
                # For SSH fallback, we need an existing SSH key
                # This is a simplified example - in production, you would use a management key
                return {'success': False, 'message': 'SSH fallback requires a management key, not implemented in this example', 'public_key': None}
            
            # For authentication purpose, the result.output contains the generated public key
            generated_public_key = None
            if key_purpose == 'authentication':
                generated_public_key = result['output'].strip()
                logger.info(f"Generated authentication SSH key pair for task {task_id}, VM {vm_id}")
            else:
                logger.info(f"Added SSH login key for task {task_id}, VM {vm_id}")
            
            logger.info(f"Successfully added {key_purpose} SSH key for task {task_id}, VM {vm_id}")
            return {
                'success': True,
                'public_key': generated_public_key,
                'execution_time': (time.time() - start_time) * 1000
            }
            
        except Exception as e:
            logger.error(f"Error adding SSH key: {e}")
            return {'success': False, 'message': str(e)}
    
    def revoke_ssh_key(self, task_id: str, vm_id: str, sshkey: str = None, 
                       username: str = None, key_purpose: str = None, created_task_id: str = None) -> Dict[str, Any]:
        """
        Revoke SSH key from VM
        
        Args:
            task_id: Task ID for tracking
            vm_id: VM ID or name
            sshkey: SSH public key content to revoke (required for precise revocation)
            username: Username in the VM (optional, will be looked up if not provided)
            key_purpose: Key purpose ('login' or 'authentication') (optional, will be looked up if not provided)
            
        Returns:
            Dict with success status and message
        """
        try:
            # Validate required parameters
            if not all([task_id, vm_id, username, key_purpose]):
                return {'success': False, 'message': 'Missing required parameters'}
            
            # If sshkey is not provided, this is considered an error as we need it to identify the exact key
            if not sshkey:
                return {'success': False, 'message': 'SSH key is required for precise revocation'}
            
            # Determine authorized_keys path based on key_purpose
            home_dir = '/root' if username == 'root' else f'/home/{username}'
            if key_purpose == 'login':
                authorized_keys_path = f'{home_dir}/.ssh/authorized_keys'
            elif key_purpose == 'authentication':
                if not created_task_id:
                    return {'success': False, 'message': 'Authentication key cannot be revoked without created_task_id', 'public_key': None}

                authorized_keys_path = f'{home_dir}/.ssh/authentication/authorized_keys'
                # For authentication keys, also remove the generated key files
                key_filename = f'id_rsa_authentication_{created_task_id}'
                key_path = f'{home_dir}/.ssh/authentication/{key_filename}'
            else:
                return {'success': False, 'message': f'Invalid key_purpose: {key_purpose}'}
            
            escaped_sshkey = sshkey.replace("'", "\\'").strip()
            
            # Create command to remove specific key from authorized_keys
            # Using sed to delete the line containing the exact key
            remove_key_command = f'sudo grep -v -F "{escaped_sshkey}" {authorized_keys_path} > {authorized_keys_path}.tmp ; sudo mv {authorized_keys_path}.tmp {authorized_keys_path}'
            
            # For authentication keys, also remove the generated key pair files
            if key_purpose == 'authentication':
                remove_key_files_command = f'sudo rm -f {key_path} {key_path}.pub'
                command = f'{remove_key_command} && {remove_key_files_command}'
            else:
                command = remove_key_command
            
            # Ensure file permissions are correct after modification
            chmod_command = f'if [ -f {authorized_keys_path} ]; then sudo chown {username}:{username} {authorized_keys_path} && sudo chmod 600 {authorized_keys_path}; fi'
            command = f'{command} && {chmod_command}'
            
            start_time = time.time()

            # Try QEMU Guest Agent first
            result = self.execute_with_qemu_agent(vm_id, command)
            
            # If QEMU Guest Agent fails, try SSH fallback
            if not result['success']:
                logger.warning(f"QEMU Guest Agent execution failed, trying SSH fallback: {result['error']}")
                
                # Get VM IP
                vm_ip = self.get_vm_ip(vm_id)
                if not vm_ip:
                    return {'success': False, 'message': 'Failed to get VM IP address for SSH fallback'}
                
                # For SSH fallback, we need an existing SSH key
                # This is a simplified example - in production, you would use a management key
                return {'success': False, 'message': 'SSH fallback requires a management key, not implemented in this example'}
            
            logger.info(f"Successfully revoked {key_purpose} SSH key for task {task_id}, VM {vm_id}")
            return {
                'success': True,
                'execution_time': (time.time() - start_time) * 1000
            }
            
        except Exception as e:
            logger.error(f"Error revoking SSH key: {e}")
            return {'success': False, 'message': str(e)}
