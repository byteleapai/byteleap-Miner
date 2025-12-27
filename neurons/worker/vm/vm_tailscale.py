import subprocess
import json
import time
import base64
import logging

logging.basicConfig(level=logging.INFO)


def is_guest_agent_available(vm_id):
    """
    Check if QEMU Guest Agent is available on the virtual machine
    
    Args:
        vm_id: Virtual machine ID or name
        
    Returns:
        bool: True if QEMU Guest Agent is available, False otherwise
    """
    try:
        # Command to check guest agent status
        cmd = ['virsh', 'domstate', vm_id]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        
        # If VM is not running, guest agent can't be available
        if 'running' not in result.stdout.lower():
            return False
        
        # Try a simple command to test guest agent availability
        test_cmd = json.dumps({
            'execute': 'guest-ping'
        })
        
        ping_cmd = ['virsh', 'qemu-agent-command', vm_id, test_cmd, '--timeout', '3']
        ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, check=True, timeout=30)
        
        # Check if response contains 'return' key (successful ping)
        response = json.loads(ping_result.stdout)
        return 'return' in response
    except Exception as e:
        logging.error(f"Error checking QEMU Guest Agent availability: {str(e)}")
        return False


def configure_tailscale_on_vm(vm_id, headscale_url, auth_key):
    """
    Configure Tailscale on a virtual machine via QEMU Guest Agent and connect to Headscale server
    
    Args:
        vm_id: Virtual machine ID or name
        headscale_url: Headscale server URL
        auth_key: Pre-authorized authentication key
    
    Returns:
        dict: Dictionary containing execution result and IP address
    """
    
    logging.info(f"Starting Tailscale configuration for VM {vm_id}...")
    
    try:
        # 1. Check if QEMU Guest Agent is available
        logging.info("Checking QEMU Guest Agent availability...")
        if not is_guest_agent_available(vm_id):
            raise Exception("QEMU Guest Agent is not available. Please ensure it is installed and running in the VM.")
        logging.info("QEMU Guest Agent is available")
        
        # 2. Use Tailscale to connect to Headscale server
        logging.info("Connecting to Headscale server...")
        connect_command = f"sudo tailscale up --login-server={headscale_url} --authkey={auth_key} --accept-routes --accept-dns"
        result = execute_guest_command_with_virsh(vm_id, connect_command)
        
        if not result['success']:
            raise Exception(f'Failed to connect to Headscale server: {result.get("error", "Unknown error")}')
        logging.info("Successfully connected to Headscale server")
        
        # 3. Query Tailscale IP address
        logging.info("Querying Tailscale IP address...")
        time.sleep(2)  # Wait for Tailscale to fully connect
        ip_query_result = execute_guest_command_with_virsh(vm_id, "sudo tailscale ip")
        
        if not ip_query_result['success']:
            raise Exception(f'Failed to query Tailscale IP: {ip_query_result.get("error", "Unknown error")}')
        
        # Parse IP address output
        ip_addresses = ip_query_result['output'].strip().split('\n')
        # Get the first IPv4 address (if any)
        ipv4_address = None
        for ip in ip_addresses:
            if '.' in ip:  # Simple check for IPv4 address
                ipv4_address = ip.strip()
                break
        
        # If no IPv4 address, use the first IP (regardless of type)
        if not ipv4_address and ip_addresses:
            ipv4_address = ip_addresses[0].strip()
        
        if not ipv4_address:
            raise Exception('Failed to obtain a valid Tailscale IP address')
        
        logging.info(f"Successfully obtained Tailscale IP address: {ipv4_address}")
        
        # 4. Return success result and IP address
        return {
            'success': True,
            'ip_address': ipv4_address
        }
        
    except Exception as e:
        logging.error(f"Error configuring Tailscale: {str(e)}")
        return {
            'success': False,
            'message': f'Exception occurred: {str(e)}',
        }


def execute_guest_command_with_virsh(vm_id, command):
    """
    Execute a command inside a virtual machine
    
    Args:
        vm_id: Virtual machine ID or name
        command: Command to execute
    
    Returns:
        dict: Dictionary containing execution result {success: bool, output: str, error: str}
    """
    import subprocess
    import json
    import base64
    import time
    
    try:
        # Build guest-exec command - removed 'exitcode': True parameter
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
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        
        # Parse PID
        response = json.loads(result.stdout)
        pid = response.get('return', {}).get('pid')
        
        if not pid:
            return {'success': False, 'output': '', 'error': 'Failed to get command PID'}
        
        # Wait for command execution to complete, maximum wait 30 seconds
        max_wait = 30
        wait_interval = 0.5
        waited = 0
        
        while waited < max_wait:
            # Query command status
            status_cmd = json.dumps({
                'execute': 'guest-exec-status',
                'arguments': {
                    'pid': pid
                }
            })
            
            status_result = subprocess.run(
                ['virsh', 'qemu-agent-command', vm_id, status_cmd, '--timeout', '5'],
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            
            status_response = json.loads(status_result.stdout)
            return_data = status_response.get('return', {})
            
            if return_data.get('exited', False):
                # Command has exited
                exit_code = return_data.get('exitcode', 1)
                
                # Get output if available
                if return_data.get('out-data'):
                    output = base64.b64decode(return_data['out-data']).decode('utf-8')
                else:
                    output = ''
                
                # Get error if available
                if return_data.get('err-data'):
                    error = base64.b64decode(return_data['err-data']).decode('utf-8')
                else:
                    error = ''
                
                # Return success if exit code is 0
                return {
                    'success': exit_code == 0,
                    'output': output,
                    'error': error if exit_code != 0 else ''
                }
            
            # Wait before checking again
            time.sleep(wait_interval)
            waited += wait_interval
        
        # If we got here, command timed out
        return {'success': False, 'output': '', 'error': 'Command execution timed out'}
        
    except subprocess.CalledProcessError as e:
        return {
            'success': False,
            'output': e.stdout,
            'error': f'Virsh command execution failed: {e.stderr}'
        }
    except Exception as e:
        return {'success': False, 'output': '', 'error': str(e)}