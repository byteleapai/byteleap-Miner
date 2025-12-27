# ByteLeap - Bittensor SN128 Compute Network

ByteLeap is a distributed compute resource platform that connects GPU providers with the Bittensor network (SN128). Miners aggregate worker resources and earn rewards through active compute leases and computational challenges.

## Architecture Overview

**Three-tier system:**
- **Validator**: Network coordination and scoring validation
- **Miner**: Resource aggregation and Bittensor network interface
- **Worker**: Hardware monitoring and compute task execution

## Scoring System

Miners earn rewards through two main factors:

### Score Components (Weighted)
- **Lease Revenue** (90%): Active compute rentals generate the primary score
- **Challenge Performance** (10%): Computational benchmarks for idle workers
- **Availability Multiplier**: Based on 169-hour online presence

### How Scoring Works

**Lease Revenue**
- Workers with active compute rentals earn lease scores
- Idle workers score zero on this component
- Integrated with compute marketplace APIs

**Challenge Performance**
- CPU/GPU matrix multiplication benchmarks
- Two-phase verification prevents cheating:
  - Phase 1: Workers commit to results (merkle root)
  - Phase 2: Validators verify through random sampling
- Scoring uses participation baseline + performance ranking
- Rewards consistent participation over peak performance

**Worker Management**
- Maximum 100 workers per miner
- Challenges target only unleased workers
- Final score sums all worker performance (capped at 100)

## Quick Start

### Prerequisites
- Python 3.8+
- Bittensor wallet with registered hotkey

### Hardware Requirements
- CPU: Physical CPU with 8+ cores
- Memory: 32 GB RAM or higher
- GPU: One of the following NVIDIA models
  - GeForce RTX 3090, 4090, 5090
  - Data center GPUs: A100, H100, H200, B200
  - Proper NVIDIA drivers and CUDA runtime installed
- Must be a physical machine or bare metal — deployment on Docker or virtual machines is not supported.

### Installation
```bash
# Setup environment
python3 -m venv venv
source ./venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Setup

Upgrade the system kernel based on the Ubuntu version (for example, Ubuntu 22.04)
If the current kernel version is higher than 6.0.0, the upgrade can be skipped.

```bash 
sudo apt install linux-generic-hwe-22.04
```
After the upgrade is complete, restart the device and then proceed to the next step.

Install these required system packages:
```bash
sudo apt install -y libvirt-daemon-system libvirt-clients qemu-system-x86 virtinst virt-manager virt-viewer libvirt-dev python3-libvirt 
sudo apt install -y qemu-utils 
sudo apt install -y cloud-utils
sudo apt-get install python3-dev
```

After the check is completed, proceed with GPU binding. This operation will bind all local NVIDIA GPUs

```bash
cd bin
./vfio-setup bind
```

After successful binding, reboot the device and perform the verification check.
```bash
./vfio-setup verify
```
If the output is:
```bash
=== Summary ===  
VFIO-bound NVIDIA GPUs: 8  
Other NVIDIA GPUs: 0  
Total NVIDIA GPUs: 8
```
it indicates that the binding was successful. Next, modify the configuration file and start the program.

If the process fails, please run:
```bash
./vfio-setup debug
```
and provide the output to our technical support team so they can assist you with troubleshooting.


### Configuration
Configure your setup in these files:
- `config/miner_config.yaml` - Network settings, wallet, worker management
- `config/worker_config.yaml` - Miner connection, compute settings

**VM Gateway (VMGW) Integration:**
Workers can connect to a VM gateway for virtual machine orchestration and lease management. The VMGW client runs in a dedicated thread, managing enrollment, certificate lifecycle, and mTLS session connectivity:
```yaml
vmgw:
  enable: true
  socket_path: "/run/libvirt/libvirt-sock"  # Socket path to libvirt
```

**Note:** GPU and VMGW features are independent and can be configured separately.

### Test run component

**Start Miner** (aggregates workers, communicates with Bittensor):
```bash
python scripts/run_miner.py --config config/miner_config.yaml
```

**Start Worker** (provides compute resources):
```bash
python scripts/run_worker.py --config config/worker_config.yaml
```

### For production use, please run it with PM2.

Start all services (Miner + Worker):
```bash
pm2 start ecosystem.config.js
```

Start Miner only:
```bash
pm2 start ecosystem.config.js --only byteleap-miner
```

Start Worker only:
```bash
pm2 start ecosystem.config.js --only byteleap-worker
```

**Typical Setup**: Run one miner + multiple workers for optimal resource utilization.

## Technical Architecture

```
┌────────────────────────┐                       ┌───────────────────┐                   ┌────────────────────────┐
│       Validator        │                       │       Miner       │                   │       Worker(s)        │
│      (Bittensor)       │       Encrypted       │    (Bittensor)    │                   │                        │
│                        │ ←── Communication ─── │                   │ ←── WebSocket ──→ │ • System Monitoring    │
│ • Challenge Creation   │    (via bittensor)    │ • Worker Mgmt.    │      (1 : N)      │ • Challenge Execution  │
│ • Score Validation     │                       │ • Resource Agg.   │                   │ • VMGW Session         │
│ • Weight Calculation   │                       │ • Task Routing    │                   │ • Libvirt Mgmt.        │
└────────────────────────┘                       └───────────────────┘                   └────────────────────────┘
```

### Core Components

**Miner** (`neurons/miner/`)
- Worker lifecycle management via WebSocket
- Resource aggregation and reporting
- Bittensor network communication
- Challenge distribution and result collection

**Worker** (`neurons/worker/`)
- Hardware monitoring and status reporting
- CPU/GPU challenge execution
- Compute task processing
- Performance metrics collection
- VM gateway client thread for enrollment + VM lifecycle connectivity (see below)

### VM Gateway Integration

Workers can optionally connect to a VM gateway for virtual machine orchestration:
- Dedicated client thread manages enrollment, certificate lifecycle, and mTLS WebSocket session
- Enrollment tokens are fetched from validators via miner relay
- Certificate artifacts are persisted beside the worker config file
- Automatic certificate validation and renewal ensures continuous connectivity

**Shared Libraries** (`neurons/shared/`)
- Cryptographic challenge protocols
- Merkle tree verification system
- Configuration management
- Network communication utilities

## License

MIT License - see the [LICENSE](LICENSE) file for details.