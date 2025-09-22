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
- **Lease Revenue** (70%): Active compute rentals generate the primary score
- **Challenge Performance** (30%): Computational benchmarks for idle workers
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

### Installation
```bash
# Setup environment
python3 -m venv venv
source ./venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration
Configure your setup in these files:
- `config/miner_config.yaml` - Network settings, wallet, worker management
- `config/worker_config.yaml` - Miner connection, compute settings

**GPU Configuration:**
Workers automatically launch the CUDA binary (`bin/subnet-miner_static`) for GPU challenge execution. The worker config includes:
```yaml
gpu:
  enable: true
  auto_start: true
  binary_path: "./bin/subnet-miner_static"
```

### Running Components

**Start Miner** (aggregates workers, communicates with Bittensor):
```bash
python scripts/run_miner.py --config config/miner_config.yaml
```

**Start Worker** (provides compute resources):
```bash
python scripts/run_worker.py --config config/worker_config.yaml
```

**Typical Setup**: Run one miner + multiple workers for optimal resource utilization.

## Technical Architecture

```
┌────────────────────────┐                       ┌───────────────────┐
│      Validator         │       Encrypted       │       Miner       │
│     (Bittensor)        │ ←── Communication ─── │    (Bittensor)    │
│                        │    (via bittensor)    │                   │
│ • Challenge Creation   │                       │ • Worker Mgmt.    │
│ • Score Validation     │                       │ • Resource Agg.   │
│ • Weight Calculation   │                       │ • Task Routing    │
└────────────────────────┘                       └───────────────────┘
                                                          ↑
                                                          │ WebSocket
                                                          │
                                               ┌───────────────────────┐
                                               │      Worker(s)        │
                                               │                       │
                                               │ • System Monitoring   │
                                               │ • Challenge Execution │
                                               │ • Compute Tasks       │
                                               └───────────────────────┘
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

**Shared Libraries** (`neurons/shared/`)
- Cryptographic challenge protocols
- Merkle tree verification system
- Configuration management
- Network communication utilities

## License

MIT License - see the [LICENSE](LICENSE) file for details.
