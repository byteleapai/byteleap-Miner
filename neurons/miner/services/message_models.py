"""
Worker<->Miner Message Models
Typed validation for registration, heartbeat, task_result, and proof_response messages
"""

from typing import Any, Dict, List, Literal, Optional

from neurons.shared.protocols import ProofResponse, StrictModel


class WorkerRegistration(StrictModel):
    type: Literal["register"]
    worker_id: str
    worker_name: Optional[str] = None
    worker_version: str
    capabilities: List[str] = []
    system_info: Dict[str, Any] = {}


class HeartbeatPayload(StrictModel):
    status: Optional[str] = None
    active_tasks: Optional[int] = None
    system_info: Dict[str, Any]
    gpu_info: Optional[Dict[str, Any]] = None
    capabilities: List[str] = []


class WorkerHeartbeatMessage(StrictModel):
    type: Literal["heartbeat"]
    data: HeartbeatPayload


class TaskResultData(StrictModel):
    success: bool
    error_code: int
    result: Dict[str, Any] = {}
    error: Optional[str] = None
    error_message: Optional[str] = None
    timestamps: Optional[Dict[str, int]] = None


class TaskResultMessage(StrictModel):
    type: Literal["task_result"]
    worker_id: str
    task_id: str
    timestamp: float
    data: TaskResultData


class ProofResponseData(StrictModel):
    success: bool
    proofs: List[ProofResponse] = []
    debug: Optional[Dict[str, Any]] = None


class ProofResponseMessage(StrictModel):
    type: Literal["proof_response"]
    message_id: str
    data: ProofResponseData


class VmgwEnrollTokenRequestData(StrictModel):
    worker_id: str


class VmgwEnrollTokenRequest(StrictModel):
    type: Literal["vmgw_enroll_token_request"]
    data: VmgwEnrollTokenRequestData


class VmgwEnrollTokenResponseData(StrictModel):
    code: int
    error: Optional[str] = None
    token: Optional[str] = None
    expires_at: Optional[str] = None
    enrollment_url: Optional[str] = None


class VmgwEnrollTokenResponse(StrictModel):
    type: Literal["vmgw_enroll_token_response"]
    data: VmgwEnrollTokenResponseData
