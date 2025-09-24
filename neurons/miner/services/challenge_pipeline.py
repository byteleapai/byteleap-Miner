"""
Challenge Pipeline
Handles two-phase challenge processing: commitment and proof exchange.
"""

import time
from typing import Any, Dict, List

import bittensor as bt

from neurons.shared.protocols import (Commitment, CommitmentData, ProofData,
                                      ProofRequest, ProofResponse,
                                      ProtocolRegistry, ProtocolTypes)


class ChallengePipeline:
    def __init__(self, transport, worker_manager) -> None:
        self.transport = transport
        self.worker_manager = worker_manager
        self._challenge_source_map: Dict[str, Dict[str, Any]] = {}
        self._challenge_timestamps: Dict[str, Dict[str, int]] = {}

    def record_source(self, challenge_id: str, validator_info: Dict[str, Any]) -> None:
        self._challenge_source_map[challenge_id] = validator_info
        self._challenge_timestamps[challenge_id] = {
            "miner_task_received_ts": int(time.time() * 1000)
        }

    def merge_worker_timestamps(
        self, challenge_id: str, timestamps: Dict[str, int]
    ) -> None:
        existing = self._challenge_timestamps.get(challenge_id, {})
        self._challenge_timestamps[challenge_id] = {**existing, **(timestamps or {})}

    async def handle_task_result(
        self, task_id: str, result: Dict[str, Any], worker_id: str
    ) -> None:
        if not isinstance(result, dict):
            return
        if not result.get("success", False) or result.get("error_code", 0) != 0:
            return
        challenge_result = result.get("result") or {}
        if not isinstance(challenge_result, dict) or not challenge_result.get(
            "commitments"
        ):
            return
        await self._handle_two_phase_challenge(task_id, challenge_result, worker_id)

    async def _handle_two_phase_challenge(
        self, task_id: str, result: Dict[str, Any], worker_id: str
    ) -> None:
        try:
            validator_info = self._challenge_source_map.get(task_id)
            if not validator_info:
                bt.logging.error(f"❌ No source validator | challenge_id={task_id}")
                return

            # Phase 1: send commitment
            bt.logging.info(f"🧪 Phase1 commit | challenge_id={task_id}")
            commitment_data = CommitmentData(
                challenge_id=task_id,
                worker_id=worker_id,
                commitments=[Commitment(**c) for c in result.get("commitments", [])],
            )

            # Phase 1 must respond quickly; if validator doesn't respond
            # (e.g., no proof requests) within 30s, free the worker.
            challenge_synapse_result = await self.transport.send_single_request(
                operation="challenge_commitment",
                synapse_class=ProtocolRegistry.get(ProtocolTypes.CHALLENGE),
                request_data=commitment_data,
                target_hotkey=validator_info["hotkey"],
                axon=validator_info["axon"],
                timeout=30,
                validator_uid=validator_info["uid"],
            )

            self._challenge_timestamps.setdefault(task_id, {})[
                "miner_task_response_ts"
            ] = int(time.time() * 1000)

            if not challenge_synapse_result.success or not isinstance(
                challenge_synapse_result.data, dict
            ):
                bt.logging.error(
                    f"❌ Phase1 commit failed | challenge_id={task_id} error={challenge_synapse_result.error_message}"
                )
                return

            proof_requests_data = challenge_synapse_result.data.get(
                "proof_requests", []
            )
            if not proof_requests_data:
                bt.logging.debug(f"No proofs requested | challenge_id={task_id}")
                return

            proof_requests = [ProofRequest(**pr) for pr in proof_requests_data]
            bt.logging.info(
                f"🧪 Phase1 complete | challenge_id={task_id} proof_requests={len(proof_requests)}"
            )

            proof_response = await self.worker_manager.get_challenge_proof(
                worker_id,
                validator_info["hotkey"],
                task_id,
                [pr.model_dump() for pr in proof_requests],
            )
            if not proof_response or not proof_response.get("success"):
                bt.logging.error(
                    f"❌ Proof generation failed | challenge_id={task_id} error={proof_response.get('error') if proof_response else 'no response'}"
                )
                return

            all_timestamps = {
                **self._challenge_timestamps.get(task_id, {}),
                **result.get("timestamps", {}),
                **(proof_response.get("debug", {}).get("phase2_timestamps", {})),
            }

            proof_data = ProofData(
                challenge_id=task_id,
                proofs=[
                    ProofResponse(**p) for p in (proof_response.get("proofs", []) or [])
                ],
                debug_info={"timestamps": all_timestamps},
            )

            bt.logging.info(f"🧪 Phase2 proof | challenge_id={task_id}")
            proof_result = await self.transport.send_single_request(
                operation="challenge_proof",
                synapse_class=ProtocolRegistry.get(ProtocolTypes.CHALLENGE_PROOF),
                request_data=proof_data,
                target_hotkey=validator_info["hotkey"],
                axon=validator_info["axon"],
                timeout=300,
                validator_uid=validator_info["uid"],
            )

            self._challenge_timestamps.setdefault(task_id, {})[
                "worker_proof_response_ts"
            ] = int(time.time() * 1000)

            if proof_result.success:
                bt.logging.info(
                    f"✅ Two-phase verification complete | challenge_id={task_id}"
                )
            else:
                bt.logging.error(
                    f"❌ Phase2 proof failed | challenge_id={task_id} error={proof_result.error_message}"
                )
        except Exception as e:
            bt.logging.error(
                f"❌ Two-phase handling error | challenge_id={task_id} error={e}",
                exc_info=True,
            )
        finally:
            self._challenge_source_map.pop(task_id, None)
            self._challenge_timestamps.pop(task_id, None)
            # Mark task session complete, unsetting busy on the worker
            try:
                await self.worker_manager.finalize_task_session(worker_id, task_id)
            except Exception:
                pass
