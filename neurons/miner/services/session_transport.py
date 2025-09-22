"""
Session Transport Utilities
Encapsulates session-based encrypted request/response for miner side.
"""

import asyncio
import json
import time
from typing import Any, List, Optional, Tuple

import bittensor as bt

from neurons.shared.protocols import CommunicationResult, ErrorCodes


class SessionTransport:
    """Encapsulates session-based encrypted communication to validators."""

    def __init__(self, wallet: bt.wallet, session_cache, session_crypto):
        self.wallet = wallet
        self.session_cache = session_cache
        self.session_crypto = session_crypto

    async def send_to_validators(
        self,
        operation: str,
        synapse_class: type,
        request_data: Any,
        validators: List[Tuple[int, bt.AxonInfo, str]],
        timeout: int = 30,
    ) -> CommunicationResult:
        """Send request to multiple validators in parallel with filtering."""
        if not validators:
            return CommunicationResult(
                success=False,
                error_code=ErrorCodes.INVALID_REQUEST,
                error_message="No validators available",
            )

        # Filter out invalid/unknown validators proactively
        safe_validators: List[Tuple[int, bt.AxonInfo, str]] = []
        for uid, axon, hotkey in validators:
            try:
                if not isinstance(hotkey, str) or not hotkey:
                    continue
                if not hasattr(axon, "is_serving") or not axon.is_serving:
                    continue
                safe_validators.append((uid, axon, hotkey))
            except Exception:
                continue

        if not safe_validators:
            return CommunicationResult(
                success=False,
                error_code=ErrorCodes.NETWORK_ERROR,
                error_message="No reachable validators",
            )

        bt.logging.debug(f"📤 Sending {operation} | validators={len(safe_validators)}")

        tasks = []
        for uid, axon, validator_hotkey in safe_validators:
            task = self.send_single_request(
                operation=operation,
                synapse_class=synapse_class,
                request_data=request_data,
                target_hotkey=validator_hotkey,
                axon=axon,
                timeout=timeout,
                validator_uid=uid,
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate
        success_count = 0
        total_processing_time = 0.0
        errors = []
        for i, r in enumerate(results):
            if isinstance(r, CommunicationResult) and r.success:
                success_count += 1
                total_processing_time += r.processing_time_ms
            elif isinstance(r, CommunicationResult):
                errors.append(r.error_message or "unknown")
            elif isinstance(r, Exception):
                errors.append(str(r))

        if success_count > 0:
            return CommunicationResult(
                success=True,
                data={
                    "success_count": success_count,
                    "total_count": len(safe_validators),
                },
                processing_time_ms=(
                    total_processing_time / len(safe_validators)
                    if len(safe_validators) > 0
                    else 0.0
                ),
            )
        return CommunicationResult(
            success=False,
            error_code=ErrorCodes.NETWORK_ERROR,
            error_message=f"All targets failed: {'; '.join(errors[:3])}",
        )

    async def send_single_request(
        self,
        operation: str,
        synapse_class: type,
        request_data: Any,
        target_hotkey: str,
        axon: bt.AxonInfo,
        timeout: int,
        validator_uid: Optional[int] = None,
        _retry_count: int = 0,
    ) -> CommunicationResult:
        """Send a single encrypted request using session-based transport."""
        start_time = time.time()
        try:
            # Defensive checks
            if not hasattr(synapse_class, "PROTOCOL_TYPE"):
                raise ValueError("Missing PROTOCOL_TYPE on synapse class")
            if not isinstance(target_hotkey, str) or not target_hotkey:
                raise ValueError("target_hotkey is required")
            if not hasattr(axon, "is_serving") or not axon.is_serving:
                raise ValueError("axon is not serving or invalid")

            session_state, session_error = await self.session_cache.ensure_session(
                target_hotkey, axon
            )
            if not session_state:
                bt.logging.error(
                    f"Session establishment failed for {target_hotkey}: {session_error}"
                )
                return CommunicationResult(
                    success=False,
                    error_code=ErrorCodes.SESSION_REQUIRED,
                    error_message=f"Session required: {session_error}",
                    processing_time_ms=(time.time() - start_time) * 1000,
                )

            seq = session_state.get_next_seq()
            encrypted_request = self.session_crypto.encrypt_with_session(
                request_data,
                session_state.session_id,
                session_state.k_cs,
                seq,
                self.wallet.hotkey.ss58_address,
                target_hotkey,
                synapse_class.PROTOCOL_TYPE,
            )

            synapse = synapse_class(request=encrypted_request)

            async with bt.dendrite(wallet=self.wallet) as dendrite:
                response_synapses = await dendrite.forward(
                    axons=[axon], synapse=synapse, timeout=timeout
                )
                response_synapse = response_synapses[0] if response_synapses else None

            processing_time = (time.time() - start_time) * 1000

            # Normalize raw response
            raw_response = None
            if response_synapse is not None:
                if hasattr(response_synapse, "response"):
                    raw_response = getattr(response_synapse, "response", None)
                elif isinstance(response_synapse, (str, bytes, dict)):
                    raw_response = response_synapse
                else:
                    raw_response = str(response_synapse)

            if raw_response is not None:
                # Plaintext error path
                try:
                    if isinstance(raw_response, bytes):
                        raw_response = raw_response.decode("utf-8", errors="replace")
                    if isinstance(raw_response, str):
                        error_response = json.loads(raw_response)
                    elif isinstance(raw_response, dict):
                        error_response = raw_response
                    else:
                        error_response = None

                    if (
                        isinstance(error_response, dict)
                        and "error" in error_response
                        and "error_code" in error_response
                    ):
                        error_code = error_response["error_code"]
                        error_msg = error_response["error"]

                        session_errors = [
                            ErrorCodes.SEQUENCE_ERROR,
                            ErrorCodes.SESSION_EXPIRED,
                            ErrorCodes.SESSION_UNKNOWN,
                            ErrorCodes.REHANDSHAKE_REQUIRED,
                        ]
                        if error_code in session_errors and _retry_count == 0:
                            bt.logging.warning(
                                f"🔄 Session error from {target_hotkey}, invalidating and retrying"
                            )
                            if error_code == ErrorCodes.SEQUENCE_ERROR:
                                self.session_cache.invalidate_session(
                                    target_hotkey, "sequence_error"
                                )
                            else:
                                self.session_cache.invalidate_session(
                                    target_hotkey, "session_expired_or_unknown"
                                )
                            return await self.send_single_request(
                                operation,
                                synapse_class,
                                request_data,
                                target_hotkey,
                                axon,
                                timeout,
                                validator_uid,
                                _retry_count=1,
                            )
                        return CommunicationResult(
                            success=False,
                            error_code=error_code,
                            error_message=f"Session error: {error_msg}"
                            + (" (retry failed)" if _retry_count > 0 else ""),
                            processing_time_ms=processing_time,
                        )
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass

                # Encrypted path
                try:
                    if isinstance(raw_response, bytes):
                        raw_response = raw_response.decode("utf-8", errors="replace")
                    if not isinstance(raw_response, str):
                        raw_response = str(raw_response)

                    response_data, _, response_seq = (
                        self.session_crypto.decrypt_with_session(
                            raw_response,
                            session_state.k_sc,
                            target_hotkey,
                            self.wallet.hotkey.ss58_address,
                            synapse_class.PROTOCOL_TYPE,
                        )
                    )

                    # Sequence validation
                    if not session_state.replay_validator.validate_sequence(
                        response_seq, "validator"
                    ):
                        bt.logging.warning(
                            f"🔄 Invalid incoming sequence from {target_hotkey}, invalidating session"
                        )
                        self.session_cache.invalidate_session(
                            target_hotkey, "invalid_incoming_sequence"
                        )
                        if _retry_count == 0:
                            return await self.send_single_request(
                                operation,
                                synapse_class,
                                request_data,
                                target_hotkey,
                                axon,
                                timeout,
                                validator_uid,
                                _retry_count=1,
                            )
                        return CommunicationResult(
                            success=False,
                            error_code=ErrorCodes.SEQUENCE_ERROR,
                            error_message=f"Invalid incoming sequence: {response_seq}"
                            + (" (retry failed)" if _retry_count > 0 else ""),
                            processing_time_ms=processing_time,
                        )

                    bt.logging.debug("Session response decrypted")
                except Exception as e:
                    bt.logging.error(
                        f"❌ Session response decrypt error | from={target_hotkey} error={e}"
                    )
                    if "session" in str(e).lower() or "expired" in str(e).lower():
                        self.session_cache.invalidate_session(
                            target_hotkey, "decryption_failed"
                        )
                    return CommunicationResult(
                        success=False,
                        error_code=ErrorCodes.BAD_AAD,
                        error_message=f"Session response decryption failed: {str(e)}",
                        processing_time_ms=processing_time,
                    )

            else:
                response_data = None

            if response_data is None:
                return CommunicationResult(
                    success=False,
                    error_code=ErrorCodes.INVALID_RESPONSE,
                    error_message="Empty or invalid response",
                    processing_time_ms=processing_time,
                )

            return CommunicationResult(
                success=True,
                data=response_data,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            bt.logging.error(
                f"❌ Session request error | target={target_hotkey} error={e}"
            )
            self.session_cache.invalidate_session(target_hotkey)
            return CommunicationResult(
                success=False,
                error_code=ErrorCodes.HANDSHAKE_FAILED,
                error_message=f"Session request failed: {str(e)}",
                processing_time_ms=processing_time,
            )
