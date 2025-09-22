"""
Session Cache for Miner
Manages session state on miner side with single-flight handshake protection
"""

import asyncio
import base64
import threading
import time
from typing import Dict, Optional, Tuple

import bittensor as bt

from neurons.shared.crypto import CryptoManager
from neurons.shared.session_replay_protection import SlidingWindowValidator


class SessionState:
    """Miner-side session state"""

    def __init__(
        self,
        session_id: str,
        k_cs: bytes,
        k_sc: bytes,
        expires_at: float,
        replay_window_size: int = CryptoManager.REPLAY_WINDOW_SIZE,
    ):
        self.session_id = session_id
        self.k_cs = k_cs  # Client to server key
        self.k_sc = k_sc  # Server to client key
        self.expires_at = expires_at
        self.seq_out = 0  # Outgoing sequence number
        self._seq_lock = threading.Lock()  # Protect sequence increment

        # Sliding window validator for incoming sequences from validator
        self.replay_validator = SlidingWindowValidator(replay_window_size)

    def is_expired(self) -> bool:
        """Check if session is expired"""
        return time.time() > self.expires_at

    def is_near_expiry(self, near_expiry_seconds: int) -> bool:
        """Check if session is close to expiry"""
        return (self.expires_at - time.time()) < near_expiry_seconds

    def get_next_seq(self) -> int:
        """Get next sequence number for outgoing messages (thread-safe)"""
        with self._seq_lock:
            self.seq_out += 1
            return self.seq_out


class SessionCache:
    """Miner session cache with single-flight handshake protection"""

    def __init__(self, crypto_manager: CryptoManager, config: Dict):
        self.crypto_manager = crypto_manager

        # Session cache: validator_hotkey -> SessionState
        self._sessions: Dict[str, SessionState] = {}

        # Single-flight handshake protection
        self._handshake_locks: Dict[str, asyncio.Lock] = {}
        self._in_flight_handshakes: Dict[str, asyncio.Future] = {}

        bt.logging.info(
            f"🧭 Session cache initialized | ttl={CryptoManager.SESSION_TTL_SECONDS}s, near_expiry={CryptoManager.NEAR_EXPIRY_THRESHOLD_SECONDS}s"
        )

    async def ensure_session(
        self, validator_hotkey: str, axon_info: bt.AxonInfo
    ) -> Tuple[Optional[SessionState], Optional[str]]:
        """
        Ensure valid session exists with single-flight handshake protection

        Args:
            validator_hotkey: Validator's hotkey
            axon_info: Validator axon information

        Returns:
            Tuple of (session_state, error_message)
        """
        # Check existing session
        current_session = self._sessions.get(validator_hotkey)
        if (
            current_session
            and not current_session.is_expired()
            and not current_session.is_near_expiry(
                CryptoManager.NEAR_EXPIRY_THRESHOLD_SECONDS
            )
        ):
            return current_session, None

        # Get or create lock for this validator
        if validator_hotkey not in self._handshake_locks:
            self._handshake_locks[validator_hotkey] = asyncio.Lock()

        lock = self._handshake_locks[validator_hotkey]

        async with lock:
            # Double-check under lock
            current_session = self._sessions.get(validator_hotkey)
            if (
                current_session
                and not current_session.is_expired()
                and not current_session.is_near_expiry(
                    CryptoManager.NEAR_EXPIRY_THRESHOLD_SECONDS
                )
            ):
                return current_session, None

            if validator_hotkey in self._in_flight_handshakes:
                try:
                    bt.logging.debug(
                        f"⏳ Waiting for in-flight handshake | peer={validator_hotkey}"
                    )
                    await asyncio.wait_for(
                        self._in_flight_handshakes[validator_hotkey],
                        timeout=CryptoManager.HANDSHAKE_TIMEOUT_SECONDS,
                    )

                    # Return newly created session
                    new_session = self._sessions.get(validator_hotkey)
                    if new_session and not new_session.is_expired():
                        return new_session, None
                    else:
                        return None, "Handshake completed but session not available"

                except asyncio.TimeoutError:
                    # Clean up failed handshake
                    self._in_flight_handshakes.pop(validator_hotkey, None)
                    return None, "Handshake timeout"
                except Exception as e:
                    self._in_flight_handshakes.pop(validator_hotkey, None)
                    return None, f"Handshake wait failed: {str(e)}"

            # Start new handshake
            handshake_future = asyncio.Future()
            self._in_flight_handshakes[validator_hotkey] = handshake_future

            try:
                session_state, error_msg = await self._perform_handshake(
                    validator_hotkey, axon_info
                )

                if session_state:
                    self._sessions[validator_hotkey] = session_state
                    bt.logging.info(
                        f"✅ Session established | id={session_state.session_id} peer={validator_hotkey}"
                    )
                    handshake_future.set_result(session_state)
                    # Return newly created session
                    return session_state, None
                else:
                    bt.logging.error(
                        f"❌ Handshake failed | peer={validator_hotkey} | reason={error_msg}"
                    )
                    handshake_future.set_exception(
                        Exception(error_msg or "Handshake failed")
                    )
                    return None, error_msg

            except Exception as e:
                error_msg = f"Handshake error: {str(e)}"
                bt.logging.error(
                    f"❌ Handshake error | peer={validator_hotkey} | error={e}"
                )
                handshake_future.set_exception(e)
                return None, error_msg

            finally:
                # Clean up in-flight tracking
                self._in_flight_handshakes.pop(validator_hotkey, None)

    async def _perform_handshake(
        self, validator_hotkey: str, axon_info: bt.axon
    ) -> Tuple[Optional[SessionState], Optional[str]]:
        """
        Perform actual handshake with validator

        Args:
            validator_hotkey: Validator's hotkey
            axon_info: Validator axon info

        Returns:
            Tuple of (session_state, error_message)
        """
        try:
            # Generate ephemeral key pair
            miner_pub_b64, miner_private_bytes = self.crypto_manager.begin_handshake()

            # Generate client nonce
            client_nonce = CryptoManager.generate_nonce()
            client_nonce_b64 = base64.b64encode(client_nonce).decode("ascii")

            # Create session init request
            import json

            from neurons.shared.protocols import (SessionInitRequest,
                                                  SessionInitSynapse)

            request = SessionInitRequest(
                miner_eph_pub32=miner_pub_b64, client_nonce16=client_nonce_b64
            )

            # Create synapse
            synapse = SessionInitSynapse(request=json.dumps(request.model_dump()))

            # Send handshake request via dendrite using async context manager
            async with bt.dendrite(wallet=self.crypto_manager.wallet) as dendrite:
                response_synapses = await dendrite.forward(
                    axons=[axon_info],
                    synapse=synapse,
                    timeout=CryptoManager.HANDSHAKE_TIMEOUT_SECONDS,
                )

            response_synapse = response_synapses[0] if response_synapses else None

            raw_response = None
            if response_synapse is None:
                return None, "Empty handshake response"

            # Handle common return shapes:
            # - bt.Synapse subclass with .response (expected)
            # - plain string (unencrypted/plaintext error)
            # - bytes (network/middleware error)
            # - dict (already-parsed payload)
            try:
                if hasattr(response_synapse, "response"):
                    raw_response = response_synapse.response
                elif isinstance(response_synapse, (str, bytes, dict)):
                    raw_response = response_synapse
                else:
                    raw_response = str(response_synapse)
            except Exception:
                raw_response = None

            if raw_response is None:
                return None, "Empty handshake response"

            if isinstance(raw_response, bytes):
                raw_response = raw_response.decode("utf-8", errors="replace")

            if isinstance(raw_response, str):
                raw_response = raw_response.strip()
                if not raw_response:
                    return None, "Empty handshake response"
                try:
                    response_data = json.loads(raw_response)
                except Exception:
                    # Treat non-JSON string as plaintext error per protocol rules
                    return None, f"Handshake failed: {raw_response}"
            elif isinstance(raw_response, dict):
                response_data = raw_response
            else:
                return None, "Invalid handshake response type"

            if "error" in response_data:
                return (
                    None,
                    f"Handshake error: {response_data.get('error', 'Unknown error')}",
                )

            from neurons.shared.protocols import SessionInitResponse

            session_response = SessionInitResponse(**response_data)

            # Validate parameter lengths
            validator_pub_bytes = base64.b64decode(
                session_response.validator_eph_pub32.encode("ascii")
            )
            if len(validator_pub_bytes) != 32:
                return (
                    None,
                    f"Invalid validator public key length: {len(validator_pub_bytes)} != 32",
                )

            server_nonce = base64.b64decode(
                session_response.server_nonce16.encode("ascii")
            )
            if len(server_nonce) != 16:
                return None, f"Invalid server nonce length: {len(server_nonce)} != 16"

            k_cs, k_sc = self.crypto_manager.complete_handshake(
                miner_private_bytes,
                miner_pub_b64,
                session_response.validator_eph_pub32,
                client_nonce,
                server_nonce,
                validator_hotkey,
            )

            # Create session state
            session_state = SessionState(
                session_id=session_response.session_id,
                k_cs=k_cs,
                k_sc=k_sc,
                expires_at=session_response.expires_at,
                replay_window_size=CryptoManager.REPLAY_WINDOW_SIZE,
            )

            return session_state, None

        except asyncio.TimeoutError:
            return None, "Handshake request timeout"
        except Exception as e:
            return None, f"Handshake failed: {str(e)}"

    def invalidate_session(
        self, validator_hotkey: str, reason: str = "unknown"
    ) -> None:
        """Remove session from cache with reason tracking"""
        if validator_hotkey in self._sessions:
            session = self._sessions[validator_hotkey]
            bt.logging.info(
                f"🔄 Session invalidated | id={session.session_id} peer={validator_hotkey} reason={reason}"
            )
            del self._sessions[validator_hotkey]

            # Also clean up any in-flight handshakes for this validator
            if validator_hotkey in self._in_flight_handshakes:
                bt.logging.debug(
                    f"Cancelling in-flight handshake for {validator_hotkey}"
                )
                future = self._in_flight_handshakes[validator_hotkey]
                if not future.done():
                    future.cancel()
                del self._in_flight_handshakes[validator_hotkey]
        else:
            bt.logging.debug(
                f"ℹ️ No session to invalidate | peer={validator_hotkey} reason={reason}"
            )

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        expired_sessions = []
        for validator_hotkey, session in self._sessions.items():
            if session.is_expired():
                expired_sessions.append(validator_hotkey)

        for validator_hotkey in expired_sessions:
            self.invalidate_session(validator_hotkey, "expired")

        return len(expired_sessions)

    def get_session_stats(self) -> Dict[str, int]:
        """Get session statistics"""
        self.cleanup_expired_sessions()
        return {
            "total_sessions": len(self._sessions),
            "handshake_locks": len(self._handshake_locks),
            "in_flight_handshakes": len(self._in_flight_handshakes),
        }
