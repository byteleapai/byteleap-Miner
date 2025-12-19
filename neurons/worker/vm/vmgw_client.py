"""
VM Gateway Client Thread
Manages VM gateway enrollment, certificate lifecycle, and WSS mTLS connection in a
dedicated thread so future libvirt integration can bypass the main event loop.
"""

import asyncio
import base64
import contextlib
import json
import os
import ssl
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
import websockets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from loguru import logger
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout
from websockets.protocol import State as WebSocketState

from neurons.shared.config.config_manager import ConfigManager
from neurons.worker.vm.vm_manager import handle_vm_operation
from neurons.shared.utils.system_monitor import \
    EnhancedSystemMonitor as SystemMonitor

VMGW_STATE_FILE = "vmgw_state.json"
CERT_RENEW_THRESHOLD_DAYS = 30
HEARTBEAT_FALLBACK_SECONDS = 30
RECONNECT_BACKOFF_SECONDS = 5


class VMGatewayClient:
    """Threaded VM gateway client for enrollment and mTLS session management."""

    def __init__(
        self,
        worker_service: "WorkerService",
        worker_id: str,
        worker_version: str,
        capabilities: Optional[list],
        config: ConfigManager,
    ):
        self.worker_service = worker_service
        self.worker_id = worker_id
        self.worker_version = worker_version
        self.capabilities = capabilities or []

        self.config = config
        config_path = Path(self.config.config_file).resolve()
        config_dir = config_path.parent
        self.state_file = config_dir / VMGW_STATE_FILE

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._message_task: Optional[asyncio.Task] = None
        self._session_id: Optional[str] = None
        self._heartbeat_interval = HEARTBEAT_FALLBACK_SECONDS
        self._cert_expires_at: Optional[datetime] = None
        self._connected_at: float = 0.0
        self._expected_nonce: Optional[str] = None
        self._force_reconnect = False
        self._pending_renew_response: Optional[asyncio.Future] = None

        self.system_monitor = SystemMonitor()

    # Thread lifecycle -----------------------------------------------------

    def start(self) -> None:
        """Start the VM gateway client thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="vmgw-client-thread",
            daemon=True,
        )
        self._thread.start()
        logger.info("🚀 VM gateway client thread started")

    def stop(self) -> None:
        """Stop the VM gateway client thread and close resources."""
        self._stop_event.set()
        if self._loop:
            self._loop.call_soon_threadsafe(lambda: None)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)

        logger.info("⏹️ VM gateway client thread stopped")

    # Internal thread entry ------------------------------------------------

    def _run_loop(self) -> None:
        """Thread entry; initializes and runs an asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._run())
        except Exception as e:
            logger.error(f"❌ VM gateway loop error: {e}", exc_info=True)
        finally:
            self._loop.run_until_complete(self._close_ws())
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            self._loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
            self._loop.close()

    async def _run(self) -> None:
        """Main loop with retry/backoff."""
        backoff = RECONNECT_BACKOFF_SECONDS
        while not self._stop_event.is_set():
            try:
                await self._initialize()
                self._force_reconnect = False
                await self._connection_guard()
                backoff = RECONNECT_BACKOFF_SECONDS
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ VM gateway initialization failed: {e}", exc_info=True)
                force_reconnect = self._force_reconnect
                delay = 0 if force_reconnect else backoff
                self._force_reconnect = False
                if delay > 0:
                    await asyncio.sleep(delay)
                if force_reconnect:
                    backoff = RECONNECT_BACKOFF_SECONDS
                else:
                    backoff = min(backoff * 2, 300)

    async def _connection_guard(self) -> None:
        """Monitor active connection until stopped or connection closes."""
        try:
            while not self._stop_event.is_set():
                if not self._ws or self._ws_is_closed():
                    raise ConnectionError("VM gateway connection closed")
                await asyncio.sleep(1)
        finally:
            await self._teardown_connection()

    # Initialization -------------------------------------------------------

    async def _initialize(self) -> None:
        """Initialize connection: reuse existing certificate or enroll anew."""
        state = await asyncio.to_thread(self._load_state)

        if state:
            try:
                await self._connect_with_state(state)
                return
            except Exception as e:
                if self._is_certificate_error(e):
                    logger.warning(f"⚠️ VMGW certificate invalid, re-enrolling: {e}")
                    # Try to reuse existing private key if available
                    existing_key_pem = state.get("deviceKeyPem")
                    await self._enroll_and_connect(existing_key_pem=existing_key_pem)
                    return
                else:
                    logger.debug(
                        f"VMGW connection failed (will retry with existing cert): {e}"
                    )
                    raise

        await self._enroll_and_connect()

    def _is_certificate_error(self, error: Exception) -> bool:
        """Determine if error is certificate-related vs network-related."""
        error_str = str(error).lower()
        error_type = type(error).__name__

        cert_indicators = [
            "certificate",
            "ssl",
            "tls",
            "key values mismatch",
            "key_values_mismatch",
            "certificate verify failed",
            "certificate has expired",
            "certificate is not yet valid",
            "unable to get local issuer certificate",
            "self signed certificate",
            "wrong version number",
        ]

        if isinstance(error, ssl.SSLError):
            return True

        for indicator in cert_indicators:
            if indicator in error_str or indicator in error_type.lower():
                return True

        return False

    # State management -----------------------------------------------------
    def _parse_iso_datetime(self, iso_str: str) -> datetime:
        """Parse ISO datetime string with optional microseconds and Zulu offset."""
        iso_str = iso_str.replace("Z", "+00:00")
        
        if "." in iso_str and "+" in iso_str:
            dt_part, tz_part = iso_str.split("+", 1)
            tz_part = "+" + tz_part
            
            if "." in dt_part:
                date_time_part, microsec_part = dt_part.split(".", 1)
                if len(microsec_part) > 6:
                    microsec_part = microsec_part[:6]
                dt_part = f"{date_time_part}.{microsec_part}"
            
            iso_str = f"{dt_part}{tz_part}"
        
        return datetime.fromisoformat(iso_str)


    def _load_state(self) -> Optional[Dict[str, Any]]:
        """Load persisted VMGW state if available and well-formed."""
        if not self.state_file.exists():
            return None
        try:
            with self.state_file.open("r", encoding="utf-8") as f:
                state = json.load(f)
            required = {
                "deviceCertPem",
                "deviceKeyPem",
                "caBundle",
                "expiresAt",
                "wsUrl",
            }
            if not required.issubset(state.keys()):
                logger.warning("⚠️ VMGW state file missing required fields")
                return None

            expires_at = self._parse_iso_datetime(state["expiresAt"])
            self._cert_expires_at = expires_at
            return state
        except Exception as e:
            logger.error(f"❌ Failed to load VMGW state: {e}")
            return None

    def _cleanup_state(self) -> None:
        """Delete persisted state file."""
        try:
            if self.state_file.exists():
                os.chmod(self.state_file, 0o600)
                self.state_file.unlink()
                logger.debug(f"Deleted VMGW state file: {self.state_file.name}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to remove state file: {e}")

        self._cert_expires_at = None

    # Enrollment -----------------------------------------------------------

    async def _enroll_and_connect(self, existing_key_pem: Optional[str] = None) -> None:
        """Run full enrollment flow then establish mTLS connection.

        Args:
            existing_key_pem: If provided, reuse this private key instead of generating new one.
                             This ensures compatibility with server-cached certificates.
        """
        token_bundle = await asyncio.to_thread(
            self.worker_service.request_vmgw_enroll_token_sync
        )
        if not token_bundle:
            raise RuntimeError("no enrollment token data received")

        # Reuse existing private key if available (server may return cached cert)
        if existing_key_pem:
            try:
                private_key = serialization.load_pem_private_key(
                    existing_key_pem.encode("utf-8"),
                    password=None,
                    backend=default_backend(),
                )
                logger.debug("Reusing existing private key for re-enrollment")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load existing key, generating new: {e}")
                private_key = ec.generate_private_key(
                    ec.SECP256R1(), backend=default_backend()
                )
        else:
            private_key = ec.generate_private_key(
                ec.SECP256R1(), backend=default_backend()
            )

        csr = self._generate_csr(private_key)

        enroll_response = await asyncio.to_thread(
            self._call_enroll,
            token_bundle["enrollment_url"],
            token_bundle["token"],
            csr,
        )

        await asyncio.to_thread(
            self._persist_enrollment,
            enroll_response,
            private_key,
        )

        # Reload state to get complete data including deviceKeyPem
        state = await asyncio.to_thread(self._load_state)
        if not state:
            raise RuntimeError("Failed to load state after enrollment")

        await self._connect_with_state(state)

    def _generate_csr(self, private_key: ec.EllipticCurvePrivateKey) -> str:
        """Create CSR for workerId using SECP256R1."""
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.worker_id),
                ]
            )
        )
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def _call_enroll(self, url: str, token: str, csr_pem: str) -> Dict[str, Any]:
        # Get initial system info
        system_info = self.system_monitor.get_system_info()
        # Align GPU reporting with heartbeat logic
        try:
            gpu_info = self.task_executor.get_gpu_heartbeat_data()
            plugin_active = bool(
                gpu_info
                and gpu_info.get("gpu_available")
                and gpu_info.get("gpu_count", 0) > 0
                and gpu_info.get("gpu_details")
            )
            if plugin_active:
                system_info["gpu_plugin"] = gpu_info.get("gpu_details", [])
            else:
                nvml_gpus = self.system_monitor.get_gpu_info_nvml()
                if isinstance(nvml_gpus, list) and nvml_gpus:
                    system_info["gpu_info"] = nvml_gpus
        except Exception:
            pass

        """Synchronous call to /enroll endpoint."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {
            "workerId": self.worker_id,
            "workerName": self.worker_service.worker_name,
            "workerVersion": self.worker_version,
            "capabilities": self.capabilities,
            "csrPem": csr_pem,
            "metadata": system_info,
        }
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        required = {"deviceCertPem", "caBundle", "expiresAt", "wsUrl"}
        if not required.issubset(data.keys()):
            raise RuntimeError("enroll response missing required fields")
        return data

    def _persist_enrollment(
        self,
        enroll_response: Dict[str, Any],
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """Persist enrollment response and private key to disk with strict perms."""
        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Verify certificate and private key match BEFORE persisting
        try:
            cert = x509.load_pem_x509_certificate(
                enroll_response["deviceCertPem"].encode("utf-8"), default_backend()
            )
            cert_public_key = cert.public_key()
            private_public_key = private_key.public_key()

            cert_public_numbers = cert_public_key.public_numbers()
            private_public_numbers = private_public_key.public_numbers()

            if (
                cert_public_numbers.x != private_public_numbers.x
                or cert_public_numbers.y != private_public_numbers.y
            ):
                raise RuntimeError(
                    "Certificate and private key mismatch detected! "
                    "Server returned a certificate that doesn't match our CSR."
                )
            logger.debug("Verified certificate and private key match")
        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"❌ Certificate/key verification failed: {e}")
            raise RuntimeError(f"Certificate/key verification failed: {e}") from e

        # Try to read existing state to check if certificate changed
        existing_state = {}
        if self.state_file.exists():
            try:
                with self.state_file.open("r", encoding="utf-8") as f:
                    existing_state = json.load(f)
            except Exception as e:
                logger.warning(f"⚠️ Failed to read existing state, will create new: {e}")
                existing_state = {}

        # Extract certificate serial for tracking
        cert_serial_hex = enroll_response.get("certSerial")
        if not cert_serial_hex:
            # If not provided in response, extract from certificate
            cert_serial_hex = cert.serial_number.to_bytes(
                (cert.serial_number.bit_length() + 7) // 8, "big"
            ).hex()

        # Check if certificate is unchanged (server returned cached cert)
        cert_unchanged = (
            existing_state.get("deviceCertPem") == enroll_response["deviceCertPem"]
            and existing_state.get("deviceKeyPem") == private_key_pem
        )

        if cert_unchanged:
            logger.debug("Server returned cached certificate, no state update needed")
            # Still update expiry tracking in memory
            self._cert_expires_at = self._parse_iso_datetime(enroll_response["expiresAt"])
            return

        # Certificate changed, update state
        logger.debug("Certificate changed, updating state")
        state = existing_state.copy()
        state.update(
            {
                "deviceCertPem": enroll_response["deviceCertPem"],
                "deviceKeyPem": private_key_pem,
                "caBundle": enroll_response["caBundle"],
                "expiresAt": enroll_response["expiresAt"],
                "wsUrl": enroll_response["wsUrl"],
                "certSerial": cert_serial_hex,
            }
        )

        # Set enrolledAt only on first enrollment
        if "enrolledAt" not in state:
            state["enrolledAt"] = datetime.now(timezone.utc).isoformat()

        # Track last renewal time
        if "enrolledAt" in existing_state:
            state["lastRenewedAt"] = datetime.now(timezone.utc).isoformat()

        # Write state file atomically with fsync
        state_json = json.dumps(state, indent=2)
        with open(self.state_file, "w", encoding="utf-8") as f:
            f.write(state_json)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(self.state_file, 0o600)

        logger.debug("Successfully persisted VMGW enrollment data to state.json")

        self._cert_expires_at = self._parse_iso_datetime(enroll_response["expiresAt"])

    # Connection -----------------------------------------------------------

    async def _connect_with_state(self, state: Dict[str, Any]) -> None:
        """Establish mTLS WebSocket connection using persisted state."""
        # Create temporary PEM files from state for SSL context
        # These files are only needed during connection establishment
        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem", prefix="vmgw_cert_")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="vmgw_key_")
        ca_fd, ca_path = tempfile.mkstemp(suffix=".pem", prefix="vmgw_ca_")

        try:
            # Write PEM data to temporary files
            os.write(cert_fd, state["deviceCertPem"].encode("utf-8"))
            os.close(cert_fd)
            os.chmod(cert_path, 0o600)

            os.write(key_fd, state["deviceKeyPem"].encode("utf-8"))
            os.close(key_fd)
            os.chmod(key_path, 0o600)

            os.write(ca_fd, state["caBundle"].encode("utf-8"))
            os.close(ca_fd)
            os.chmod(ca_path, 0o600)

            logger.debug("Created temporary PEM files from state.json")

            # Create SSL context with temporary files
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.load_cert_chain(cert_path, key_path)
            ssl_context.load_verify_locations(ca_path)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            ws_url = state["wsUrl"]
            self._ws = await websockets.connect(
                ws_url,
                ssl=ssl_context,
                max_size=10 * 1024 * 1024,
                ping_interval=30,
                ping_timeout=30,
            )

            self._expected_nonce = await self._send_hello()
            ready = await asyncio.wait_for(self._ws.recv(), timeout=10)
            ready_data = json.loads(ready)
            logger.debug(f"VMGW received | type={ready_data.get('type', 'unknown')}")

            if ready_data.get("type") != "READY_V1":
                raise RuntimeError("unexpected READY response type")

            data = ready_data.get("data", {})
            if not data.get("accepted", False):
                raise RuntimeError(f"READY rejected: {data.get('error')}")
            nonce_echo = data.get("nonceEcho")
            if self._expected_nonce and nonce_echo != self._expected_nonce:
                raise RuntimeError("READY nonce echo mismatch")

            self._session_id = data.get("sessionId")
            self._heartbeat_interval = max(
                HEARTBEAT_FALLBACK_SECONDS,
                data.get("heartbeatInterval", 30000) / 1000.0,
            )
            self._connected_at = time.time()

            logger.success(
                f"✅ VM gateway session ready | session={self._session_id} heartbeat={self._heartbeat_interval}s"
            )

            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            self._message_task = asyncio.create_task(self._message_loop())

        finally:
            # Clean up temporary PEM files
            for temp_path in [cert_path, key_path, ca_path]:
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except Exception as e:
                    logger.debug(f"Failed to remove temp file {temp_path}: {e}")

    async def _send_hello(self) -> str:
        """Send HELLO_V1 message after mTLS handshake."""
        nonce = os.urandom(16)
        nonce_b64 = base64.b64encode(nonce).decode("utf-8")
        hello = {
            "type": "HELLO_V1",
            "data": {
                "workerId": self.worker_id,
                "workerVersion": self.worker_version,
                "capabilities": self.capabilities,
                "startTime": int(time.time()),
                "nonce": nonce_b64,
            },
        }
        await self._ws.send(json.dumps(hello))
        logger.debug(f"VMGW sent | type={hello.get('type', 'unknown')}")
        return nonce_b64

    async def _teardown_connection(self) -> None:
        """Cancel background tasks and close websocket."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
        if self._message_task:
            self._message_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._message_task
        await self._close_ws()
        self._heartbeat_task = None
        self._message_task = None
        self._session_id = None
        self._expected_nonce = None

    # Message handling -----------------------------------------------------

    async def _message_loop(self) -> None:
        """Continuously receive and dispatch WebSocket messages.

        Messages are dispatched asynchronously to avoid blocking reception,
        which is critical for long-running operations like libvirt commands.
        """
        try:
            while not self._stop_event.is_set():
                if not self._ws or self._ws_is_closed():
                    break

                try:
                    message = await self._ws.recv()
                    # Dispatch asynchronously to avoid blocking message reception
                    asyncio.create_task(self._dispatch_message(message))
                except Exception as e:
                    logger.error(f"❌ Error receiving VMGW message: {e}")
                    break

        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"❌ VMGW message loop error: {e}", exc_info=True)

    async def _dispatch_message(self, message: str) -> None:
        """Dispatch a single message asynchronously.

        This runs independently of the receive loop, allowing slow operations
        (like libvirt commands) to not block incoming message reception.
        """
        try:
            msg_data = json.loads(message)
            msg_type = msg_data.get("type", "unknown")

            logger.debug(f"VMGW received | type={msg_type}")

            # Dispatch message by type
            if msg_type == "ANNOUNCEMENT_V1":
                await self._handle_announcement(msg_data)
            elif msg_type == "CERT_RENEW_RESPONSE_V1":
                self._handle_renew_response(msg_data)
            elif msg_type == "STATS_REQUEST_V1":
                await self._handle_stats_request(msg_data)
            elif msg_type == "VM_OPERATION_V1":
                await self._handle_vm_operation(msg_data)
            else:
                logger.debug(f"Unhandled VMGW message type: {msg_type}")

        except json.JSONDecodeError as e:
            logger.warning(f"⚠️ Failed to parse VMGW message: {e}")
        except Exception as e:
            logger.error(f"❌ Error dispatching VMGW message: {e}", exc_info=True)

    async def _handle_announcement(self, msg_data: Dict[str, Any]) -> None:
        """Handle ANNOUNCEMENT_V1 messages.

        This is async to support future extensions (e.g., saving to DB).
        Currently it just logs the announcement.
        """
        announcement_data = msg_data.get("data", {})
        message = announcement_data.get("message", "")
        if message:
            logger.info(f"📢 VMGW Announcement: {message}")
        else:
            logger.debug(
                f"VMGW Announcement with no message field: {announcement_data}"
            )

    def _handle_renew_response(self, msg_data: Dict[str, Any]) -> None:
        """Handle CERT_RENEW_RESPONSE_V1 messages."""
        if self._pending_renew_response and not self._pending_renew_response.done():
            self._pending_renew_response.set_result(msg_data)
        else:
            logger.warning("⚠️ Received CERT_RENEW_RESPONSE_V1 but no pending request")

    async def _handle_stats_request(self, msg_data: Dict[str, Any]) -> None:
        """Handle STATS_REQUEST_V1 messages by sending STATS_RESPONSE_V1."""
        request_data = msg_data.get("data", {})
        message_id = request_data.get("messageId")

        if not message_id:
            logger.warning("⚠️ Received STATS_REQUEST_V1 without messageId")
            return

        logger.debug(f"VMGW stats request | message_id={message_id}")

        uptime = int((time.time() - self._connected_at) * 1000)
        response_payload = {
            "type": "STATS_RESPONSE_V1",
            "data": {
                "messageId": message_id,
                "respondedAt": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "uptime": uptime,
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "active_vms": 0,
                },
            },
        }

        if self._ws and not self._ws_is_closed():
            try:
                await self._ws.send(json.dumps(response_payload))
                logger.debug(
                    f"VMGW sent | type=STATS_RESPONSE_V1 message_id={message_id}"
                )
            except Exception as e:
                logger.error(f"❌ Failed to send STATS_RESPONSE_V1: {e}")

    async def _handle_vm_operation(self, msg_data: Dict[str, Any]) -> None:
        await handle_vm_operation(self.config, msg_data, self._send_vm_operation_response)

    async def _send_vm_operation_response(self, response_type: str, success: bool, 
                                    error_message: Optional[str] = None, 
                                    result_data: Optional[Dict] = None) -> None:
        """Send VM operation response back to VMGW."""
        if not self._ws or self._ws_is_closed():
            logger.warning("⚠️ Cannot send VM operation response: WebSocket not connected")
            return
        
        response_payload = {
            "type": response_type,
            "data": {
                "success": success
            }
        }
        
        if result_data:
            response_payload["data"]["result"] = result_data.get("result", {})
        
        if not success:
            error_message = result_data.get("error_message", "Unknown error")
            response_payload["data"]["error"] = error_message
        else:
            response_payload["data"]["execution_time"] = result_data.get("execution_time")

        try:
            await self._ws.send(json.dumps(response_payload))
            logger.debug(f"VMGW sent | type=VM_OPERATION_RESPONSE_V1 response_type={response_type} success={success}")
        except Exception as e:
            logger.error(f"❌ Failed to send VM operation response: {e}")

    # Heartbeat ------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat sender."""
        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(self._heartbeat_interval)
                await self._send_heartbeat()
                # Check if certificate needs renewal while connected
                await self._check_online_renewal()
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"❌ VM gateway heartbeat error: {e}", exc_info=True)

    async def _send_heartbeat(self) -> None:
        """Send heartbeat payload with coarse metrics."""
        uptime = int(time.time() - self._connected_at)
        payload = {
            "type": "HEARTBEAT_V1",
            "data": {
                "uptime": uptime * 1000,
                "metrics": {
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "active_vms": 0,
                },
            },
        }
        if self._ws and not self._ws_is_closed():
            await self._ws.send(json.dumps(payload))
            logger.debug(f"VMGW sent | type={payload.get('type', 'unknown')}")

    # Online Renewal -------------------------------------------------------

    async def _check_online_renewal(self) -> None:
        """Check if certificate needs online renewal (via WebSocket)."""
        if not self._cert_expires_at:
            return

        # Prevent concurrent renewal attempts
        if hasattr(self, "_renewal_in_progress") and self._renewal_in_progress:
            return

        threshold = timedelta(days=CERT_RENEW_THRESHOLD_DAYS)
        time_until_expiry = self._cert_expires_at - datetime.now(timezone.utc)

        if time_until_expiry <= threshold and time_until_expiry > timedelta(0):
            logger.info(
                f"Certificate in renewal window, attempting online renewal | expires_in={time_until_expiry}"
            )
            self._renewal_in_progress = True
            try:
                await self._renew_certificate_online()
            except Exception as e:
                logger.error(
                    f"❌ Online certificate renewal failed: {e}", exc_info=True
                )
                # If certificate will expire soon and online renewal failed,
                # clean up state to force re-enrollment on next connection
                if time_until_expiry < timedelta(days=7):
                    logger.warning(
                        "⚠️ Certificate expires soon and online renewal failed, cleaning up state"
                    )
                    await asyncio.to_thread(self._cleanup_state)
                    # Force reconnect to trigger re-enrollment
                    self._force_reconnect = True
                    await self._close_ws()
            finally:
                self._renewal_in_progress = False

    async def _renew_certificate_online(self) -> None:
        """Renew certificate via WebSocket CERT_RENEW_REQUEST_V1."""
        if not self._ws or self._ws_is_closed():
            logger.warning("Cannot renew certificate: WebSocket not connected")
            return

        # Load current state to get current serial and private key
        state = await asyncio.to_thread(self._load_state)
        if not state:
            logger.warning("Cannot renew certificate: no state found")
            return

        current_serial_hex = state.get("certSerial")
        existing_key_pem = state.get("deviceKeyPem")

        if not current_serial_hex or not existing_key_pem:
            logger.warning("Cannot renew certificate: missing serial or key")
            return

        # Generate new private key for renewal (per e2e test pattern)
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        csr_pem = self._generate_csr(private_key)

        # Send CERT_RENEW_REQUEST_V1
        renew_request = {
            "type": "CERT_RENEW_REQUEST_V1",
            "data": {
                "workerId": self.worker_id,
                "currentCertSerial": current_serial_hex,
                "csrPem": csr_pem,
            },
        }

        # Create future for response
        self._pending_renew_response = asyncio.Future()

        await self._ws.send(json.dumps(renew_request))
        logger.debug("VMGW sent | type=CERT_RENEW_REQUEST_V1")

        # Wait for response (handled by _message_loop)
        try:
            response_data = await asyncio.wait_for(
                self._pending_renew_response, timeout=10
            )
            data = response_data.get("data", {})
            if not data.get("success"):
                error_msg = data.get("error", "unknown error")
                raise RuntimeError(f"Certificate renewal failed: {error_msg}")

            new_cert_pem = data.get("deviceCertPem")
            expires_at_str = data.get("expiresAt")

            if not new_cert_pem or not expires_at_str:
                raise RuntimeError("Renewal response missing required fields")

            # Parse new certificate to extract serial
            cert = x509.load_pem_x509_certificate(
                new_cert_pem.encode("utf-8"), default_backend()
            )
            new_serial_hex = cert.serial_number.to_bytes(
                (cert.serial_number.bit_length() + 7) // 8, "big"
            ).hex()

            # Persist renewed enrollment
            renew_response = {
                "deviceCertPem": new_cert_pem,
                "caBundle": state.get("caBundle"),  # CA bundle unchanged
                "expiresAt": expires_at_str,
                "wsUrl": state.get("wsUrl"),  # WS URL unchanged
                "certSerial": new_serial_hex,
            }

            await asyncio.to_thread(
                self._persist_enrollment,
                renew_response,
                private_key,
            )

            logger.success(
                f"✅ Certificate renewed online | old_serial={current_serial_hex[:8]}... new_serial={new_serial_hex[:8]}..."
            )

            # Note: No reconnection needed - server updates session internally
            # But we may want to force reconnect to use new cert for mTLS

        except asyncio.TimeoutError:
            raise RuntimeError("Certificate renewal request timed out")
        finally:
            self._pending_renew_response = None

    # Helpers --------------------------------------------------------------

    def _ws_is_closed(self, ws: Optional[Any] = None) -> bool:
        """Return True if the websocket connection is closed."""
        ws = ws or self._ws
        if ws is None:
            return True

        closed_attr = getattr(ws, "closed", None)
        if isinstance(closed_attr, bool):
            return closed_attr
        if isinstance(closed_attr, asyncio.Future):
            return closed_attr.done()
        if closed_attr is not None and not callable(closed_attr):
            try:
                return bool(closed_attr)
            except Exception:
                pass

        state = getattr(ws, "state", None)
        if state is None:
            return False

        if WebSocketState is not None:
            return state in (WebSocketState.CLOSING, WebSocketState.CLOSED)

        return str(state).upper() in {"CLOSING", "CLOSED"}

    async def _close_ws(self) -> None:
        """Close and clear the websocket connection safely."""
        ws = self._ws
        if ws is None:
            return

        if not self._ws_is_closed(ws):
            try:
                await ws.close()
                wait_closed = getattr(ws, "wait_closed", None)
                if callable(wait_closed):
                    await wait_closed()
            except Exception:
                pass

        self._ws = None
