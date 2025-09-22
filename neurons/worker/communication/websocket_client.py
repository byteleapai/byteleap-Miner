"""
WebSocket Client Module
Handle WebSocket communication with miner
"""

import asyncio
import json
import time
from typing import Any, Callable, Dict, Optional

import websockets
from loguru import logger
from websockets.exceptions import ConnectionClosed, WebSocketException


class WebSocketClient:
    """WebSocket client for miner communication"""

    def __init__(self, config):
        """Initialize WebSocket client"""
        self.config = config

        # Connection configuration
        # Fail-fast with type validation
        from neurons.shared.config.config_manager import ConfigManager

        if not isinstance(config, ConfigManager):
            raise ValueError("WebSocketClient requires ConfigManager-compatible config")

        self.miner_url = config.get_non_empty_string("miner_url")
        self.ping_interval = config.get_positive_number("ping_interval", int)
        self.ping_timeout = config.get_positive_number("ping_timeout", int)

        # Connection state
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.is_connected_flag = False

        # Message handling (single waiter per type)
        self.message_handlers: Dict[str, Callable] = {}
        self.pending_responses: Dict[str, asyncio.Event] = {}
        self.received_messages: Dict[str, Dict[str, Any]] = {}

        # Background tasks
        self._message_task: Optional[asyncio.Task] = None

        logger.info(f"🌐 WebSocket client initialized | url={self.miner_url}")

    async def connect(self):
        """Connect to miner WebSocket server"""
        try:
            logger.info(f"🔌 Connecting | url={self.miner_url}")

            # Establish WebSocket connection
            self.websocket = await websockets.connect(
                self.miner_url,
                ping_interval=self.ping_interval,
                ping_timeout=self.ping_timeout,
            )

            self.is_connected_flag = True

            logger.info(f"✅ Connected | url={self.miner_url}")

            # Start background tasks
            self._message_task = asyncio.create_task(self._message_handler())

        except Exception as e:
            logger.error(f"Connection attempt failed: {e}")
            self.is_connected_flag = False
            raise

    async def disconnect(self):
        """Disconnect from miner"""
        self.is_connected_flag = False

        # Cancel background tasks
        if self._message_task:
            self._message_task.cancel()
            try:
                await self._message_task
            except asyncio.CancelledError:
                pass

        if self.websocket:
            await self.websocket.close()
            self.websocket = None

        logger.info("⏹️ Disconnected")

    async def send_message(self, message: Dict[str, Any]):
        """Send message to miner"""
        if not self.is_connected() or not self.websocket:
            raise Exception("Not connected to miner")

        try:
            # Send message
            message_json = json.dumps(message)
            await self.websocket.send(message_json)

            logger.debug(f"📤 Sent | type={message.get('type', 'unknown')}")

        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.is_connected_flag = False
            raise

    async def wait_for_message(
        self, message_type: str, timeout: float = 30
    ) -> Optional[Dict[str, Any]]:
        """Wait for a specific message type (single waiter per type)"""
        # Replace any previous waiter for this type to avoid leaks
        event = asyncio.Event()
        self.pending_responses[message_type] = event

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self.received_messages.get(message_type)
        except asyncio.TimeoutError:
            logger.warning(f"⏳ Wait timeout | type={message_type}")
            return None
        finally:
            self.pending_responses.pop(message_type, None)
            self.received_messages.pop(message_type, None)

    def set_message_handler(self, message_type: str, handler: Callable):
        """Set handler for specific message type"""
        self.message_handlers[message_type] = handler
        logger.info(f"🧩 Handler set | type={message_type}")

    async def process_messages(self):
        """Process any pending messages (non-blocking)"""
        # Message processing happens in the background _message_handler task
        pass

    async def _message_handler(self):
        """Handle incoming messages in background"""
        try:
            async for message in self.websocket:
                try:
                    # Parse message
                    data = json.loads(message)
                    message_type = data.get("type")

                    if not message_type:
                        logger.warning("⚠️ Message missing type")
                        continue

                    logger.debug(f"📥 Received | type={message_type}")

                    # Fulfill waiter for this exact message type
                    event = self.pending_responses.get(message_type)
                    if event:
                        self.received_messages[message_type] = data
                        event.set()

                    # Call registered handler
                    if message_type in self.message_handlers:
                        try:
                            await self.message_handlers[message_type](data)
                        except Exception as e:
                            logger.error(
                                f"❌ Handler error | type={message_type} | error={e}",
                                exc_info=True,
                            )

                except json.JSONDecodeError:
                    logger.error("❌ Invalid JSON received")
                except (KeyError, ValueError, AttributeError) as e:
                    logger.error(f"❌ Message validation error | error={e}")
                except Exception as e:
                    logger.error(
                        f"❌ Message processing error | error={e}", exc_info=True
                    )

        except ConnectionClosed as e:
            logger.warning(f"🔌 Connection closed | code={e.code} reason={e.reason}")
            self.is_connected_flag = False
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"🌐 Network error | error={e}")
            self.is_connected_flag = False
        except Exception as e:
            logger.error(f"❌ Message loop error | error={e}", exc_info=True)
            self.is_connected_flag = False

    def is_connected(self) -> bool:
        """Check if connected to miner"""
        return self.is_connected_flag and self.websocket is not None

    async def ping(self) -> bool:
        """Send ping to check connection"""
        if not self.is_connected():
            return False

        try:
            pong_waiter = await self.websocket.ping()
            await asyncio.wait_for(pong_waiter, timeout=10)
            return True
        except Exception as e:
            logger.warning(f"🏓 Ping failed | error={e}")
            self.is_connected_flag = False
            return False

    def get_connection_info(self) -> Dict[str, Any]:
        """Get connection information"""
        return {
            "miner_url": self.miner_url,
            "is_connected": self.is_connected(),
            "registered_handlers": list(self.message_handlers.keys()),
        }
