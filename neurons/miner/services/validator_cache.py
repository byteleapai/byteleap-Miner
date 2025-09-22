"""
ValidatorCache for miner validator selection and connectivity management

Simple wrapper that caches filtered validators and manages their connectivity status.
"""

import asyncio
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import bittensor as bt

if TYPE_CHECKING:
    from neurons.shared.config.config_manager import ConfigManager


class ValidatorCache:
    """
    Simple validator cache for miners

    Caches filtered validators and manages connectivity probing.
    Does not manage metagraph - relies on framework's metagraph.sync().
    """

    def __init__(
        self,
        subtensor: bt.subtensor,
        netuid: int,
        config: "ConfigManager",
        metagraph: bt.metagraph,
    ):
        """
        Initialize validator cache

        Args:
            subtensor: Bittensor subtensor instance
            netuid: Network UID
            config: Configuration manager instance
            metagraph: Shared metagraph instance to reuse
        """
        self.subtensor = subtensor
        self.netuid = netuid

        # Validate configuration
        self.sync_interval = config.get_positive_number("metagraph.sync_interval", int)
        self.validator_whitelist = config.get("metagraph.validator_whitelist")
        self.min_stake_tao = config.get_positive_number(
            "metagraph.validator_min_stake_tao", int
        )

        # Validate blacklist configuration
        self.blacklist_threshold = config.get_positive_number(
            "metagraph.blacklist.threshold", int
        )
        self.blacklist_ttl_seconds = config.get_positive_number(
            "metagraph.blacklist.ttl_seconds", int
        )

        # Cached validator data
        self._cached_validators: List[Tuple[int, bt.AxonInfo, str]] = []

        # Validate required metagraph parameter
        if metagraph is None:
            raise ValueError("metagraph parameter is required and cannot be None")

        # Use provided metagraph instance
        self._metagraph = metagraph
        bt.logging.debug("ValidatorCache initialized with shared metagraph instance")
        self._cache_timestamp: float = 0

        # Blacklist management
        self._blacklisted_validators: Dict[str, float] = {}
        self._validator_failure_count: Dict[str, int] = {}
        self._validator_success_count: Dict[str, int] = {}

        # Background tasks
        self._sync_task: Optional[asyncio.Task] = None
        self._is_running = False

        # Reusable metagraph instance
        self._metagraph: bt.metagraph

    async def start(self) -> None:
        """Start background sync task"""
        if self._is_running:
            return

        self._is_running = True

        # Perform immediate initial sync to have validators available on startup
        bt.logging.debug("Performing initial validator cache sync")
        await self._refresh_validator_cache()

        self._sync_task = asyncio.create_task(self._background_sync_loop())

    async def stop(self) -> None:
        """Stop background tasks"""
        self._is_running = False

        if self._sync_task:
            self._sync_task.cancel()
            try:
                await asyncio.wait_for(self._sync_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Note: We don't cleanup the shared metagraph instance as it's owned by the caller

    def get_validators(self) -> List[Tuple[int, bt.AxonInfo, str]]:
        """
        Get cached filtered validators

        Returns:
            List of (uid, axon, hotkey) tuples ready for communication
        """
        return self._cached_validators.copy()

    async def _background_sync_loop(self) -> None:
        """Background task for periodic validator list refresh"""
        while self._is_running:
            try:
                # Respect sync interval timing
                await asyncio.sleep(self.sync_interval)
                await self._refresh_validator_cache()
                self._cleanup_expired_blacklist_entries()
            except asyncio.CancelledError:
                break
            except Exception as e:
                bt.logging.error(f"❌ Error in validator cache sync: {e}")
                await asyncio.sleep(10)

    async def _refresh_validator_cache(self) -> None:
        """Refresh cached validator list from current metagraph"""
        try:
            # Access shared metagraph instance
            bt.logging.debug(f"Syncing shared metagraph instance: {self._metagraph}")

            if self._metagraph is None:
                raise ValueError(
                    "Internal error: metagraph became None after initialization"
                )

            # Only sync the existing metagraph instance
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: self._metagraph.sync(subtensor=self.subtensor)
            )

            # Filter validators
            filtered_validators = self._filter_validators(self._metagraph)

            # Update cache
            self._cached_validators = filtered_validators
            self._cache_timestamp = time.time()

            bt.logging.info(
                f"✅ Validator cache updated: {len(filtered_validators)} validators"
            )

        except Exception as e:
            bt.logging.error(f"❌ Failed to refresh validator cache: {e}")

    def _filter_validators(
        self, metagraph: bt.metagraph
    ) -> List[Tuple[int, bt.AxonInfo, str]]:
        """Filter validators from metagraph with logging"""
        valid_validators = []
        whitelisted_count = 0
        permit_qualified_count = 0
        permit_rejected_count = 0
        blacklisted_count = 0
        invalid_address_count = 0

        for uid in range(len(metagraph.hotkeys)):
            hotkey = metagraph.hotkeys[uid]

            # Check if whitelisted - bypass all other checks
            if hotkey in self.validator_whitelist:
                override_axon = self.validator_whitelist[hotkey]
                if override_axon:
                    # Parse IP:port
                    try:
                        ip, port = override_axon.split(":")

                        # Filter out invalid addresses
                        if ip == "0.0.0.0":
                            bt.logging.debug(
                                f"Rejected whitelisted validator {uid}: {hotkey} (invalid address: {ip}:{port})"
                            )
                            invalid_address_count += 1
                            continue

                        # Check blacklist
                        cache_key = f"{ip}:{port}"
                        if self._is_blacklisted(cache_key):
                            bt.logging.debug(
                                f"Rejected whitelisted validator {uid}: {hotkey} (blacklisted: {ip}:{port})"
                            )
                            blacklisted_count += 1
                            continue

                        custom_axon = bt.AxonInfo(
                            version=1,
                            ip=ip,
                            port=int(port),
                            ip_type=4,
                            hotkey=hotkey,
                            coldkey="",
                            protocol=4,
                        )
                        valid_validators.append((uid, custom_axon, hotkey))
                        whitelisted_count += 1
                        continue

                    except ValueError:
                        bt.logging.debug(
                            f"Rejected whitelisted validator {uid}: {hotkey} (invalid override format)"
                        )
                        invalid_address_count += 1
                        continue
                else:
                    # Use default axon
                    axon = metagraph.axons[uid]

                    # Filter out invalid addresses
                    if axon.ip == "0.0.0.0":
                        bt.logging.debug(
                            f"Rejected whitelisted validator {uid}: {hotkey} (invalid address: {axon.ip}:{axon.port})"
                        )
                        invalid_address_count += 1
                        continue

                    # Check blacklist
                    cache_key = f"{axon.ip}:{axon.port}"
                    if self._is_blacklisted(cache_key):
                        bt.logging.debug(
                            f"Rejected whitelisted validator {uid}: {hotkey} (blacklisted: {axon.ip}:{axon.port})"
                        )
                        blacklisted_count += 1
                        continue

                    valid_validators.append((uid, axon, hotkey))
                    whitelisted_count += 1
                    continue

            # Check if validator has permit
            if not metagraph.validator_permit[uid]:
                continue

            # For validators with permits, verify minimum stake requirements
            stake = metagraph.total_stake[uid]
            if stake < self.min_stake_tao:
                bt.logging.debug(
                    f"Rejected validator {uid}: {hotkey} (stake: {stake} TAO < {self.min_stake_tao} TAO)"
                )
                permit_rejected_count += 1
                continue

            # Validator has permit and sufficient stake
            axon = metagraph.axons[uid]

            # Filter out invalid addresses
            if axon.ip == "0.0.0.0":
                bt.logging.debug(
                    f"Rejected validator {uid}: {hotkey} (invalid address: {axon.ip}:{axon.port})"
                )
                invalid_address_count += 1
                continue

            # Check blacklist
            cache_key = f"{axon.ip}:{axon.port}"
            if self._is_blacklisted(cache_key):
                bt.logging.debug(
                    f"Rejected validator {uid}: {hotkey} (blacklisted: {axon.ip}:{axon.port})"
                )
                blacklisted_count += 1
                continue

            valid_validators.append((uid, axon, hotkey))
            permit_qualified_count += 1

        bt.logging.info(
            f"📈 Validator selection: {len(valid_validators)} total "
            f"({whitelisted_count} whitelisted, {permit_qualified_count} permit-qualified, "
            f"{permit_rejected_count} permit-stake-rejected, "
            f"{blacklisted_count} blacklisted, {invalid_address_count} invalid-address) "
            f"[blacklist: {len(self._blacklisted_validators)} entries]"
        )

        return valid_validators

    def _is_blacklisted(self, cache_key: str) -> bool:
        """
        Check if validator is blacklisted

        Args:
            cache_key: Validator address in format "ip:port"

        Returns:
            True if should reject, False if should allow
        """
        if cache_key not in self._blacklisted_validators:
            return False

        # Check if entry has expired
        blacklist_time = self._blacklisted_validators[cache_key]
        if time.time() - blacklist_time > self.blacklist_ttl_seconds:
            # Entry expired, remove it
            del self._blacklisted_validators[cache_key]
            self._validator_failure_count.pop(cache_key, None)
            self._validator_success_count.pop(cache_key, None)
            bt.logging.debug(f"Blacklist entry expired | key={cache_key}")
            return False

        return True

    def record_communication_failure(self, ip: str, port: int) -> None:
        """
        Record communication failure for passive blacklisting
        Should be called from heartbeat/communication logic when validator fails to respond

        Args:
            ip: Validator IP address
            port: Validator port
        """
        cache_key = f"{ip}:{port}"

        self._validator_failure_count[cache_key] = (
            self._validator_failure_count.get(cache_key, 0) + 1
        )

        # Debug logging to track failure accumulation
        bt.logging.debug(
            f"📉 Validator {cache_key} failure count: {self._validator_failure_count[cache_key]}/{self.blacklist_threshold}"
        )

        # Add to blacklist on threshold reached
        if (
            cache_key not in self._blacklisted_validators
            and self._validator_failure_count[cache_key] >= self.blacklist_threshold
        ):
            self._blacklisted_validators[cache_key] = time.time()
            bt.logging.warning(
                f"⚫ Validator {cache_key} blacklisted after {self.blacklist_threshold} failures"
            )

    def record_communication_success(self, ip: str, port: int) -> None:
        """
        Record communication success - reset failure count and potentially remove from blacklist

        Args:
            ip: Validator IP address
            port: Validator port
        """
        cache_key = f"{ip}:{port}"

        # Reset failure count
        self._validator_failure_count[cache_key] = 0

        # If was blacklisted, remove it on successful communication
        if cache_key in self._blacklisted_validators:
            del self._blacklisted_validators[cache_key]
            self._validator_success_count.pop(cache_key, None)
            bt.logging.info(f"✅ Validator {cache_key} removed from blacklist")

    def _cleanup_expired_blacklist_entries(self) -> None:
        """Clean up expired blacklist entries based on TTL"""
        if not self._blacklisted_validators:
            return

        current_time = time.time()
        expired_keys = []

        for cache_key, timestamp in self._blacklisted_validators.items():
            if current_time - timestamp > self.blacklist_ttl_seconds:
                expired_keys.append(cache_key)

        # Remove expired entries
        for key in expired_keys:
            del self._blacklisted_validators[key]
            self._validator_failure_count.pop(key, None)
            self._validator_success_count.pop(key, None)

        if expired_keys:
            bt.logging.debug(
                f"🧹 Cleaned up {len(expired_keys)} expired blacklist entries"
            )

    def get_blacklist_status(self) -> Dict[str, Dict]:
        """Get current blacklist status for monitoring"""
        return {
            "blacklisted_validators": dict(self._blacklisted_validators),
            "failure_counts": dict(self._validator_failure_count),
            "success_counts": dict(self._validator_success_count),
            "cache_size": len(self._cached_validators),
        }
