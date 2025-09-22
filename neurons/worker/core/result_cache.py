"""
Worker Result Cache Module
Manages a per-validator, per-UUID cache for challenge computation results.
"""

import time
from typing import Any, Dict, List, Optional

from loguru import logger

from neurons.shared.utils.merkle_tree import MerkleTree
from neurons.worker.clients.gpu_client import GPUServerClient


class ResultCache:
    """
    Manages a cache for challenge results, optimized for two-phase verification.
    The cache stores MerkleTree objects for on-demand, unified proof generation.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initializes the result cache.

        Args:
            config: Configuration for GPU client.
        """
        # Structure: {validator_hotkey -> {uuid -> MerkleTree}}
        self._cache: Dict[str, Dict[str, MerkleTree]] = {}
        self._gpu_client = GPUServerClient(config) if config else None
        logger.debug("ResultCache initialized")

    def add_cacheable_data(self, validator_hotkey: str, cacheable_data: Dict[str, Any]):
        """
        Caches Merkle trees from cacheable data provided by challenge plugins.

        Args:
            validator_hotkey: The hotkey of the validator that issued the challenge.
            cacheable_data: A dictionary from the plugin, e.g., {"uuid": {"row_hashes": [...]}}.
        """
        if not validator_hotkey or not isinstance(cacheable_data, dict):
            logger.error("❌ Cache add invalid args")
            return

        if validator_hotkey in self._cache:
            logger.debug(f"Cache overwrite | validator={validator_hotkey}")

        self._cache[validator_hotkey] = {}

        for uuid, data in cacheable_data.items():
            row_hashes = data.get("row_hashes")
            if not row_hashes or not isinstance(row_hashes, list):
                logger.warning(f"⚠️ Missing row_hashes | uuid={uuid}")
                continue

            try:
                self._cache[validator_hotkey][uuid] = MerkleTree(row_hashes)
                logger.debug(
                    f"🌳 Merkle cached | validator={validator_hotkey} uuid={uuid}"
                )
            except Exception as e:
                logger.error(
                    f"❌ Merkle cache error | validator={validator_hotkey} uuid={uuid} error={e}"
                )

    def generate_proof(
        self, validator_hotkey: str, request_item: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Generates a proof for a single request item, following the unified API.

        Args:
            validator_hotkey: The hotkey of the validator requesting the proof.
            request_item: A dict containing uuid, and optional rows and coordinates.

        Returns:
            A dictionary containing the proof data for the requested item.
        """
        uuid = request_item.get("uuid")
        requested_rows = request_item.get("rows", [])
        requested_coords = request_item.get("coordinates", [])

        validator_cache = self._cache.get(validator_hotkey)
        if not validator_cache or uuid not in validator_cache:
            logger.warning(
                f"⚠️ Missing Merkle cache | validator={validator_hotkey} uuid={uuid}"
            )
            return None

        merkle_tree = validator_cache[uuid]
        response = {
            "uuid": uuid,
            "row_hashes": [],
            "merkle_proofs": [],
            "coordinate_values": [],
        }

        try:
            # Generate Merkle proofs for requested rows
            if requested_rows:
                proofs = []
                for idx in requested_rows:
                    proof = merkle_tree.generate_proof(idx)
                    proofs.append(
                        {
                            "leaf_index": proof.leaf_index,
                            "leaf_hash": proof.leaf_hash,
                            "proof_hashes": proof.proof_hashes,
                            "proof_directions": proof.proof_directions,
                        }
                    )
                response["merkle_proofs"] = proofs
                response["row_hashes"] = [
                    merkle_tree.leaf_hashes[idx] for idx in requested_rows
                ]

            # GPU challenges require specific coordinate values
            if requested_coords:
                if uuid == "-1" or not self._gpu_client:
                    logger.warning(
                        f"Coordinate values requested for non-GPU UUID '{uuid}' or GPU client not available"
                    )
                else:
                    coord_response = self._gpu_client.get_result_values(
                        uuid, requested_coords, requested_rows
                    )
                    if coord_response and coord_response.get("success"):
                        response["coordinate_values"] = coord_response.get("values", [])

                        # Clear GPU result cache after retrieving Phase 2 data
                        clear_response = self._gpu_client.clear_result_cache(uuid)
                        if clear_response and clear_response.get("success"):
                            logger.debug(f"🧹 GPU result cache cleared | uuid={uuid}")
                        else:
                            logger.warning(
                                f"⚠️ GPU result cache clear failed | uuid={uuid} resp={clear_response}"
                            )
                    else:
                        logger.error(f"❌ GPU values fetch failed | uuid={uuid}")

            return response
        except Exception as e:
            logger.error(
                f"❌ Proof generation error | validator={validator_hotkey} uuid={uuid} error={e}"
            )
            return None

    def clear_cache_for_validator(self, validator_hotkey: str):
        """
        Clears the entire cache for a specific validator after the proof request is handled.
        """
        if validator_hotkey in self._cache:
            del self._cache[validator_hotkey]
            logger.debug(f"🧹 Cache cleared | validator={validator_hotkey}")
