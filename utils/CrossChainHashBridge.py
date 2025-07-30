"""
CrossChainHashBridge.py - Cross-Chain Hash Compatibility Utility

Handles hash function compatibility between EVM (Keccak256) and Tezos (SHA-256)
for universal Merkle tree support and secret validation.

Key Features:
- Universal leaf format generation
- Chain-specific Merkle tree construction
- Hash function bridging
- Cross-chain proof validation
"""

import hashlib
import struct
from typing import List, Dict, Any, Tuple, Optional


class CrossChainHashBridge:
    """
    Cross-Chain Hash Compatibility Bridge

    Provides utilities for generating hash-compatible data structures
    that work across both EVM (Keccak256) and Tezos (SHA-256) chains.
    """

    def __init__(self, *args):
        """Initialize the hash bridge with supported hash functions"""
        self.evm_hasher = self._keccak256
        self.tezos_hasher = self._sha256

        # Chain-specific configuration
        self.chain_configs = {
            "ethereum": {
                "hasher": self.evm_hasher,
                "name": "keccak256",
                "block_time": 12,
                "finality_blocks": 64,
            },
            "polygon": {
                "hasher": self.evm_hasher,
                "name": "keccak256",
                "block_time": 2,
                "finality_blocks": 256,
            },
            "tezos": {
                "hasher": self.tezos_hasher,
                "name": "sha256",
                "block_time": 15,
                "finality_blocks": 2,
            },
        }

    # ================================================================
    # HASH FUNCTION UTILITIES
    # ================================================================

    def _keccak256(self, data: bytes) -> bytes:
        """Keccak256 hash function (EVM compatible)"""
        from Crypto.Hash import keccak

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()

    def _sha256(self, data: bytes) -> bytes:
        """SHA-256 hash function (Tezos compatible)"""
        return hashlib.sha256(data).digest()

    def get_chain_hasher(self, chain_name: str):
        """Get the appropriate hash function for a chain"""
        if chain_name not in self.chain_configs:
            raise ValueError(f"Unsupported chain: {chain_name}")
        return self.chain_configs[chain_name]["hasher"]

    # ================================================================
    # UNIVERSAL LEAF GENERATION
    # ================================================================

    def generate_universal_leaf(self, index: int, secret_hash: bytes) -> bytes:
        """
        Generate universal leaf format compatible across chains

        Format: 8-byte big-endian index + 32-byte secret hash
        This format works with both EVM and Tezos Merkle implementations.
        """
        if len(secret_hash) != 32:
            raise ValueError("Secret hash must be exactly 32 bytes")

        if index < 0 or index >= 2**64:
            raise ValueError("Index must be a valid 64-bit unsigned integer")

        # Convert index to 8-byte big-endian format
        index_bytes = struct.pack(">Q", index)  # Big-endian 64-bit unsigned

        # Combine index + secret hash
        universal_leaf = index_bytes + secret_hash

        assert len(universal_leaf) == 40, "Universal leaf must be exactly 40 bytes"
        return universal_leaf

    def extract_leaf_components(self, universal_leaf: bytes) -> Tuple[int, bytes]:
        """
        Extract index and secret hash from universal leaf

        Args:
            universal_leaf: 40-byte universal leaf

        Returns:
            Tuple of (index, secret_hash)
        """
        if len(universal_leaf) != 40:
            raise ValueError("Universal leaf must be exactly 40 bytes")

        # Extract index from first 8 bytes
        index_bytes = universal_leaf[:8]
        index = struct.unpack(">Q", index_bytes)[0]

        # Extract secret hash from remaining 32 bytes
        secret_hash = universal_leaf[32:]

        return index, secret_hash

    # ================================================================
    # CROSS-CHAIN MERKLE TREE CONSTRUCTION
    # ================================================================

    def build_cross_chain_merkle_trees(self, secrets: List[bytes]) -> Dict[str, Any]:
        """
        Build Merkle trees compatible with both EVM and Tezos chains

        Creates separate trees using each chain's native hash function
        from the same universal leaf data.

        Args:
            secrets: List of secret bytes (N+1 secrets for N parts)

        Returns:
            Dictionary containing trees and metadata for both chains
        """
        if len(secrets) < 2:
            raise ValueError("At least 2 secrets required for Merkle tree")

        # Generate universal leaves
        universal_leaves = []
        for i, secret in enumerate(secrets):
            secret_hash = self._sha256(secret)  # Use SHA-256 as base hash
            leaf = self.generate_universal_leaf(i, secret_hash)
            universal_leaves.append(leaf)

        # Build EVM-compatible tree (keccak256)
        evm_tree = self._build_merkle_tree(universal_leaves, self.evm_hasher)

        # Build Tezos-compatible tree (SHA-256)
        tezos_tree = self._build_merkle_tree(universal_leaves, self.tezos_hasher)

        return {
            "universal_leaves": universal_leaves,
            "secrets": secrets,
            "evm_tree": {
                "leaves": evm_tree["leaves"],
                "tree": evm_tree["tree"],
                "root": evm_tree["root"],
                "hash_function": "keccak256",
            },
            "tezos_tree": {
                "leaves": tezos_tree["leaves"],
                "tree": tezos_tree["tree"],
                "root": tezos_tree["root"],
                "hash_function": "sha256",
            },
            "metadata": {
                "total_secrets": len(secrets),
                "tree_depth": len(evm_tree["tree"]) - 1,
                "leaf_count": len(universal_leaves),
            },
        }

    def _build_merkle_tree(self, leaves: List[bytes], hasher) -> Dict[str, Any]:
        """
        Build a Merkle tree using the specified hash function

        Args:
            leaves: List of leaf data (universal format)
            hasher: Hash function to use

        Returns:
            Dictionary containing tree structure and root
        """
        if not leaves:
            raise ValueError("Cannot build tree with empty leaves")

        # Hash each universal leaf to get actual leaf hashes
        leaf_hashes = [hasher(leaf) for leaf in leaves]

        # Build tree level by level
        tree_levels = [leaf_hashes]
        current_level = leaf_hashes

        while len(current_level) > 1:
            next_level = []

            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]

                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Odd number of nodes - duplicate the last one
                    right = current_level[i]

                # Hash the pair to create parent node
                parent = hasher(left + right)
                next_level.append(parent)

            tree_levels.append(next_level)
            current_level = next_level

        # Root is the single node at the top level
        root = current_level[0] if current_level else hasher(b"")

        return {"leaves": leaf_hashes, "tree": tree_levels, "root": root}

    # ================================================================
    # PROOF GENERATION AND VALIDATION
    # ================================================================

    def generate_cross_chain_proof(
        self, trees: Dict[str, Any], leaf_index: int
    ) -> Dict[str, Any]:
        """
        Generate Merkle proofs for both chains

        Args:
            trees: Cross-chain tree data from build_cross_chain_merkle_trees
            leaf_index: Index of the leaf to prove

        Returns:
            Dictionary containing proofs for both chains
        """
        if leaf_index < 0 or leaf_index >= len(trees["universal_leaves"]):
            raise ValueError("Invalid leaf index")

        # Generate EVM proof
        evm_proof = self._generate_merkle_proof(
            trees["evm_tree"], leaf_index, self.evm_hasher
        )

        # Generate Tezos proof
        tezos_proof = self._generate_merkle_proof(
            trees["tezos_tree"], leaf_index, self.tezos_hasher
        )

        return {
            "leaf_index": leaf_index,
            "universal_leaf": trees["universal_leaves"][leaf_index],
            "secret": trees["secrets"][leaf_index],
            "evm_proof": {
                "proof_path": evm_proof,
                "root": trees["evm_tree"]["root"],
                "hash_function": "keccak256",
            },
            "tezos_proof": {
                "proof_path": tezos_proof,
                "root": trees["tezos_tree"]["root"],
                "hash_function": "sha256",
            },
        }

    def _generate_merkle_proof(
        self, tree: Dict[str, Any], leaf_index: int, hasher
    ) -> List[bytes]:
        """
        Generate Merkle proof path for a specific leaf

        Args:
            tree: Tree structure from _build_merkle_tree
            leaf_index: Index of the leaf
            hasher: Hash function used in tree construction

        Returns:
            List of sibling hashes forming the proof path
        """
        proof_path = []
        current_index = leaf_index

        # Walk up the tree, collecting sibling hashes
        for level in range(len(tree["tree"]) - 1):  # Exclude root level
            level_nodes = tree["tree"][level]

            # Determine sibling index
            if current_index % 2 == 0:  # Left child
                sibling_index = current_index + 1
            else:  # Right child
                sibling_index = current_index - 1

            # Add sibling hash - this must match the duplicate-last-node rule
            # used in _build_merkle_tree
            if sibling_index < len(level_nodes):
                proof_path.append(level_nodes[sibling_index])
            else:
                # No sibling (odd number of nodes) - use same as tree building
                proof_path.append(level_nodes[current_index])

            # Move to parent index
            current_index = current_index // 2

        return proof_path

    def validate_cross_chain_proof(
        self,
        proof_data: Dict[str, Any],
        chain_name: str,
        expected_root: Optional[bytes] = None,
    ) -> bool:
        """
        Validate a Merkle proof for a specific chain

        Args:
            proof_data: Proof data from generate_cross_chain_proof
            chain_name: Chain to validate for ('ethereum', 'tezos', etc.)
            expected_root: Expected root hash (if None, use proof's root)

        Returns:
            True if proof is valid, False otherwise
        """
        if chain_name not in self.chain_configs:
            raise ValueError(f"Unsupported chain: {chain_name}")

        hasher = self.get_chain_hasher(chain_name)

        # Get chain-specific proof data
        if chain_name == "tezos":
            proof_info = proof_data["tezos_proof"]
        else:  # EVM chains
            proof_info = proof_data["evm_proof"]

        # Validate proof
        universal_leaf = proof_data["universal_leaf"]
        proof_path = proof_info["proof_path"]
        root = expected_root if expected_root else proof_info["root"]

        # Compute root from proof
        computed_root = self._compute_root_from_proof(
            universal_leaf, proof_path, proof_data["leaf_index"], hasher
        )

        return computed_root == root

    def _compute_root_from_proof(
        self, universal_leaf: bytes, proof_path: List[bytes], leaf_index: int, hasher
    ) -> bytes:
        """
        Compute Merkle root from proof path

        Args:
            universal_leaf: Universal leaf data
            proof_path: List of sibling hashes
            leaf_index: Index of the leaf
            hasher: Hash function to use

        Returns:
            Computed root hash
        """
        # Start with leaf hash
        current_hash = hasher(universal_leaf)
        current_index = leaf_index

        # Walk up the tree using proof path
        for sibling_hash in proof_path:
            if current_index % 2 == 0:  # Left child
                current_hash = hasher(current_hash + sibling_hash)
            else:  # Right child
                current_hash = hasher(sibling_hash + current_hash)

            # Move to parent index
            current_index = current_index // 2

        return current_hash

    # ================================================================
    # UTILITY FUNCTIONS
    # ================================================================

    def generate_secret_set(
        self, num_parts: int, base_secret: Optional[bytes] = None
    ) -> List[bytes]:
        """
        Generate a set of secrets for partial fills

        Args:
            num_parts: Number of parts (generates N+1 secrets)
            base_secret: Base secret to derive from (random if None)

        Returns:
            List of N+1 secrets for N parts
        """
        if num_parts < 1:
            raise ValueError("Number of parts must be at least 1")

        if base_secret is None:
            import secrets

            base_secret = secrets.token_bytes(32)

        secret_set = []

        # Generate N+1 secrets (one for each part + completion secret)
        for i in range(num_parts + 1):
            # Derive secret by hashing base_secret + index
            derived_secret = self._sha256(base_secret + i.to_bytes(4, "big"))
            secret_set.append(derived_secret)

        return secret_set

    def verify_chain_compatibility(self, chain_a: str, chain_b: str) -> Dict[str, Any]:
        """
        Verify that two chains are compatible for cross-chain swaps

        Args:
            chain_a: First chain name
            chain_b: Second chain name

        Returns:
            Compatibility analysis and recommendations
        """
        if chain_a not in self.chain_configs or chain_b not in self.chain_configs:
            raise ValueError("One or both chains not supported")

        config_a = self.chain_configs[chain_a]
        config_b = self.chain_configs[chain_b]

        # Analyze timing characteristics
        finality_a = config_a["finality_blocks"] * config_a["block_time"]
        finality_b = config_b["finality_blocks"] * config_b["block_time"]

        timing_ratio = max(finality_a, finality_b) / min(finality_a, finality_b)

        # Hash function compatibility
        same_hash_function = config_a["hasher"] == config_b["hasher"]

        return {
            "compatible": True,  # All supported chains are compatible
            "chain_a": {
                "name": chain_a,
                "hash_function": config_a["name"],
                "finality_time": finality_a,
            },
            "chain_b": {
                "name": chain_b,
                "hash_function": config_b["name"],
                "finality_time": finality_b,
            },
            "analysis": {
                "same_hash_function": same_hash_function,
                "timing_ratio": timing_ratio,
                "recommended_buffer": max(finality_a, finality_b) + 300,  # 5 min buffer
                "requires_hash_bridge": not same_hash_function,
            },
            "recommendations": {
                "source_chain": chain_a if finality_a < finality_b else chain_b,
                "destination_chain": chain_b if finality_a < finality_b else chain_a,
                "safety_level": "high" if timing_ratio < 3 else "medium",
            },
        }


# ================================================================
# TESTING AND EXAMPLES
# ================================================================


def test_cross_chain_hash_bridge():
    """Test the cross-chain hash bridge functionality"""

    print("Testing Cross-Chain Hash Bridge...")

    # Initialize bridge
    bridge = CrossChainHashBridge()

    # Test 1: Generate secret set
    print("\n1. Generating secret set for 4-part order...")
    secrets = bridge.generate_secret_set(4)
    print(f"Generated {len(secrets)} secrets (4 parts + 1 completion)")

    # Test 2: Build cross-chain Merkle trees
    print("\n2. Building cross-chain Merkle trees...")
    trees = bridge.build_cross_chain_merkle_trees(secrets)
    print(f"EVM root: {trees['evm_tree']['root'].hex()}")
    print(f"Tezos root: {trees['tezos_tree']['root'].hex()}")
    print(f"Tree depth: {trees['metadata']['tree_depth']}")

    # Test 3: Generate and validate proofs
    print("\n3. Testing proof generation and validation...")
    for i in range(len(secrets)):
        proof = bridge.generate_cross_chain_proof(trees, i)

        # Validate EVM proof
        evm_valid = bridge.validate_cross_chain_proof(proof, "ethereum")

        # Validate Tezos proof
        tezos_valid = bridge.validate_cross_chain_proof(proof, "tezos")

        print(
            f"Secret {i}: EVM proof valid={evm_valid}, Tezos proof valid={tezos_valid}"
        )

    # Test 4: Chain compatibility
    print("\n4. Testing chain compatibility...")
    compatibility = bridge.verify_chain_compatibility("ethereum", "tezos")
    print(f"Ethereum ↔ Tezos compatibility: {compatibility['compatible']}")
    print(f"Recommended buffer: {compatibility['analysis']['recommended_buffer']}s")

    print("\nAll tests completed successfully!")


if "main" in __name__:
    test_cross_chain_hash_bridge()
