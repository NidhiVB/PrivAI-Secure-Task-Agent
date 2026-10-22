"""Deterministic RFC 6962-compliant Merkle Tree implementation for audit checkpoint anchoring."""

import hashlib
import hmac
from typing import Any

# RFC 6962 Domain Separation Prefixes
LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"


def hash_leaf(record_hash: str) -> str:
    """Compute leaf hash with RFC 6962 domain separation (0x00 prefix).

    Security Invariant:
    Pre-image domain separation prevents ambiguity between leaf hashes and internal tree nodes.
    """
    try:
        data = bytes.fromhex(record_hash) if len(record_hash) == 64 else record_hash.encode("utf-8")
    except ValueError:
        data = record_hash.encode("utf-8")
    return hashlib.sha256(LEAF_PREFIX + data).hexdigest()


def hash_nodes(left_hex: str, right_hex: str) -> str:
    """Compute internal node hash with RFC 6962 domain separation (0x01 prefix)."""
    try:
        left_bytes = bytes.fromhex(left_hex) if len(left_hex) == 64 else left_hex.encode("utf-8")
    except ValueError:
        left_bytes = left_hex.encode("utf-8")

    try:
        right_bytes = bytes.fromhex(right_hex) if len(right_hex) == 64 else right_hex.encode("utf-8")
    except ValueError:
        right_bytes = right_hex.encode("utf-8")

    return hashlib.sha256(NODE_PREFIX + left_bytes + right_bytes).hexdigest()


def build_merkle_layers(record_hashes: list[str]) -> list[list[str]]:
    """Build all layers of the Merkle Tree from an ordered list of leaf record hashes.

    Odd-Node Handling Rule:
    If a layer has an odd count of nodes (len % 2 == 1), the last node is carried over
    (promoted) to the next level unchanged without pairing, matching Certificate Transparency
    / RFC 6962 Section 2.1 tree construction.
    """
    if not record_hashes:
        raise ValueError("Cannot build Merkle tree from empty list of record hashes.")

    # Layer 0: Hash each leaf with LEAF_PREFIX (0x00)
    current_layer = [hash_leaf(h) for h in record_hashes]
    layers = [current_layer]

    while len(current_layer) > 1:
        next_layer: list[str] = []
        n = len(current_layer)
        for i in range(0, n, 2):
            if i + 1 < n:
                # Pair nodes: hash(0x01 + left + right)
                parent = hash_nodes(current_layer[i], current_layer[i + 1])
                next_layer.append(parent)
            else:
                # Odd node: promote to next layer unchanged
                next_layer.append(current_layer[i])
        layers.append(next_layer)
        current_layer = next_layer

    return layers


def compute_merkle_root(record_hashes: list[str]) -> str:
    """Compute deterministic cryptographic Merkle root for ordered audit record hashes."""
    layers = build_merkle_layers(record_hashes)
    return layers[-1][0]


def generate_inclusion_proof(record_hashes: list[str], target_index: int) -> list[dict[str, str]]:
    """Generate cryptographic inclusion proof for the leaf at target_index.

    Returns a list of sibling steps: [{"position": "left"|"right", "hash": "<hex>"}]
    """
    if not (0 <= target_index < len(record_hashes)):
        raise IndexError(f"target_index {target_index} out of range for {len(record_hashes)} leaves.")

    layers = build_merkle_layers(record_hashes)
    proof: list[dict[str, str]] = []
    idx = target_index

    # Traverse from layer 0 up to the layer below root
    for layer in layers[:-1]:
        n = len(layer)
        if idx % 2 == 0:
            # Current node is left child
            if idx + 1 < n:
                # Sibling is to the right
                proof.append({"position": "right", "hash": layer[idx + 1]})
            # If idx == n - 1 (odd promoted node), no sibling at this level
        else:
            # Current node is right child; sibling is to the left
            proof.append({"position": "left", "hash": layer[idx - 1]})
        idx = idx // 2

    return proof


def verify_merkle_inclusion_proof(
    leaf_record_hash: str,
    proof: list[dict[str, str]],
    expected_merkle_root: str,
) -> bool:
    """Verify cryptographic Merkle inclusion proof against the expected root hash.

    Security Invariant:
    Uses constant-time comparison to prevent timing side-channels.
    """
    try:
        current = hash_leaf(leaf_record_hash)
        for step in proof:
            pos = step.get("position")
            sibling = step.get("hash")
            if not sibling:
                return False

            if pos == "right":
                current = hash_nodes(current, sibling)
            elif pos == "left":
                current = hash_nodes(sibling, current)
            else:
                return False

        return hmac.compare_digest(current, expected_merkle_root)
    except Exception:
        return False
