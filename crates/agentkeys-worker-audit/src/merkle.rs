//! Minimal Merkle tree over keccak256 with OpenZeppelin-style sorted-pairs.
//!
//! Matches the on-chain `CredentialAudit.verifyEntryInRoot` algorithm so a
//! proof emitted by this module is verifiable on chain without further
//! transformation.

use sha3::{Digest, Keccak256};

pub type Bytes32 = [u8; 32];

pub fn keccak256(bytes: &[u8]) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Domain prefix for an internal node. Mirrors `verifyEntryInRoot` in
/// `CredentialAudit.sol`. Without this prefix an internal-node digest
/// could impersonate a leaf at a shorter depth (codex M2).
const INTERNAL_NODE_PREFIX: u8 = 0x01;
/// Domain prefix for a leaf. Mirrors the contract's leaf-hashing step.
const LEAF_PREFIX: u8 = 0x00;

fn hash_pair(a: Bytes32, b: Bytes32) -> Bytes32 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Keccak256::new();
    h.update([INTERNAL_NODE_PREFIX]);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Domain-prefix a raw application leaf hash before it enters the Merkle
/// tree. Callers building leaves from event data must apply this before
/// calling [`merkle_root`] / [`merkle_proof`].
pub fn leaf_prefix(raw_leaf: Bytes32) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update([LEAF_PREFIX]);
    h.update(raw_leaf);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the Merkle root of `raw_leaves`. Each leaf is automatically
/// prefixed with `LEAF_PREFIX` (`0x00`) before entering the tree so the
/// resulting root matches the on-chain `CredentialAudit.verifyEntryInRoot`
/// consumer. Returns the all-zero root for an empty input. For odd-length
/// levels the last node is paired with itself (matches OpenZeppelin).
pub fn merkle_root(raw_leaves: &[Bytes32]) -> Bytes32 {
    if raw_leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<Bytes32> = raw_leaves.iter().copied().map(leaf_prefix).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Compute a sorted-pairs Merkle proof for raw leaf at `index`. The
/// returned proof is in the format the on-chain `verifyEntryInRoot`
/// expects: pass the RAW (unprefixed) leaf bytes alongside this proof;
/// the contract applies `LEAF_PREFIX` internally.
pub fn merkle_proof(raw_leaves: &[Bytes32], index: usize) -> Vec<Bytes32> {
    if raw_leaves.is_empty() || index >= raw_leaves.len() {
        return Vec::new();
    }
    let mut proof = Vec::new();
    let mut idx = index;
    let mut level: Vec<Bytes32> = raw_leaves.iter().copied().map(leaf_prefix).collect();
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            if idx + 1 < level.len() { level[idx + 1] } else { level[idx] }
        } else {
            level[idx - 1]
        };
        proof.push(sibling);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(s: &str) -> Bytes32 {
        keccak256(s.as_bytes())
    }

    #[test]
    fn root_matches_hand_computed() {
        let l0 = leaf("audit-event-0");
        let l1 = leaf("audit-event-1");
        let l2 = leaf("audit-event-2");
        let l3 = leaf("audit-event-3");
        // Apply LEAF_PREFIX (codex M2 domain separation) before pair-hashing.
        let h01 = hash_pair(leaf_prefix(l0), leaf_prefix(l1));
        let h23 = hash_pair(leaf_prefix(l2), leaf_prefix(l3));
        let expected = hash_pair(h01, h23);
        let got = merkle_root(&[l0, l1, l2, l3]);
        assert_eq!(got, expected);
    }

    #[test]
    fn proof_verifies_with_root() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let root = merkle_root(&leaves);
        for (i, target) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i);
            // Verify locally by mirroring the contract: prefix the raw leaf,
            // then walk the proof with internal-node prefixes via hash_pair.
            let mut computed = leaf_prefix(*target);
            for sibling in &proof {
                computed = hash_pair(computed, *sibling);
            }
            assert_eq!(computed, root, "leaf {i} proof failed");
        }
    }

    #[test]
    fn empty_input() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        assert!(merkle_proof(&[], 0).is_empty());
    }

    #[test]
    fn odd_count_pairs_last_with_self() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c")];
        let root = merkle_root(&leaves);
        // Hand check: pair c with c at level 1, with LEAF_PREFIX on each leaf.
        let l0 = leaf_prefix(leaves[0]);
        let l1 = leaf_prefix(leaves[1]);
        let l2 = leaf_prefix(leaves[2]);
        let h_ab = hash_pair(l0, l1);
        let h_cc = hash_pair(l2, l2);
        let expected = hash_pair(h_ab, h_cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn internal_node_cannot_pose_as_leaf() {
        // The codex M2 attack: take an internal-node digest from a deeper
        // tree and submit it as a leaf in a shallower proof. With domain
        // separation, the contract's leaf_prefix(internal_digest) won't
        // match the previously-computed internal-node hash, so the proof
        // chain breaks. We model that here by computing an internal node
        // and verifying it does NOT verify as a leaf against the root.
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let root = merkle_root(&leaves);
        let internal_node = hash_pair(leaf_prefix(leaves[0]), leaf_prefix(leaves[1]));
        // Attempt: claim `internal_node` is a leaf with proof = [right-half-root].
        let right_half = hash_pair(leaf_prefix(leaves[2]), leaf_prefix(leaves[3]));
        let proof = vec![right_half];
        let mut computed = leaf_prefix(internal_node);
        for sibling in &proof {
            computed = hash_pair(computed, *sibling);
        }
        assert_ne!(computed, root, "internal-node-as-leaf attack should fail");
    }
}
