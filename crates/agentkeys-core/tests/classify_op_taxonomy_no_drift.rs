//! No-drift guard (#322): the policy-intent classifier's `operation` taxonomy
//! lives in `agentkeys-catalog` (the dependency-light crate the worker + dataset
//! tooling share), but the **canonical** op_kind labels are owned here in
//! `agentkeys-core::audit::op_kind` (arch.md §15.3a). These tests assert the two
//! cannot silently diverge: every "landed" operation the classifier may emit is a
//! real op_kind label, and every "uncovered" operation is genuinely *not* yet a
//! landed op_kind. Without this, a renamed op_kind would leave the validator
//! happily accepting a stale operation name.

use std::collections::HashSet;

use agentkeys_catalog::validate::{LANDED_OPERATIONS, UNCOVERED_OPERATIONS};
use agentkeys_core::audit::op_kind::AuditOpKind;

fn canonical_labels() -> HashSet<&'static str> {
    (0u8..=255)
        .filter_map(AuditOpKind::from_u8)
        .map(|k| k.label())
        .collect()
}

#[test]
fn landed_operations_are_real_op_kind_labels() {
    let labels = canonical_labels();
    for op in LANDED_OPERATIONS {
        assert!(
            labels.contains(op),
            "LANDED_OPERATIONS entry `{op}` is not a canonical AuditOpKind::label() — \
             op_kind taxonomy drift (arch.md §15.3a). Update the constant or the enum."
        );
    }
}

#[test]
fn uncovered_operations_have_no_landed_op_kind() {
    let labels = canonical_labels();
    for op in UNCOVERED_OPERATIONS {
        assert!(
            !labels.contains(op),
            "UNCOVERED_OPERATIONS entry `{op}` now collides with a landed op_kind label — \
             once its worker ships, move it from UNCOVERED_OPERATIONS to LANDED_OPERATIONS."
        );
    }
}
