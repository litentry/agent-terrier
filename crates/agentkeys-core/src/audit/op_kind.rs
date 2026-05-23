//! Canonical op_kind byte assignments (arch.md §15.3a, issue #97).
//!
//! **PRs adding new op_kinds MUST append a row to the canonical table in
//! arch.md §15.3a AND add a variant here.** Numbers are never reused and
//! never reordered — that's invariant #7 in the non-break design.
//!
//! Byte ranges with reserved slots:
//!
//! - 0-9   creds family (CredStore=0, CredFetch=1, CredTeardown=2; 3-9 reserved)
//! - 10-19 memory family (MemoryPut=10, MemoryGet=11, MemoryTeardown=12; 13-19 reserved)
//! - 20-29 signs family (SignEip191=20, SignEip712=21; 22-29 reserved)
//! - 30-39 payments family (PaymentEscrowRedeem=30, PaymentDirect=31; 32-39 reserved)
//! - 40-49 scope family (ScopeGrant=40, ScopeRevoke=41; 42-49 reserved)
//! - 50-59 device family (DeviceAdd=50, DeviceRevoke=51, K10Rotate=52; 53-59 reserved)
//! - 60-69 email family (EmailSend=60, EmailReceive=61; 62-69 reserved)
//! - 70-79 K3 family (K3EpochAdvance=70; 71-79 reserved)
//! - 80-255 reserved for future families

/// Canonical op_kind enum. The byte value MUST match the row in arch.md
/// §15.3a. The enum is `repr(u8)` so `as u8` gives the canonical byte.
///
/// Decoders MUST handle unknown bytes (anything outside this enum) by
/// keeping the envelope-level fields readable and surfacing
/// `Unknown(byte)` in the explorer UI (per non-break invariant #1).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOpKind {
    CredStore = 0,
    CredFetch = 1,
    CredTeardown = 2,
    MemoryPut = 10,
    MemoryGet = 11,
    MemoryTeardown = 12,
    SignEip191 = 20,
    SignEip712 = 21,
    PaymentEscrowRedeem = 30,
    PaymentDirect = 31,
    ScopeGrant = 40,
    ScopeRevoke = 41,
    DeviceAdd = 50,
    DeviceRevoke = 51,
    K10Rotate = 52,
    EmailSend = 60,
    EmailReceive = 61,
    K3EpochAdvance = 70,
}

impl AuditOpKind {
    /// Decode a canonical byte to a known op_kind. Returns `None` for any
    /// byte not in the canonical table (caller renders `Unknown(byte)`).
    pub fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::CredStore,
            1 => Self::CredFetch,
            2 => Self::CredTeardown,
            10 => Self::MemoryPut,
            11 => Self::MemoryGet,
            12 => Self::MemoryTeardown,
            20 => Self::SignEip191,
            21 => Self::SignEip712,
            30 => Self::PaymentEscrowRedeem,
            31 => Self::PaymentDirect,
            40 => Self::ScopeGrant,
            41 => Self::ScopeRevoke,
            50 => Self::DeviceAdd,
            51 => Self::DeviceRevoke,
            52 => Self::K10Rotate,
            60 => Self::EmailSend,
            61 => Self::EmailReceive,
            70 => Self::K3EpochAdvance,
            _ => return None,
        })
    }

    /// Human-readable label — what the explorer prints when it recognizes
    /// the op_kind. Unknown op_kinds render `Unknown(<byte>)` per
    /// invariant #4.
    pub fn label(self) -> &'static str {
        match self {
            Self::CredStore => "cred.store",
            Self::CredFetch => "cred.fetch",
            Self::CredTeardown => "cred.teardown",
            Self::MemoryPut => "memory.put",
            Self::MemoryGet => "memory.get",
            Self::MemoryTeardown => "memory.teardown",
            Self::SignEip191 => "sign.eip191",
            Self::SignEip712 => "sign.eip712",
            Self::PaymentEscrowRedeem => "payment.escrow_redeem",
            Self::PaymentDirect => "payment.direct",
            Self::ScopeGrant => "scope.grant",
            Self::ScopeRevoke => "scope.revoke",
            Self::DeviceAdd => "device.add",
            Self::DeviceRevoke => "device.revoke",
            Self::K10Rotate => "device.k10_rotate",
            Self::EmailSend => "email.send",
            Self::EmailReceive => "email.receive",
            Self::K3EpochAdvance => "k3.epoch_advance",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant in the table can be encoded to its byte and decoded
    /// back. Catches accidental byte-value collisions or missing
    /// `from_u8` arms.
    #[test]
    fn every_op_kind_roundtrips_through_u8() {
        let all = [
            AuditOpKind::CredStore,
            AuditOpKind::CredFetch,
            AuditOpKind::CredTeardown,
            AuditOpKind::MemoryPut,
            AuditOpKind::MemoryGet,
            AuditOpKind::MemoryTeardown,
            AuditOpKind::SignEip191,
            AuditOpKind::SignEip712,
            AuditOpKind::PaymentEscrowRedeem,
            AuditOpKind::PaymentDirect,
            AuditOpKind::ScopeGrant,
            AuditOpKind::ScopeRevoke,
            AuditOpKind::DeviceAdd,
            AuditOpKind::DeviceRevoke,
            AuditOpKind::K10Rotate,
            AuditOpKind::EmailSend,
            AuditOpKind::EmailReceive,
            AuditOpKind::K3EpochAdvance,
        ];
        for k in all {
            let byte = k as u8;
            assert_eq!(
                AuditOpKind::from_u8(byte),
                Some(k),
                "byte {byte} round-trip"
            );
        }
    }

    /// Bytes in the reserved gaps return None — proves the non-break
    /// invariant #1 (open enum). 250 is the reserved-future canary.
    #[test]
    fn unknown_bytes_return_none() {
        for byte in [3u8, 9, 13, 19, 22, 32, 42, 53, 62, 71, 80, 200, 250, 255] {
            assert_eq!(
                AuditOpKind::from_u8(byte),
                None,
                "byte {byte} must be unknown"
            );
        }
    }

    /// No two enum variants share a byte. Compile-time guarantee in Rust,
    /// but verify in case someone copy-pastes a number.
    #[test]
    fn all_byte_values_unique() {
        use std::collections::HashSet;
        let all = [
            AuditOpKind::CredStore as u8,
            AuditOpKind::CredFetch as u8,
            AuditOpKind::CredTeardown as u8,
            AuditOpKind::MemoryPut as u8,
            AuditOpKind::MemoryGet as u8,
            AuditOpKind::MemoryTeardown as u8,
            AuditOpKind::SignEip191 as u8,
            AuditOpKind::SignEip712 as u8,
            AuditOpKind::PaymentEscrowRedeem as u8,
            AuditOpKind::PaymentDirect as u8,
            AuditOpKind::ScopeGrant as u8,
            AuditOpKind::ScopeRevoke as u8,
            AuditOpKind::DeviceAdd as u8,
            AuditOpKind::DeviceRevoke as u8,
            AuditOpKind::K10Rotate as u8,
            AuditOpKind::EmailSend as u8,
            AuditOpKind::EmailReceive as u8,
            AuditOpKind::K3EpochAdvance as u8,
        ];
        let s: HashSet<_> = all.iter().copied().collect();
        assert_eq!(s.len(), all.len(), "duplicate byte assignment");
    }
}
