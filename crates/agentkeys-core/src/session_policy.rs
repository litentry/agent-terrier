//! #512 — the per-cloud SESSION-POLICY RENDERER (ADR
//! `docs/spec/stacks/ve-sts-signing-split.md`, "pass intent, not policy").
//!
//! ONE owner for the per-actor scope-down dialects: callers hand a dialect-free
//! [`ScopedAccessIntent`] and get the cloud's policy JSON back. The broker's
//! `ve_session_policy` (ve_sts.rs) and the signer's `/dev/sign-sts` both render
//! through here, so the two mint paths cannot drift — rule 2 of the ADR holds
//! **by construction** (no caller-authored policy string exists to validate).
//!
//! Dialect facts this module owns (and its golden tests pin):
//!   - VE policies carry NO `Version` field (canonical VE system-policy shape)
//!     and the ListBucket prefix condition key is the LOWERCASE `tos:prefix`
//!     (the only spelling VE's engine accepts — found live, 2026-07-02).
//!   - AWS policies carry `Version: 2012-10-17` and `s3:prefix`.

use serde_json::json;

/// Which cloud's policy grammar to emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloudDialect {
    /// `s3:*` actions, `arn:aws:s3:::…` resources, `Version` field, `s3:prefix`.
    AwsS3,
    /// `tos:*` actions, `trn:tos:::…` resources, NO `Version`, `tos:prefix`.
    VeTos,
}

/// One object-store verb of the intent. `List` controls the bucket-level
/// ListBucket statement (prefix-conditioned); the other three are object I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Get,
    Put,
    Delete,
    List,
}

impl Verb {
    /// Parse the wire spelling (`SignStsBody.verbs` entries). Case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "get" => Some(Self::Get),
            "put" => Some(Self::Put),
            "delete" => Some(Self::Delete),
            "list" => Some(Self::List),
            _ => None,
        }
    }
}

/// The dialect-free scope-down: WHO (bare lowercase actor omni — callers
/// normalize), WHERE (buckets), WHAT (verbs). Everything else is dialect.
pub struct ScopedAccessIntent<'a> {
    pub actor_omni: &'a str,
    pub buckets: &'a [String],
    pub verbs: &'a [Verb],
}

/// Render the inline session policy for `intent` in `dialect`.
///
/// Object actions are emitted in the FIXED canonical order Get, Put, Delete
/// (independent of caller order) so output is deterministic; the ListBucket
/// statement appears only when `List` is requested. An intent with no verbs
/// renders an empty-statement policy — callers reject that upstream (the
/// signer 400s `invalid_verbs`), it is never a valid mint.
pub fn render_session_policy(dialect: CloudDialect, intent: &ScopedAccessIntent) -> String {
    // Two strings carry the whole dialect — the action service prefix and the
    // resource scheme; everything else is shared shape.
    let (svc, scheme) = match dialect {
        CloudDialect::VeTos => ("tos", "trn:tos:::"),
        CloudDialect::AwsS3 => ("s3", "arn:aws:s3:::"),
    };

    let mut object_actions: Vec<String> = Vec::new();
    for (verb, name) in [
        (Verb::Get, "Get"),
        (Verb::Put, "Put"),
        (Verb::Delete, "Delete"),
    ] {
        if intent.verbs.contains(&verb) {
            object_actions.push(format!("{svc}:{name}Object"));
        }
    }
    let object_resources: Vec<String> = intent
        .buckets
        .iter()
        .map(|b| format!("{scheme}{b}/bots/{}/*", intent.actor_omni))
        .collect();
    let bucket_resources: Vec<String> = intent
        .buckets
        .iter()
        .map(|b| format!("{scheme}{b}"))
        .collect();

    let mut statements = Vec::new();
    if !object_actions.is_empty() {
        statements.push(json!({
            "Effect": "Allow",
            "Action": object_actions,
            "Resource": object_resources,
        }));
    }
    if intent.verbs.contains(&Verb::List) {
        let prefix_key = format!("{svc}:prefix");
        statements.push(json!({
            "Effect": "Allow",
            "Action": [format!("{svc}:ListBucket")],
            "Resource": bucket_resources,
            "Condition": { "StringLike": { prefix_key: format!("bots/{}/*", intent.actor_omni) } },
        }));
    }

    match dialect {
        CloudDialect::VeTos => json!({ "Statement": statements }).to_string(),
        CloudDialect::AwsS3 => {
            json!({ "Version": "2012-10-17", "Statement": statements }).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[Verb] = &[Verb::Get, Verb::Put, Verb::Delete, Verb::List];

    fn omni() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn ve_golden_all_verbs_single_bucket() {
        let o = omni();
        let p = render_session_policy(
            CloudDialect::VeTos,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["agentterrier-vault".into()],
                verbs: ALL,
            },
        );
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let expected = serde_json::json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["tos:GetObject", "tos:PutObject", "tos:DeleteObject"],
                    "Resource": [format!("trn:tos:::agentterrier-vault/bots/{o}/*")],
                },
                {
                    "Effect": "Allow",
                    "Action": ["tos:ListBucket"],
                    "Resource": ["trn:tos:::agentterrier-vault"],
                    "Condition": { "StringLike": { "tos:prefix": format!("bots/{o}/*") } },
                }
            ]
        });
        assert_eq!(v, expected);
        // The two dialect facts, pinned as strings: lowercase `tos:prefix`,
        // and NO `Version` field on VE.
        assert!(p.contains("\"tos:prefix\""), "{p}");
        assert!(!p.contains("Version"), "{p}");
    }

    #[test]
    fn aws_golden_all_verbs_single_bucket() {
        let o = omni();
        let p = render_session_policy(
            CloudDialect::AwsS3,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["agentkeys-vault".into()],
                verbs: ALL,
            },
        );
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        let expected = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": [format!("arn:aws:s3:::agentkeys-vault/bots/{o}/*")],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::agentkeys-vault"],
                    "Condition": { "StringLike": { "s3:prefix": format!("bots/{o}/*") } },
                }
            ]
        });
        assert_eq!(v, expected);
    }

    #[test]
    fn verb_subset_drops_statements() {
        let o = omni();
        let get_only = render_session_policy(
            CloudDialect::VeTos,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["b".into()],
                verbs: &[Verb::Get],
            },
        );
        assert!(get_only.contains("tos:GetObject"), "{get_only}");
        assert!(!get_only.contains("PutObject"), "{get_only}");
        assert!(!get_only.contains("ListBucket"), "{get_only}");

        let list_only = render_session_policy(
            CloudDialect::VeTos,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["b".into()],
                verbs: &[Verb::List],
            },
        );
        let v: serde_json::Value = serde_json::from_str(&list_only).unwrap();
        assert_eq!(v["Statement"].as_array().unwrap().len(), 1, "{list_only}");
        assert!(list_only.contains("tos:ListBucket"), "{list_only}");
    }

    #[test]
    fn caller_verb_order_does_not_change_output() {
        let o = omni();
        let a = render_session_policy(
            CloudDialect::VeTos,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["b".into()],
                verbs: &[Verb::Delete, Verb::Get, Verb::Put],
            },
        );
        let b = render_session_policy(
            CloudDialect::VeTos,
            &ScopedAccessIntent {
                actor_omni: &o,
                buckets: &["b".into()],
                verbs: &[Verb::Get, Verb::Put, Verb::Delete],
            },
        );
        assert_eq!(a, b);
    }

    #[test]
    fn verb_parse_wire_spellings() {
        assert_eq!(Verb::parse("get"), Some(Verb::Get));
        assert_eq!(Verb::parse("PUT"), Some(Verb::Put));
        assert_eq!(Verb::parse("Delete"), Some(Verb::Delete));
        assert_eq!(Verb::parse("list"), Some(Verb::List));
        assert_eq!(Verb::parse("read"), None);
    }
}
