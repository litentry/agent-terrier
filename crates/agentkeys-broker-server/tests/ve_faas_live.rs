//! Live **veFaaS sandbox-lifecycle** conformance — `#[ignore]`d. The #377
//! proof against real VE: spawn a LABELED instance for a synthetic delegate →
//! the label is visible on `ListSandboxes` rows (the per-delegate quota key)
//! → a second ensure returns the SAME instance (`created=false`, quota ≤ 1) →
//! `kill_for_device` tears it down and a re-ensure would have to re-create.
//!
//! Costs one short-lived instance (Timeout is forced to the 3-minute veFaaS
//! minimum below, so even an aborted run self-expires). It never touches
//! instances not labeled with THIS run's synthetic device hash.
//!
//! Run (operator laptop; needs the ark family resolvable for the instance env):
//! ```text
//! set -a; . scripts/operator-workstation.ve.env; set +a
//! AK_SK from ~/volc-broker.csv (or the admin csv) into VOLCENGINE_ACCESS_KEY/_SECRET_KEY
//! SANDBOX_FUNCTION_ID=… SANDBOX_GATEWAY_URL=…   # from ~/.zshenv / config.md
//! AGENTKEYS_VEFAAS_TIMEOUT_MINUTES=3 \
//! cargo test -p agentkeys-broker-server --test ve_faas_live -- --ignored --nocapture
//! ```

use agentkeys_broker_server::ve_faas::{label_value, VeFaasClient, LABEL_DEVICE_KEY_HASH};

#[tokio::test]
#[ignore = "live VE call — needs VOLCENGINE_ACCESS_KEY/_SECRET_KEY + SANDBOX_FUNCTION_ID (+ ark family)"]
async fn sandbox_lifecycle_spawn_is_idempotent_and_teardown_kills() {
    let client = VeFaasClient::from_env()
        .expect("veFaaS config invalid — see error")
        .expect("SANDBOX_FUNCTION_ID must be set for the live test");

    // Synthetic delegate identity, unique per run so a crashed prior run's
    // leftovers (which self-expire in 3 min anyway) can't collide.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let device_key_hash = format!("0x{:064x}", nonce);
    let actor_omni = format!("0x{:064x}", nonce + 1);
    // #543 — veFaaS stores/filters the TRUNCATED label value (values <64 chars);
    // the full 66-char hash never appears in Metadata.
    let dkh_label = label_value(&device_key_hash);

    // 1. Spawn: first ensure must CREATE.
    let first = client
        .ensure_for_delegate(&device_key_hash, &actor_omni)
        .await
        .expect("first ensure");
    assert!(first.created, "no instance existed for the fresh delegate");
    println!("--- spawned {} ({})", first.sandbox_id, first.status);

    // 2. Quota key: the fresh instance is findable by its Metadata label.
    let labeled = client
        .list_instances(Some(&[(LABEL_DEVICE_KEY_HASH, dkh_label.as_str())]))
        .await
        .expect("list by label");
    assert!(
        labeled.iter().any(|i| i.id == first.sandbox_id
            && i.metadata.get(LABEL_DEVICE_KEY_HASH).map(String::as_str)
                == Some(dkh_label.as_str())),
        "Metadata labels NOT visible on ListSandboxes rows — the per-delegate \
         quota invariant is unenforceable; rows: {labeled:?}",
        labeled = labeled
            .iter()
            .map(|i| (i.id.clone(), i.status.clone(), i.metadata.clone()))
            .collect::<Vec<_>>()
    );
    println!("--- label visible on ListSandboxes ✓");

    // 3. Idempotency: a second ensure for the SAME delegate reuses, never
    //    duplicates (ListSandboxes shows ≤ 1 live instance for the label).
    let second = client
        .ensure_for_delegate(&device_key_hash, &actor_omni)
        .await
        .expect("second ensure");
    assert!(!second.created, "second ensure must reuse, not duplicate");
    assert_eq!(second.sandbox_id, first.sandbox_id);
    let live_for_label = client
        .list_instances(Some(&[(LABEL_DEVICE_KEY_HASH, dkh_label.as_str())]))
        .await
        .expect("re-list")
        .into_iter()
        .filter(|i| {
            i.is_live()
                && i.metadata.get(LABEL_DEVICE_KEY_HASH).map(String::as_str)
                    == Some(dkh_label.as_str())
        })
        .count();
    assert_eq!(
        live_for_label, 1,
        "quota invariant: exactly one live instance"
    );
    println!(
        "--- second ensure reused {} ✓ (quota = 1)",
        second.sandbox_id
    );

    // 4. Teardown (the unpair leg): kill_for_device kills exactly ours.
    let killed = client
        .kill_for_device(&device_key_hash)
        .await
        .expect("kill_for_device");
    assert_eq!(killed, vec![first.sandbox_id.clone()]);
    println!("--- teardown killed {} ✓", first.sandbox_id);

    // 5. After teardown no live labeled instance remains (Terminating counts
    //    as dead for the quota scan, so a re-ensure would create afresh).
    let after = client
        .list_instances(Some(&[(LABEL_DEVICE_KEY_HASH, dkh_label.as_str())]))
        .await
        .expect("post-kill list");
    assert!(
        !after.iter().any(|i| i.is_live()
            && i.metadata.get(LABEL_DEVICE_KEY_HASH).map(String::as_str)
                == Some(dkh_label.as_str())),
        "instance still live after KillSandbox: {after:?}",
        after = after
            .iter()
            .map(|i| (i.id.clone(), i.status.clone()))
            .collect::<Vec<_>>()
    );
    println!("--- no live labeled instance after teardown ✓");
}
