#![cfg(unix)]

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use agentkeys_broker_server::{error::BrokerResult, jwt::SessionKeypair, oidc::OidcKeypair};

struct KeyFiles {
    generate: fn(&Path) -> BrokerResult<String>,
    load: fn(&Path) -> BrokerResult<String>,
}

fn key_types() -> [KeyFiles; 2] {
    [
        KeyFiles {
            generate: |path| OidcKeypair::generate_and_persist(path).map(|key| key.public_x_b64),
            load: |path| OidcKeypair::load(path).map(|key| key.public_x_b64),
        },
        KeyFiles {
            generate: |path| SessionKeypair::generate_and_persist(path).map(|key| key.public_x_b64),
            load: |path| SessionKeypair::load(path).map(|key| key.public_x_b64),
        },
    ]
}

#[test]
fn key_generation_never_replaces_existing_files_or_follows_links() {
    for keys in key_types() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing.json");
        let public_key = (keys.generate)(&path).unwrap();
        assert_eq!((keys.load)(&path).unwrap(), public_key);
        let original = std::fs::read(&path).unwrap();
        assert!(
            (keys.generate)(&path).is_err(),
            "key generation replaced an existing identity"
        );
        assert!(std::fs::read(&path).unwrap() == original);
        let alias = directory.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!((keys.generate)(&alias).is_err());
        assert!(std::fs::read(&path).unwrap() == original);
        std::fs::remove_file(&alias).unwrap();
        let absent = directory.path().join("absent.json");
        symlink(&absent, &alias).unwrap();
        assert!((keys.generate)(&alias).is_err());
        assert!(!absent.exists());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn key_loading_rejects_unsafe_files_without_mutation() {
    for keys in key_types() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing.json");
        let public_key = (keys.generate)(&path).unwrap();
        let original = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            (keys.load)(&path).is_err(),
            "readable-by-others key was accepted"
        );
        assert!(std::fs::read(&path).unwrap() == original);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!((keys.load)(&path).unwrap(), public_key);
        let alias = directory.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!((keys.load)(&alias).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        assert!((keys.load)(&alias).is_err());
        assert!((keys.load)(&path).is_err());
        std::fs::remove_file(&alias).unwrap();
        assert_eq!((keys.load)(&path).unwrap(), public_key);
        let mut oversized = original;
        oversized.extend(vec![
            b' ';
            agentkeys_core::protected_file::MAX_SECRET_FILE_BYTES
                as usize
        ]);
        std::fs::write(&path, &oversized).unwrap();
        assert!((keys.load)(&path).is_err());
        assert!(std::fs::read(&path).unwrap() == oversized);
    }
}

#[test]
fn concurrent_generation_creates_one_stable_identity() {
    for keys in key_types() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker/signing.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                let generate = keys.generate;
                std::thread::spawn(move || {
                    barrier.wait();
                    generate(&path)
                })
            })
            .collect();
        let created: Vec<_> = writers
            .into_iter()
            .filter_map(|writer| writer.join().unwrap().ok())
            .collect();
        assert_eq!(created.len(), 1);
        assert_eq!((keys.load)(&path).unwrap(), created[0]);
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
