use agentkeys_core::device_crypto::DeviceKey;

#[test]
fn hard_linked_device_key_is_rejected_without_changing_the_original() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.key");
    let alias = directory.path().join("alias.key");
    let original_key = DeviceKey::load_or_generate(original.to_str().unwrap(), false).unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    assert!(DeviceKey::load_or_generate(alias.to_str().unwrap(), false).is_err());
    std::fs::remove_file(&alias).unwrap();
    assert_eq!(
        DeviceKey::load_or_generate(original.to_str().unwrap(), false)
            .unwrap()
            .address(),
        original_key.address()
    );
}

#[cfg(unix)]
#[test]
fn protected_writes_reject_links_and_loose_permissions_before_truncation() {
    use agentkeys_core::{device_crypto::write_key_0600, protected_file};
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    let alias = directory.path().join("alias");
    protected_file::write(original.to_str().unwrap(), b"original", true).unwrap();
    assert!(protected_file::write(original.to_str().unwrap(), b"replacement", true).is_err());
    std::fs::hard_link(&original, &alias).unwrap();
    assert!(write_key_0600(alias.to_str().unwrap(), "replacement").is_err());
    assert!(DeviceKey::load_or_generate(alias.to_str().unwrap(), true).is_err());
    std::fs::remove_file(&alias).unwrap();
    symlink(&original, &alias).unwrap();
    assert!(write_key_0600(alias.to_str().unwrap(), "replacement").is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(write_key_0600(original.to_str().unwrap(), "replacement").is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"original");
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
    write_key_0600(original.to_str().unwrap(), "replacement").unwrap();
    assert_eq!(
        &*protected_file::read_text(original.to_str().unwrap()).unwrap(),
        "replacement"
    );
}
