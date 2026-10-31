#![cfg(unix)]
use agentkeys_core::protected_file::{self, replace_atomic};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
fn replace_preserves_private_permissions_and_leaves_no_temporary_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret");
    replace_atomic(&path, b"first synthetic value").unwrap();
    replace_atomic(&path, b"second synthetic value").unwrap();
    assert_eq!(
        protected_file::read_text(path.to_str().unwrap())
            .unwrap()
            .as_str(),
        "second synthetic value"
    );
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn unsafe_targets_are_rejected_without_touching_the_original() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    replace_atomic(&original, b"unchanged").unwrap();
    let alias = directory.path().join("alias");
    symlink(&original, &alias).unwrap();
    assert!(replace_atomic(&alias, b"denied").is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    assert!(replace_atomic(&alias, b"denied").is_err());
    assert!(replace_atomic(&original, b"denied").is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(replace_atomic(&original, b"denied").is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"unchanged");
}

#[test]
fn unsafe_parent_and_oversized_contents_have_no_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("private");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    symlink(&parent, &alias).unwrap();
    assert!(replace_atomic(&alias.join("secret"), b"denied").is_err());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(replace_atomic(&parent.join("secret"), b"denied").is_err());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(replace_atomic(
        &parent.join("secret"),
        &vec![0; protected_file::MAX_SECRET_FILE_BYTES as usize + 1]
    )
    .is_err());
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
}
