//! The schema stays consistent with itself and with the README.

use super::*;
use std::collections::HashSet;

#[test]
fn names_are_unique_and_plain() {
    let list = features();
    assert_eq!(list.len(), 37);
    let mut seen = HashSet::new();
    for feature in &list {
        assert!(seen.insert(feature.name), "{} twice", feature.name);
        let plain = feature
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        assert!(plain, "{}", feature.name);
    }
    for (name, _) in METADATA {
        assert!(!seen.contains(name), "{name} is metadata, never a feature");
    }
}

#[test]
fn the_readme_documents_every_feature_and_metadata_column() {
    let readme = include_str!("../README.md");
    for feature in features() {
        assert!(
            readme.contains(&format!("`{}`", feature.name)),
            "{} missing from README",
            feature.name
        );
    }
    for (name, _) in METADATA {
        assert!(
            readme.contains(&format!("`{name}`")),
            "{name} missing from README"
        );
    }
}

#[test]
fn the_json_schema_carries_the_version() {
    let json = schema_json();
    assert_eq!(json["schema_version"], SCHEMA_VERSION);
    assert_eq!(json["features"].as_array().map(Vec::len), Some(37));
    assert_eq!(json["features"][0]["name"], "protocol");
    assert_eq!(
        json["metadata"].as_array().map(Vec::len),
        Some(METADATA.len())
    );
}
