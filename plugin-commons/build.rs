//! Build script for plugin-commons

use cargo_metadata::semver::Version;
use cargo_metadata::{Metadata, MetadataCommand};

fn main() {
    // read and extract bincode version, respect features enabled
    let metadata = MetadataCommand::new()
        .manifest_path(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .exec()
        .unwrap();
    let bincode_version = find_version(&metadata, "bincode");
    let abi_stable_version = find_version(&metadata, "abi_stable");

    // write bincode version to file
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_file = std::path::Path::new(&out_dir).join("consts.rs");
    std::fs::write(
        out_file,
        format!(
            r#"pub const BINCODE_VERSION: &str = "{bincode_version}";
pub const ABI_STABLE_VERSION: &str = "{abi_stable_version}";
"#
        ),
    )
    .unwrap();
}

fn find_version<'m>(metadata: &'m Metadata, name: &str) -> &'m Version {
    &metadata
        .packages
        .iter()
        .find(|p| p.name == name)
        .unwrap()
        .version
}
