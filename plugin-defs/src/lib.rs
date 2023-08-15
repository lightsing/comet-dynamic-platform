#[macro_use]
extern crate log;

use ed25519::Signature;
use rand::distributions::{Alphanumeric, DistString};
use rand::thread_rng;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[cfg(windows)]
const PLUGIN_EXT: &str = "dll";
#[cfg(all(unix, not(target_os = "macos")))]
const PLUGIN_EXT: &str = "so";
#[cfg(target_os = "macos")]
const PLUGIN_EXT: &str = "dylib";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("generic io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature error: {0}")]
    Signature(#[from] ed25519::Error),
    #[error("package digest mismatch")]
    InvalidDigest,
    #[error("unable to read the package file: {0}")]
    UnableToReadPackage(std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ExportAlgorithm {
    None,
    Zstd,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageExport {
    pub alog: ExportAlgorithm,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct Package {
    pub metadata: PackageMetadata,
    pub library: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    #[serde(default)]
    pub digest: String,
    pub version: Version,
    #[serde(default)]
    pub dependencies: Vec<DependencySpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencySpec {
    pub name: String,
    pub version: VersionReq,
}

impl Package {
    pub fn new(metadata: PackageMetadata, library: Vec<u8>) -> Self {
        let mut this = Self { metadata, library };

        this.metadata.digest = hex::encode(this.digest());
        this
    }

    pub fn digest(&self) -> [u8; 64] {
        let mut blake = blake::Blake::new(512).unwrap();
        blake.update(self.library.as_slice());
        let mut digest = [0; 64];
        blake.finalise(&mut digest);
        digest
    }

    pub fn digest_check(&self) -> bool {
        let provided_digest: Option<[u8; 64]> = hex::decode(&self.metadata.digest)
            .ok()
            .and_then(|d| d.try_into().ok());
        if let Some(provided_digest) = provided_digest {
            if provided_digest == self.digest() {
                return true;
            }
        }
        false
    }

    pub fn export<S>(&self, signer: S) -> Result<Vec<u8>>
    where
        S: ed25519::signature::Signer<Signature>,
    {
        let result = bincode::serialize(&self)?;
        let signature = signer.try_sign(&result)?;

        let compressed = zstd::encode_all(result.as_slice(), zstd::DEFAULT_COMPRESSION_LEVEL)?;

        let exported = PackageExport {
            alog: ExportAlgorithm::Zstd,
            payload: compressed,
            signature,
        };
        let exported = bincode::serialize(&exported)?;
        Ok(exported)
    }

    pub fn import_file<V, P: AsRef<Path>>(pathname: P, verifier: V) -> Result<Self>
    where
        V: ed25519::signature::Verifier<Signature>,
    {
        let content = fs::read(pathname).map_err(Error::UnableToReadPackage)?;
        Self::import(content.as_slice(), verifier)
    }

    pub fn import<V>(exported: &[u8], verifier: V) -> Result<Self>
    where
        V: ed25519::signature::Verifier<Signature>,
    {
        let exported: PackageExport = bincode::deserialize(exported)?;
        let payload = match exported.alog {
            ExportAlgorithm::None => exported.payload,
            ExportAlgorithm::Zstd => zstd::decode_all(exported.payload.as_slice())?,
        };
        verifier.verify(&payload, &exported.signature)?;
        let package: Package = bincode::deserialize(&payload)?;
        trace!("plugin {} contains valid signature", package.metadata.name);
        if package.digest_check() {
            trace!("plugin {} contains valid digest", package.metadata.name);
            Ok(package)
        } else {
            trace!("plugin {} contains invalid digest", package.metadata.name);
            Err(Error::InvalidDigest)
        }
    }

    pub fn release_lib_to_temp(&self) -> Result<(TempDir, PathBuf)> {
        let temp_dir = tempfile::tempdir()?;
        // generate a random name with extension
        let temp_dll_name = format!(
            "{}.{}",
            Alphanumeric.sample_string(&mut thread_rng(), 32),
            PLUGIN_EXT
        );
        let temp_dll_path = temp_dir.path().join(temp_dll_name);
        fs::write(&temp_dll_path, self.library.as_slice())?;
        trace!("release {PLUGIN_EXT} to: {:?}", temp_dll_path);
        Ok((temp_dir, temp_dll_path))
    }
}

mod ser {
    use super::Package;
    use plugin_commons::consts::*;
    use serde::ser::{Error, SerializeStruct};
    use serde::{Serialize, Serializer};

    impl Serialize for Package {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut ser = serializer.serialize_struct("Package", 1)?;
            let meta_json = serde_json::to_string(&self.metadata).map_err(S::Error::custom)?;
            ser.serialize_field("bincode_version", BINCODE_VERSION)?;
            ser.serialize_field("abi_stable_version", ABI_STABLE_VERSION)?;
            ser.serialize_field("metadata", &meta_json)?;
            ser.serialize_field("library", &self.library)?;
            ser.end()
        }
    }
}

mod de {
    use super::Package;
    use plugin_commons::consts::*;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    struct PackageDe {
        bincode_version: String,
        abi_stable_version: String,
        metadata: String,
        library: Vec<u8>,
    }

    impl<'de> Deserialize<'de> for Package {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let de = PackageDe::deserialize(deserializer)?;
            if de.bincode_version != BINCODE_VERSION {
                warn!(
                    "bincode version mismatch: expected {}, got {}",
                    BINCODE_VERSION, de.bincode_version
                );
                #[cfg(feature = "strict")]
                return Err(Error::custom(format!(
                    "bincode version mismatch: expected {}, got {}",
                    BINCODE_VERSION, de.bincode_version
                )));
            }
            trace!("bincode version matched");
            if de.abi_stable_version != ABI_STABLE_VERSION {
                warn!(
                    "abi stable version mismatch: expected {}, got {}",
                    ABI_STABLE_VERSION, de.abi_stable_version
                );
                #[cfg(feature = "strict")]
                return Err(Error::custom(format!(
                    "abi stable version mismatch: expected {}, got {}",
                    ABI_STABLE_VERSION, de.abi_stable_version
                )));
            }
            trace!("abi stable version matched");
            let metadata = serde_json::from_str(&de.metadata).map_err(D::Error::custom)?;
            Ok(Self {
                metadata,
                library: de.library,
            })
        }
    }
}
