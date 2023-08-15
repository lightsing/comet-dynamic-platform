#![allow(clippy::let_unit_value)]

use abi_stable::sabi_trait;
use abi_stable::std_types::{RNone, ROption, RResult, RStr, RString};
use abi_stable::StableAbi;
use ed25519_dalek::VerifyingKey;
use konst::{primitive::parse_u64, unwrap_ctx};
use libloading::{Library, Symbol};
use once_cell::sync::Lazy;
use plugin_defs::Package;
use semver::{Version, VersionReq};
use std::io;
use std::ops::Deref;
use std::path::Path;

pub use abi_stable;

pub use log::{self, debug, error, info, trace, warn};
pub use semver;

pub mod logger;

mod utils;

use crate::logger::{log_callback, LogCallback};

static VERIFIER_KEY: Lazy<VerifyingKey> = Lazy::new(|| {
    let key = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../public-key.pem"));
    let key = pem::parse(key).unwrap().contents;
    VerifyingKey::from_bytes(&key.try_into().unwrap()).unwrap()
});

pub const API_VERSION: Version = Version::new(
    unwrap_ctx!(parse_u64(env!("CARGO_PKG_VERSION_MAJOR"))),
    unwrap_ctx!(parse_u64(env!("CARGO_PKG_VERSION_MINOR"))),
    unwrap_ctx!(parse_u64(env!("CARGO_PKG_VERSION_PATCH"))),
);

pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
    loaded_libraries: Vec<Library>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to load the plugin package: {0}")]
    InvalidPackage(#[from] plugin_defs::Error),
    #[error("unable to load the plugin lib: {0}")]
    LibraryLoad(libloading::Error),
    #[error("cannot found symbol {0}")]
    MissingSymbol(String),
    #[error("plugin {name} used an invalid version req {req}")]
    InvalidVersionReq { name: String, req: String },
    #[error("plugin {name} used an unmet version req {req}")]
    UnmetRequirement { name: String, req: String },
    #[error("plugin initialization failed: {0}")]
    PluginInitialization(PluginError),
    #[error("failed to lock library file: {0}")]
    LockFile(io::Error),
    #[error("another entity is tampering current program")]
    Tampered,
    #[error("generic io error: {0}")]
    Io(#[from] io::Error),
}

#[repr(u8)]
#[derive(Debug, thiserror::Error, StableAbi)]
pub enum PluginError {
    #[error("given config is invalid")]
    InvalidConfig,
    #[error("cannot set logger")]
    SetLogger,
    #[error("{0}")]
    Custom(RString),
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Plugin trait
#[sabi_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> RStr<'static>;
    /// get used API_VERSION
    fn api_version_require(&self) -> RStr<'static> {
        RStr::from(concat!("^", env!("CARGO_PKG_VERSION")))
    }
    /// on load callback
    fn on_plugin_load(&self) {
        info!("plugin loaded")
    }
    /// on unload callback
    fn on_plugin_unload(&self) {
        info!("plugin unloaded")
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> PluginManager {
        PluginManager {
            plugins: Vec::new(),
            loaded_libraries: Vec::new(),
        }
    }

    /// # Safety
    /// this api is sound iff when the package is a valid plugin package.
    pub unsafe fn load_plugin<P: AsRef<Path>>(&mut self, filename: P) -> Result<()> {
        type PluginCreate =
            unsafe fn(ROption<RString>, LogCallback) -> RResult<*mut dyn Plugin, PluginError>;

        trace!("loading package: {:?}", filename.as_ref());
        let package = Package::import_file(filename, *VERIFIER_KEY.deref())?;

        trace!("using release-recheck strategy");
        let (_temp_dir, lib_path) = package.release_lib_to_temp()?;
        trace!("re-open and lockdown dll from: {:?}", lib_path);
        let mut lib_file = utils::lock_open_file(&lib_path)?;
        utils::validate_file(&mut lib_file, package.digest())?;
        trace!("integrity check passed");
        let lib = Library::new(&lib_path).map_err(Error::LibraryLoad)?;

        self.loaded_libraries.push(lib);
        let lib = self.loaded_libraries.last().unwrap();

        let constructor: Symbol<PluginCreate> = lib
            .get(b"_comet_plugin_create")
            .map_err(|_| Error::MissingSymbol("_comet_plugin_create".to_string()))?;
        let plugin = constructor(RNone, log_callback)
            .into_result()
            .map_err(Error::PluginInitialization)?;
        let plugin = Box::from_raw(plugin);

        let version_req_str = plugin.api_version_require();
        let version_req =
            VersionReq::parse(version_req_str.as_str()).map_err(|_| Error::InvalidVersionReq {
                name: plugin.name().to_string(),
                req: version_req_str.to_string(),
            })?;
        if version_req.matches(&API_VERSION) {
            debug!("Loaded plugin: {}", plugin.name());
            plugin.on_plugin_load();
            self.plugins.push(plugin);
            Ok(())
        } else {
            self.loaded_libraries.pop();
            Err(Error::InvalidVersionReq {
                name: plugin.name().to_string(),
                req: version_req_str.to_string(),
            })
        }
    }
}

#[macro_export]
macro_rules! declare_plugin {
    ($plugin_type:ty, $constructor:path) => {
        #[no_mangle]
        pub extern "C" fn _comet_plugin_create(
            config: $crate::abi_stable::std_types::ROption<$crate::abi_stable::std_types::RString>,
            log_callback: LogCallback,
        ) -> $crate::abi_stable::std_types::RResult<*mut dyn $crate::Plugin, $crate::PluginError> {
            // make sure the constructor is the correct type.
            let constructor: fn(
                Option<String>,
                log_callback: LogCallback,
            ) -> Result<$plugin_type, $crate::PluginError> = $constructor;

            let object = constructor(config.into_option().map(|s| s.into_string()), log_callback);
            match object {
                Ok(plugin) => {
                    let boxed: Box<dyn $crate::Plugin> = Box::new(plugin);
                    $crate::abi_stable::std_types::ROk(Box::into_raw(boxed))
                }
                Err(e) => $crate::abi_stable::std_types::RErr(e),
            }
        }
    };
}

#[test]
fn test_load() {
    pretty_env_logger::init();
    let mut plugin_mgr = PluginManager::new();
    unsafe {
        plugin_mgr
            .load_plugin(
                r"/Users/lightsing/workspace/GitHub/comet-dynamic-platform/target/debug/spider.cdp",
            )
            .unwrap();
    }
}
