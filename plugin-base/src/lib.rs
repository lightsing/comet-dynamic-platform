use std::ffi::OsStr;
use abi_stable::sabi_trait;
use libloading::{Library, Symbol};
use konst::{unwrap_ctx, primitive::parse_u64};
use semver::{Version, VersionReq};

pub use abi_stable;
pub use log::{self, trace, debug, info, warn, error};
pub use semver;
use abi_stable::std_types::{RNone, ROption, RResult, RStr, RString};
use abi_stable::StableAbi;

pub mod logger;
use crate::logger::{log_callback, LogCallback};

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
    fn on_plugin_load(&self) {}
    /// on unload callback
    fn on_plugin_unload(&self) {}
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

    pub unsafe fn load_plugin<P: AsRef<OsStr>>(&mut self, filename: P) -> Result<()> {
        type PluginCreate = unsafe fn(
            ROption<RString>,
            LogCallback
        ) -> RResult<*mut dyn Plugin, PluginError>;

        let lib = Library::new(filename.as_ref()).map_err(Error::LibraryLoad)?;
        self.loaded_libraries.push(lib);
        let lib = self.loaded_libraries.last().unwrap();

        let constructor: Symbol<PluginCreate> = lib.get(b"_comet_plugin_create")
            .map_err(|_| Error::MissingSymbol("_comet_plugin_create".to_string()))?;
        let plugin = constructor(RNone, log_callback)
            .into_result()
            .map_err(|e| Error::PluginInitialization(e))?;
        let plugin = Box::from_raw(plugin);

        let version_req_str = plugin.api_version_require();
        let version_req = VersionReq::parse(version_req_str.as_str())
            .map_err(|_| Error::InvalidVersionReq {
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
        ) -> $crate::abi_stable::std_types::RResult<
            *mut dyn $crate::Plugin,
            $crate::PluginError
        > {
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
                },
                Err(e) => {
                    $crate::abi_stable::std_types::RErr(e)
                }
            }
        }
    };
}

#[test]
fn test_load() {
    pretty_env_logger::init();
    let mut plugin_mgr = PluginManager::new();
    unsafe {
        plugin_mgr.load_plugin("/Users/lightsing/workspace/comet/comet-dynamic-platform/target/debug/libspider.dylib").unwrap();
    }

}