#[macro_use] extern crate plugin_base;

use plugin_base::log::{self, LevelFilter};
use plugin_base::{declare_plugin, Plugin, abi_stable::std_types::RStr, PluginError};
use plugin_base::abi_stable::std_types::RString;
use plugin_base::logger::{ExternalLogger, LogCallback};

struct Spider {

}

impl Plugin for Spider {
    fn name(&self) -> RStr<'static> {
        RStr::from_str(env!("CARGO_PKG_NAME"))
    }

    fn api_version_require(&self) -> RStr<'static> {
        RStr::from_str("^0.1.0")
    }

    fn on_plugin_load(&self) {
        info!("Plugin loaded");
    }

}

fn create_plugin(
    config: Option<String>,
    log_callback: LogCallback
) -> Result<Spider, PluginError> {
    let logger = ExternalLogger::new(log_callback);
    log::set_boxed_logger(Box::new(logger)).map_err(|_| PluginError::SetLogger)?;
    log::set_max_level(LevelFilter::Trace);
    Ok(Spider {})
}

declare_plugin!(Spider, create_plugin);