use log::{Log, Metadata, Record};

pub type LogCallback = fn(record: &Record);

pub(crate) fn log_callback(record: &Record) {
    log::logger().log(record)
}

pub struct ExternalLogger {
    callback: LogCallback,
}

impl ExternalLogger {
    pub fn new(callback: LogCallback) -> Self {
        Self {
            callback
        }
    }
}

impl Log for ExternalLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        (self.callback)(record)
    }

    fn flush(&self) {}
}