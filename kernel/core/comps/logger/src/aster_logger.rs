// SPDX-License-Identifier: MPL-2.0

use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use ostd::{
    log::{Level, LevelFilter, Record},
    timer::Jiffies,
};

use crate::ring;

/// The logger used for Asterinas.
struct AsterLogger;

static LOGGER: AsterLogger = AsterLogger;

static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(LevelFilter::Off as u8);

impl ostd::log::Log for AsterLogger {
    fn log(&self, record: &Record) {
        ring::push_kernel(record.level() as u8, record.prefix(), record.args());
        if (record.level() as u8) < CONSOLE_LEVEL.load(Ordering::Relaxed) {
            let timestamp = Jiffies::elapsed().as_duration();
            print_logs(record, &timestamp);
        }
    }
}

#[cfg(feature = "log_color")]
fn print_logs(record: &Record, timestamp: &Duration) {
    use owo_colors::Style;

    let secs = timestamp.as_secs();
    let millis = timestamp.subsec_millis();

    let timestamp_style = Style::new().green();
    let record_style = Style::new().default_color();
    let level_style = match record.level() {
        Level::Error => Style::new().red(),
        Level::Warning => Style::new().bright_yellow(),
        Level::Info => Style::new().blue(),
        Level::Debug => Style::new().bright_green(),
        Level::Notice => Style::new().cyan(),
        Level::Emerg | Level::Alert | Level::Crit => Style::new().red().bold(),
    };

    super::_print(format_args!(
        "{} {:<6}: {}{}\n",
        timestamp_style.style(format_args!("[{:>6}.{:03}]", secs, millis)),
        level_style.style(record.level()),
        record_style.style(record.prefix()),
        record_style.style(record.args())
    ));
}

#[cfg(not(feature = "log_color"))]
fn print_logs(record: &Record, timestamp: &Duration) {
    let secs = timestamp.as_secs();
    let millis = timestamp.subsec_millis();

    super::_print(format_args!(
        "[{:>6}.{:03}] {:<6}: {}{}\n",
        secs,
        millis,
        record.level(),
        record.prefix(),
        record.args()
    ));
}

pub(super) fn init() {
    let console_level = ostd::log::max_level();
    CONSOLE_LEVEL.store(console_level as u8, Ordering::Relaxed);
    ostd::log::inject_logger(&LOGGER);
    ostd::log::set_max_level(console_level.max(LevelFilter::Info));
}
