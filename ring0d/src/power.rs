use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{info, warn};

const _UPROXY_SERVICE: &str = "org.freedesktop.UPower";
const _UPROXY_PATH: &str = "/org/freedesktop/UPower";
const _UPROXY_IFACE: &str = "org.freedesktop.UPower";

pub struct PowerGovernor {
    on_battery: AtomicBool,
    fim_throttled: AtomicBool,
    poll_interval: Arc<std::sync::atomic::AtomicU64>,
    dbus_handle: Option<tokio::task::JoinHandle<()>>,
}

impl PowerGovernor {
    pub fn new() -> Self {
        Self {
            on_battery: AtomicBool::new(false),
            fim_throttled: AtomicBool::new(false),
            poll_interval: Arc::new(std::sync::atomic::AtomicU64::new(5)),
            dbus_handle: None,
        }
    }

    pub fn start_dbus_monitor(&mut self) {
        warn!("PowerGovernor: D-Bus monitor not available (zbus API mismatch)");
    }

    pub fn set_on_battery(&self, on_battery: bool) {
        self.on_battery.store(on_battery, Ordering::Relaxed);
        if on_battery {
            self.fim_throttled.store(true, Ordering::Relaxed);
            self.poll_interval.store(30, Ordering::Relaxed);
            info!("PowerGovernor: switched to BATTERY — throttling FIM, poll interval = 30s");
        } else {
            self.fim_throttled.store(false, Ordering::Relaxed);
            self.poll_interval.store(5, Ordering::Relaxed);
            info!("PowerGovernor: switched to AC power — full performance");
        }
    }

    pub fn is_on_battery(&self) -> bool {
        self.on_battery.load(Ordering::Relaxed)
    }

    pub fn is_fim_throttled(&self) -> bool {
        self.fim_throttled.load(Ordering::Relaxed)
    }

    pub fn poll_interval_secs(&self) -> u64 {
        self.poll_interval.load(Ordering::Relaxed)
    }
}
