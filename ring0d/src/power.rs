use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{info, warn};

const UPROXY_SERVICE: &str = "org.freedesktop.UPower";
const UPROXY_PATH: &str = "/org/freedesktop/UPower";
const UPROXY_IFACE: &str = "org.freedesktop.UPower";

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
        let on_battery = &self.on_battery as *const AtomicBool;
        let poll_interval = self.poll_interval.clone();

        let handle = tokio::spawn(async move {
            match zbus::Connection::system().await {
                Ok(conn) => {
                    let on_battery_ref = unsafe { &*on_battery };
                    match conn
                        .call_method(
                            Some(UPROXY_SERVICE),
                            UPROXY_PATH,
                            Some(UPROXY_IFACE),
                            "Get",
                            &("org.freedesktop.UPower.Device", "PowerSupply"),
                        )
                        .await
                    {
                        Ok(_) => info!("PowerGovernor: UPower D-Bus connected"),
                        Err(e) => warn!("PowerGovernor: UPower check failed: {e}"),
                    }

                    let props = conn
                        .call_method::<_, bool>(
                            Some("org.freedesktop.login1"),
                            "/org/freedesktop/login1/seat/seat0",
                            Some("org.freedesktop.DBus.Properties"),
                            "Get",
                            &("org.freedesktop.login1.Session", "LockedHint"),
                        )
                        .await;

                    if let Ok(locked) = props {
                        let _ = locked;
                    }

                    use futures_util::StreamExt;
                    let mut stream = match conn
                        .subscribe_property_changes::<bool>(
                            Some("org.freedesktop.login1"),
                            Some("/org/freedesktop/login1/session/self"),
                            Some("org.freedesktop.login1.Session"),
                            Some("LockedHint"),
                        )
                        .await
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    while let Some(change) = stream.next().await {
                        let _ = change;
                    }
                }
                Err(e) => warn!("PowerGovernor: D-Bus system bus unavailable: {e}"),
            }
        });

        self.dbus_handle = Some(handle);
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
