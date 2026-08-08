use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{info, warn};

pub struct PowerGovernor {
    on_battery: Arc<AtomicBool>,
    fim_throttled: Arc<AtomicBool>,
    poll_interval: Arc<std::sync::atomic::AtomicU64>,
    dbus_handle: Option<tokio::task::JoinHandle<()>>,
}

impl PowerGovernor {
    pub fn new() -> Self {
        Self {
            on_battery: Arc::new(AtomicBool::new(false)),
            fim_throttled: Arc::new(AtomicBool::new(false)),
            poll_interval: Arc::new(std::sync::atomic::AtomicU64::new(5)),
            dbus_handle: None,
        }
    }

    /// Subscribe to `org.freedesktop.login1.Manager.PrepareForSleep` so the
    /// daemon throttles FIM scanning across suspend/resume (suspend can leave
    /// open files in an inconsistent state and a heavy scan during resume
    /// competes with the desktop for I/O).
    pub fn start_dbus_monitor(&mut self) {
        use futures_util::StreamExt;

        let fim_throttled = self.fim_throttled.clone();
        let poll_interval = self.poll_interval.clone();
        self.dbus_handle = Some(tokio::spawn(async move {
            let conn = match zbus::Connection::system().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("PowerGovernor: system bus unavailable: {e}");
                    return;
                }
            };
            let proxy = match zbus::proxy::Proxy::new(
                &conn,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("PowerGovernor: login1 proxy failed: {e}");
                    return;
                }
            };
            let mut signals = match proxy.receive_signal("PrepareForSleep").await {
                Ok(s) => s,
                Err(e) => {
                    warn!("PowerGovernor: PrepareForSleep subscription failed: {e}");
                    return;
                }
            };
            info!("PowerGovernor: login1 PrepareForSleep monitor active");
            while let Some(sig) = signals.next().await {
                match sig.body().deserialize::<(bool,)>() {
                    Ok((sleeping,)) => {
                        if sleeping {
                            fim_throttled.store(true, Ordering::Relaxed);
                            poll_interval.store(30, Ordering::Relaxed);
                            info!("PowerGovernor: system sleeping  -  FIM throttled");
                        } else {
                            fim_throttled.store(false, Ordering::Relaxed);
                            poll_interval.store(5, Ordering::Relaxed);
                            info!("PowerGovernor: system resumed  -  full performance");
                        }
                    }
                    Err(e) => warn!("PowerGovernor: bad PrepareForSleep payload: {e}"),
                }
            }
        }));
    }

    pub fn set_on_battery(&self, on_battery: bool) {
        self.on_battery.store(on_battery, Ordering::Relaxed);
        if on_battery {
            self.fim_throttled.store(true, Ordering::Relaxed);
            self.poll_interval.store(30, Ordering::Relaxed);
            info!("PowerGovernor: switched to BATTERY  -  throttling FIM, poll interval = 30s");
        } else {
            self.fim_throttled.store(false, Ordering::Relaxed);
            self.poll_interval.store(5, Ordering::Relaxed);
            info!("PowerGovernor: switched to AC power  -  full performance");
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
