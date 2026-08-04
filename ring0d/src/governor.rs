use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::{info, warn};

const CPU_CHECK_INTERVAL_SECS: u64 = 2;
// Thresholds are in percent of a single CPU core used by the daemon.
const NORMAL_THRESHOLD: f32 = 1.0;
const ELEVATED_THRESHOLD: f32 = 3.0;

#[derive(Debug, Clone, PartialEq)]
pub enum GovernorState {
    Normal,
    Elevated,
    Critical,
}

pub struct CpuGovernor {
    state: Arc<RwLock<GovernorState>>,
    ring_buffer_pct: AtomicU32,
    sampling_enabled: Arc<RwLock<bool>>,
    dpi_fast_mode: Arc<RwLock<bool>>,
    last_check: RwLock<Instant>,
    daemon_cpu: AtomicU32,
    bpf_cpu: AtomicU32,
}

impl CpuGovernor {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(GovernorState::Normal)),
            ring_buffer_pct: AtomicU32::new(0),
            sampling_enabled: Arc::new(RwLock::new(true)),
            dpi_fast_mode: Arc::new(RwLock::new(false)),
            last_check: RwLock::new(Instant::now()),
            daemon_cpu: AtomicU32::new(0),
            bpf_cpu: AtomicU32::new(0),
        }
    }

    pub fn tick(&self) -> GovernorState {
        let now = Instant::now();
        let elapsed = now.duration_since(*self.last_check.read());
        if elapsed.as_secs() < CPU_CHECK_INTERVAL_SECS {
            return self.state.read().clone();
        }
        *self.last_check.write() = now;

        let daemon_pct = self.measure_daemon_cpu();
        let bpf_pct = self.measure_bpf_cpu();
        let total_pct = daemon_pct + bpf_pct;

        self.daemon_cpu
            .store((daemon_pct * 100.0) as u32, Ordering::Relaxed);
        self.bpf_cpu
            .store((bpf_pct * 100.0) as u32, Ordering::Relaxed);

        let new_state = if total_pct > ELEVATED_THRESHOLD {
            GovernorState::Critical
        } else if total_pct > NORMAL_THRESHOLD {
            GovernorState::Elevated
        } else {
            GovernorState::Normal
        };

        let mut state = self.state.write();
        if *state != new_state {
            info!(
                "Governor state change: {:?} -> {:?} (cpu={:.1}%, daemon={:.1}%, bpf={:.1}%)",
                *state, new_state, total_pct, daemon_pct, bpf_pct
            );
            *state = new_state.clone();
        }

        match *state {
            GovernorState::Normal => {
                *self.sampling_enabled.write() = true;
                *self.dpi_fast_mode.write() = false;
            }
            GovernorState::Elevated => {
                *self.sampling_enabled.write() = true;
                *self.dpi_fast_mode.write() = false;
                let pct = self.ring_buffer_pct.load(Ordering::Relaxed);
                if pct > 70 {
                    warn!("Governor: ring buffer at {pct}% — increasing capacity would help");
                }
            }
            GovernorState::Critical => {
                *self.sampling_enabled.write() = false;
                *self.dpi_fast_mode.write() = true;
                warn!(
                    "Governor CRITICAL: CPU {:.1}% — sampling disabled, DPI in fast-header mode",
                    total_pct
                );
            }
        }

        new_state
    }

    fn measure_daemon_cpu(&self) -> f32 {
        // Sample the daemon's own CPU usage from /proc/self/stat (utime+stime
        // deltas) and return it as a percentage of a single core. The previous
        // implementation measured *global* system CPU usage and mixed fractions
        // with the percent thresholds, so the governor could never trigger.
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if clk_tck <= 0 {
            return 0.0;
        }
        let clk_tck = clk_tck as f64;
        let Some((u1, s1)) = Self::proc_self_ticks() else {
            return 0.0;
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        let Some((u2, s2)) = Self::proc_self_ticks() else {
            return 0.0;
        };
        let delta = (u2.saturating_sub(u1) + s2.saturating_sub(s1)) as f64 / clk_tck;
        let pct = delta / 0.1 * 100.0; // percent of one core over the 100ms window
        pct as f32
    }

    /// Returns (utime, stime) ticks for the current process from /proc/self/stat.
    fn proc_self_ticks() -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // The comm field (in parentheses) may contain spaces; start after it.
        let end = stat.rfind(')')?;
        // Fields after comm: 3=state ... 14=utime 15=stime (1-indexed).
        let fields: Vec<&str> = stat[end + 1..].split_whitespace().collect();
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        Some((utime, stime))
    }

    fn measure_bpf_cpu(&self) -> f32 {
        0.0
    }

    pub fn state(&self) -> GovernorState {
        self.state.read().clone()
    }

    pub fn set_ring_buffer_pct(&self, pct: u32) {
        self.ring_buffer_pct.store(pct, Ordering::Relaxed);
    }

    pub fn is_sampling_enabled(&self) -> bool {
        *self.sampling_enabled.read()
    }

    pub fn is_dpi_fast_mode(&self) -> bool {
        *self.dpi_fast_mode.read()
    }

    pub fn daemon_cpu_pct(&self) -> f32 {
        self.daemon_cpu.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn bpf_cpu_pct(&self) -> f32 {
        self.bpf_cpu.load(Ordering::Relaxed) as f32 / 100.0
    }
}
