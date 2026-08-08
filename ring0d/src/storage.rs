use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;

use anyhow::{Context, Result};
use rocksdb::{
    BlockBasedOptions, ColumnFamilyDescriptor, Direction, IteratorMode, Options, ReadOptions, DB,
};
use tracing::{error, info, warn};

/// Bounded queue depth for async event/alert writes. Bounded so an alert storm
/// cannot grow memory without limit; excess writes are counted (see
/// [`RocksManager::dropped_count`]) instead of silently vanishing.
const WRITE_QUEUE_DEPTH: usize = 16384;

const WRITE_RAW: u8 = 0;
const WRITE_ALERT: u8 = 1;

/// Periodic drop-reporting threshold.
const DROP_REPORT_INTERVAL: u64 = 1000;

pub struct RocksManager {
    db: Arc<DB>,
    write_tx: Option<SyncSender<(u8, Vec<u8>)>>,
    writer: Option<std::thread::JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
}

impl RocksManager {
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // 16 MB memtable (was 64 MB x 4 = up to 256 MB in-process): with raw
        // events no longer persisted, this bounds the alerts-CF footprint.
        opts.set_write_buffer_size(16 * 1024 * 1024);
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_max_bytes_for_level_base(512 * 1024 * 1024);
        opts.set_level_zero_file_num_compaction_trigger(4);

        opts.set_wal_size_limit_mb(1024);
        opts.set_wal_ttl_seconds(3600);

        let mut bb_opts = BlockBasedOptions::default();
        bb_opts.set_block_size(16 * 1024);
        bb_opts.set_cache_index_and_filter_blocks(true);
        bb_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        opts.set_block_based_table_factory(&bb_opts);

        opts.increase_parallelism(num_cpus::get() as i32);

        let cfs = vec![
            ColumnFamilyDescriptor::new("events", Options::default()),
            ColumnFamilyDescriptor::new("alerts", Options::default()),
            ColumnFamilyDescriptor::new("metrics", Options::default()),
            ColumnFamilyDescriptor::new("baseline", Options::default()),
            ColumnFamilyDescriptor::new("fim_baseline", Options::default()),
            ColumnFamilyDescriptor::new("intel", Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .with_context(|| format!("failed to open RocksDB at {path}"))?;
        let db = Arc::new(db);

        // Background writer: event/alert writes are queued and drained on a
        // dedicated thread instead of blocking the async event loop with a
        // synchronous RocksDB put + WAL fsync per event.
        let (write_tx, write_rx) = sync_channel::<(u8, Vec<u8>)>(WRITE_QUEUE_DEPTH);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_db = db.clone();
        let writer_dropped = dropped.clone();
        let writer = std::thread::Builder::new()
            .name("ring0-storage-writer".into())
            .spawn(move || {
                Self::writer_loop(writer_db, write_rx, writer_dropped);
            })
            .map_err(|e| anyhow::anyhow!("failed to spawn storage writer: {e}"))?;

        info!("RocksDB opened at {path}");
        Ok(Self {
            db,
            write_tx: Some(write_tx),
            writer: Some(writer),
            dropped,
        })
    }

    fn writer_loop(db: Arc<DB>, rx: Receiver<(u8, Vec<u8>)>, dropped: Arc<AtomicU64>) {
        use std::time::{Duration, Instant};
        // Batched writes: each event previously became its own RocksDB Put
        // (one WAL append + memtable insert + write-amplification on flush).
        // Under an event flood that multiplied into disk saturation. Grouping
        // into WriteBatches (flush every 50 ms or 512 items) makes the disk
        // cost ~1 WAL append per batch instead of per event.
        const BATCH_MAX_ITEMS: usize = 512;
        const BATCH_MAX_LATENCY: Duration = Duration::from_millis(50);

        let ev_cf = db
            .cf_handle("events")
            .expect("RocksDB events column family missing");
        let al_cf = db
            .cf_handle("alerts")
            .expect("RocksDB alerts column family missing");

        // Strictly increasing key base: two events written within the same
        // nanosecond previously got identical keys (a silent overwrite). The
        // writer is the only key assigner, so a plain counter is safe.
        let mut last_key: u64 = 0;
        let mut dropped_at_last_report = 0u64;
        loop {
            let mut batch = rocksdb::WriteBatch::default();
            let mut n = 0usize;
            let mut disconnected = false;
            let deadline = Instant::now() + BATCH_MAX_LATENCY;
            // Block on the first item (no polling), then drain up to the batch
            // cap or until the latency budget expires.
            while n < BATCH_MAX_ITEMS {
                let item = if n == 0 {
                    match rx.recv() {
                        Ok(i) => i,
                        Err(_) => {
                            disconnected = true;
                            break;
                        }
                    }
                } else {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(remaining) {
                        Ok(i) => i,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            disconnected = true;
                            break;
                        }
                    }
                };
                let (kind, data) = item;
                let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
                let key = now.max(last_key + 1);
                last_key = key;
                let cf = if kind == WRITE_ALERT { al_cf } else { ev_cf };
                batch.put_cf(cf, key.to_be_bytes(), data);
                n += 1;
            }
            if n > 0 {
                if let Err(e) = db.write(batch) {
                    error!("RocksDB batch write ({n} events) failed: {e}");
                }
            }
            let dropped_now = dropped.load(Ordering::Relaxed);
            if dropped_now > 0 && dropped_now - dropped_at_last_report >= DROP_REPORT_INTERVAL {
                dropped_at_last_report = dropped_now;
                warn!(
                    "RocksDB write queue overflowed — {dropped_now} events dropped (storage backpressure)"
                );
            }
            if disconnected {
                return;
            }
        }
    }

    /// Non-blocking enqueue of a raw event record. Never blocks the caller;
    /// when the queue is full the write is counted as dropped.
    ///
    /// DISABLED BY DEFAULT: raw events (packet/exec/connect) are persisted to
    /// the `events` column family, but nothing ever reads them (query_events
    /// has no callers — the GUI/CLI query alerts). Writing them saturates the
    /// RocksDB memtable (64 MB x 4 buffers) on slow disks, which looked like a
    /// memory leak (steady RSS growth at the event-write rate) and hammered
    /// the disk. Set RING0_EVENT_LOG=1 to persist raw events again.
    pub fn write_raw(&self, data: &[u8]) {
        static EVENT_LOG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if !*EVENT_LOG_ENABLED
            .get_or_init(|| std::env::var("RING0_EVENT_LOG").as_deref() == Ok("1"))
        {
            return;
        }
        match self
            .write_tx
            .as_ref()
            .and_then(|tx| tx.try_send((WRITE_RAW, data.to_vec())).ok())
        {
            Some(()) => {}
            None => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Non-blocking enqueue of an alert record (see also [`write_raw`]).
    pub fn write_alert(&self, data: &[u8]) {
        match self
            .write_tx
            .as_ref()
            .and_then(|tx| tx.try_send((WRITE_ALERT, data.to_vec())).ok())
        {
            Some(()) => {}
            None => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Number of writes dropped due to queue overflow (exposed in status so
    /// event loss is observable instead of silent).
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn query_events(
        &self,
        start_timestamp: u64,
        end_timestamp: u64,
        limit: usize,
    ) -> Vec<Vec<u8>> {
        let cf = match self.db.cf_handle("events") {
            Some(cf) => cf,
            None => {
                warn!("RocksDB column family 'events' not found");
                return Vec::new();
            }
        };
        let start_key = start_timestamp.to_be_bytes();
        let end_key = end_timestamp.to_be_bytes();
        let mut ro = ReadOptions::default();
        ro.set_iterate_lower_bound(start_key.as_slice());
        ro.set_iterate_upper_bound(end_key.as_slice());

        let iter = self.db.iterator_cf_opt(
            &cf,
            ro,
            IteratorMode::From(start_key.as_slice(), Direction::Forward),
        );

        iter.take(limit)
            .filter_map(|r| {
                r.map(|(_, v)| v.to_vec())
                    .map_err(|e| warn!("RocksDB event iteration error: {e}"))
                    .ok()
            })
            .collect()
    }

    pub fn query_alerts(&self, severity_threshold: u8, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        // F3 defense in depth: even if a caller bypasses the IPC clamp, never
        // iterate/collect more than a hard cap (a u32::MAX limit used to force
        // a full-table scan + unbounded collection on the root daemon).
        const MAX_ALERT_SCAN: usize = 5000;
        let limit = limit.min(MAX_ALERT_SCAN);
        let cf = match self.db.cf_handle("alerts") {
            Some(cf) => cf,
            None => {
                warn!("RocksDB column family 'alerts' not found");
                return Vec::new();
            }
        };
        let iter = self.db.iterator_cf(&cf, IteratorMode::End);
        let mut out = Vec::with_capacity(limit);
        for r in iter {
            let (k, v) = match r {
                Ok(kv) => kv,
                Err(e) => {
                    warn!("RocksDB alert iteration error: {e}");
                    break;
                }
            };
            // Canonical alert layout lives in crate::alert; decode centrally
            // so a format change cannot silently corrupt the filter.
            if crate::alert::AlertRecord::decode(&v)
                .map(|r| r.severity >= severity_threshold)
                .unwrap_or(false)
            {
                out.push((k.to_vec(), v.to_vec()));
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    pub fn inner_db(&self) -> Arc<DB> {
        self.db.clone()
    }

    pub fn flush(&self) {
        if let Err(e) = self.db.flush_wal(true) {
            error!("RocksDB WAL flush failed: {e}");
        }
        if let Err(e) = self.db.flush() {
            error!("RocksDB flush failed: {e}");
        }
    }
}

impl Drop for RocksManager {
    fn drop(&mut self) {
        // Close the queue and join the writer so queued writes land before the
        // final flush — otherwise a shutdown could lose the tail of the queue.
        drop(self.write_tx.take());
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
        self.flush();
    }
}
