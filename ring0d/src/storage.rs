use anyhow::{Context, Result};
use rocksdb::{
    BlockBasedOptions, ColumnFamilyDescriptor, Direction, IteratorMode, Options, ReadOptions, DB,
};
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct RocksManager {
    db: Arc<DB>,
}

impl RocksManager {
    pub fn open(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        opts.set_write_buffer_size(64 * 1024 * 1024);
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

        info!("RocksDB opened at {path}");
        Ok(Self { db: Arc::new(db) })
    }

    pub fn write_raw(&self, data: &[u8]) {
        let ts = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_be_bytes();
        let mut key = Vec::with_capacity(8);
        key.extend_from_slice(&ts);
        if let Some(cf) = self.db.cf_handle("events") {
            if let Err(e) = self.db.put_cf(&cf, key, data) {
                error!("RocksDB write to 'events' failed: {e}");
            }
        }
    }

    pub fn write_alert(&self, data: &[u8]) {
        let ts = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_be_bytes();
        let mut key = Vec::with_capacity(8);
        key.extend_from_slice(&ts);
        if let Some(cf) = self.db.cf_handle("alerts") {
            if let Err(e) = self.db.put_cf(&cf, key, data) {
                error!("RocksDB write to 'alerts' failed: {e}");
            }
        }
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
        let cf = match self.db.cf_handle("alerts") {
            Some(cf) => cf,
            None => {
                warn!("RocksDB column family 'alerts' not found");
                return Vec::new();
            }
        };
        let iter = self.db.iterator_cf(&cf, IteratorMode::End);
        iter.take(limit.saturating_mul(2))
            .filter_map(|r| {
                r.map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .map_err(|e| warn!("RocksDB alert iteration error: {e}"))
                    .ok()
            })
            .filter(|(_, v)| {
                // Alert byte layout: [0..8] timestamp (BE), [8] severity,
                // [9..13] rule id, [13] message length, [14..] message.
                v.len() > 8 && v[8] >= severity_threshold
            })
            .take(limit)
            .collect()
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
        self.flush();
    }
}
