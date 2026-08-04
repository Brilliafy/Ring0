use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use lru_cache::LruCache;
use parking_lot::RwLock;
use tracing::{info, warn};

const MAX_RDNS_CACHE: usize = 10000;
const RDNS_CACHE_TTL_SECS: u64 = 3600;
const GEO_DB_PATH: &str = "/usr/share/GeoIP/GeoLite2-Country.mmdb";

pub struct EnrichmentEngine {
    geo_reader: Option<maxminddb::Reader<Vec<u8>>>,
    rdns_cache: Arc<RwLock<LruCache<u32, RdnsEntry>>>,
    resolver: Option<tokio::sync::Mutex<hickory_resolver::TokioResolver>>,
}

struct RdnsEntry {
    hostname: String,
    cached_at: Instant,
}

impl EnrichmentEngine {
    pub fn new() -> Self {
        let geo_reader = match maxminddb::Reader::open_readfile(GEO_DB_PATH) {
            Ok(reader) => {
                info!("Enrichment: GeoIP database loaded from {GEO_DB_PATH}");
                Some(reader)
            }
            Err(e) => {
                warn!("Enrichment: GeoIP database not found at {GEO_DB_PATH}: {e}");
                None
            }
        };

        let resolver = match hickory_resolver::TokioResolver::builder_tokio() {
            Ok(builder) => match builder.build() {
                Ok(r) => Some(tokio::sync::Mutex::new(r)),
                Err(e) => {
                    warn!("Enrichment: DNS resolver build failed: {e}");
                    None
                }
            },
            Err(e) => {
                warn!("Enrichment: DNS resolver init failed: {e}");
                None
            }
        };

        Self {
            geo_reader,
            rdns_cache: Arc::new(RwLock::new(LruCache::new(MAX_RDNS_CACHE))),
            resolver,
        }
    }

    pub fn lookup_country(&self, ip: u32) -> (String, String) {
        let ip_addr = IpAddr::V4(std::net::Ipv4Addr::from(ip));
        match &self.geo_reader {
            Some(reader) => match reader.lookup(ip_addr) {
                Ok(result) => match result.decode::<maxminddb::geoip2::Country>() {
                    Ok(Some(country)) => {
                        let code = country.country.iso_code.unwrap_or("XX").to_string();
                        let name = country
                            .country
                            .names
                            .english
                            .unwrap_or("Unknown")
                            .to_string();
                        (code, name)
                    }
                    _ => ("XX".into(), "Unknown".into()),
                },
                Err(_) => ("XX".into(), "Unknown".into()),
            },
            None => ("XX".into(), "Unknown".into()),
        }
    }

    pub async fn lookup_rdns(&self, ip: u32) -> String {
        let ip_addr = std::net::Ipv4Addr::from(ip);
        let ip_u32 = ip;

        {
            let mut cache = self.rdns_cache.write();
            if let Some(entry) = cache.get_mut(&ip_u32) {
                if entry.cached_at.elapsed().as_secs() < RDNS_CACHE_TTL_SECS {
                    return entry.hostname.clone();
                }
            }
        }

        let hostname = match &self.resolver {
            Some(resolver) => {
                let resolver = resolver.lock().await;
                match resolver.reverse_lookup(ip_addr).await {
                    Ok(lookup) => lookup
                        .answers()
                        .iter()
                        .next()
                        .map(|n| n.to_string().trim_end_matches('.').to_string())
                        .unwrap_or_else(|| ip_addr.to_string()),
                    Err(_) => ip_addr.to_string(),
                }
            }
            None => ip_addr.to_string(),
        };

        let mut cache = self.rdns_cache.write();
        cache.insert(
            ip_u32,
            RdnsEntry {
                hostname: hostname.clone(),
                cached_at: Instant::now(),
            },
        );

        hostname
    }

    pub fn cache_size(&self) -> usize {
        self.rdns_cache.read().len()
    }

    pub fn is_geo_loaded(&self) -> bool {
        self.geo_reader.is_some()
    }
}
