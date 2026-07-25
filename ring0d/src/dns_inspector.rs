use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{info, warn};

const DNS_HEADER_SIZE: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub questions: Vec<DnsQuery>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_str: String,
}

pub struct DnsInspector {
    blacklist: Arc<RwLock<HashMap<String, u32>>>,
}

impl DnsInspector {
    pub fn new() -> Self {
        Self {
            blacklist: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn parse_dns_query(data: &[u8]) -> Option<DnsQuery> {
        if data.len() < DNS_HEADER_SIZE + 5 {
            return None;
        }
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount == 0 {
            return None;
        }
        let mut offset = DNS_HEADER_SIZE;
        let qname = Self::decode_name(data, &mut offset)?;
        if offset + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        Some(DnsQuery {
            transaction_id,
            qname,
            qtype,
            qclass,
        })
    }

    pub fn parse_dns_response(data: &[u8]) -> Option<DnsResponse> {
        if data.len() < DNS_HEADER_SIZE {
            return None;
        }
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);

        let mut offset = DNS_HEADER_SIZE;
        let mut questions = Vec::new();
        for _ in 0..qdcount {
            let qname = Self::decode_name(data, &mut offset)?;
            if offset + 4 > data.len() {
                return None;
            }
            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            questions.push(DnsQuery {
                transaction_id,
                qname,
                qtype,
                qclass,
            });
            offset += 4;
        }

        let total_records = ancount + nscount;
        let mut answers = Vec::new();
        for _ in 0..total_records {
            let record = Self::parse_record(data, &mut offset)?;
            if record.rtype == TYPE_CNAME {
                info!(
                    "DnsInspector: CNAME uncloak {} -> {}",
                    record.name, record.rdata_str
                );
            }
            answers.push(record);
        }

        Some(DnsResponse {
            transaction_id,
            questions,
            answers,
            authorities: Vec::new(),
        })
    }

    fn decode_name(data: &[u8], offset: &mut usize) -> Option<String> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut pos = *offset;
        let orig_offset = *offset;

        loop {
            if pos >= data.len() {
                return None;
            }
            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 2 > data.len() {
                    return None;
                }
                let ptr = ((len & 0x3F) << 8) | data[pos + 1] as usize;
                if !jumped {
                    *offset = pos + 2;
                }
                pos = ptr;
                jumped = true;
                continue;
            }
            pos += 1;
            if pos + len > data.len() {
                return None;
            }
            if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
                labels.push(label.to_string());
            }
            pos += len;
        }
        if !jumped {
            *offset = pos;
        }
        Some(labels.join("."))
    }

    fn parse_record(data: &[u8], offset: &mut usize) -> Option<DnsRecord> {
        let name = Self::decode_name(data, offset)?;
        if *offset + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
        let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]) as usize;
        *offset += 10;
        if *offset + rdlength > data.len() {
            return None;
        }
        let rdata = data[*offset..*offset + rdlength].to_vec();
        let rdata_str = match rtype {
            TYPE_A if rdlength >= 4 => {
                format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
            }
            TYPE_CNAME => {
                let mut cname_off = 0;
                Self::decode_name(&rdata, &mut cname_off).unwrap_or_default()
            }
            _ => hex::encode(&rdata),
        };
        *offset += rdlength;
        Some(DnsRecord {
            name,
            rtype,
            ttl,
            rdata,
            rdata_str,
        })
    }

    pub fn update_blacklist(&self, domains: Vec<String>) {
        let mut bl = self.blacklist.write();
        bl.clear();
        for d in domains {
            bl.insert(d.to_lowercase(), 1);
        }
        info!("DnsInspector: loaded {} blacklisted domains", bl.len());
    }

    pub fn check_domain(&self, domain: &str) -> Option<u32> {
        let lower = domain.to_lowercase();
        let bl = self.blacklist.read();
        if bl.contains_key(&lower) {
            return Some(1);
        }
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len() {
            let wild = parts[i..].join(".");
            if bl.contains_key(&wild) {
                return Some(2);
            }
        }
        None
    }

    pub fn extract_cname_chain(response: &DnsResponse) -> Vec<String> {
        let mut chain = Vec::new();
        for r in &response.answers {
            if r.rtype == TYPE_CNAME {
                chain.push(format!("{} -> {}", r.name, r.rdata_str));
            }
        }
        chain
    }

    pub fn blacklist_size(&self) -> usize {
        self.blacklist.read().len()
    }
}
