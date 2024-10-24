use std::{collections::HashMap, time::Instant};

use o_dns_lib::{QueryType, ResourceData, ResourceRecord};

pub enum CacheRecordKind {
    Answer,
    Authority,
    Additional,
}

pub struct CachedRecord {
    pub resource_data: ResourceData<'static>,
    pub qname: String,
    pub ttl: u32,
    pub kind: CacheRecordKind,
}

pub struct CacheEntry {
    pub records: Vec<CachedRecord>,
    pub added: Instant,
    pub ttd: u32,
}

impl CachedRecord {
    pub fn new(value: ResourceRecord<'static>, kind: CacheRecordKind) -> Self {
        CachedRecord {
            qname: value.name.into_owned(),
            resource_data: value.resource_data,
            ttl: value.ttl,
            kind,
        }
    }

    pub fn into_rr(&self, added: &Instant) -> ResourceRecord<'static> {
        let ttl = match self.resource_data.get_query_type() {
            QueryType::OPT => self.ttl,
            _ => self.ttl.saturating_sub(added.elapsed().as_secs() as u32),
        };
        ResourceRecord::new(
            self.qname.to_owned().into(),
            self.resource_data.clone(),
            Some(ttl),
            None,
        )
    }
}

#[derive(Default)]
pub struct Cache {
    internal: HashMap<u128, CacheEntry>,
}

impl Cache {
    pub fn new() -> Self {
        Default::default()
    }

    // TODO: I also need to cache the source of the response (for AA flag)
    pub fn set(&mut self, key: u128, value: CachedRecord, cache_for: u32) {
        let cache = self.internal.entry(key).or_insert_with(|| CacheEntry {
            records: vec![],
            ttd: cache_for,
            added: Instant::now(),
        });
        cache.records.push(value);
    }

    pub fn set_empty(&mut self, key: u128, cache_for: u32) {
        self.internal.insert(
            key,
            CacheEntry {
                records: vec![],
                ttd: cache_for,
                added: Instant::now(),
            },
        );
    }

    pub fn get(&self, key: &u128) -> Option<&CacheEntry> {
        self.internal.get(key)
    }

    pub fn contains(&self, key: &u128) -> bool {
        self.internal.contains_key(key)
    }
}
