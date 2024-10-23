use std::{collections::HashMap, time::Instant};

use o_dns_lib::{ResourceData, ResourceRecord};

pub enum Kind {
    Answer,
    Authority,
    Additional,
}

pub enum Source {
    Local,
    Upstream,
}

pub struct CacheEntry {
    resource_data: ResourceData<'static>,
    ttl: u32,
    added: Instant,
    kind: Kind,
    source: Source,
}

impl CacheEntry {
    pub fn new(value: ResourceRecord<'static>, kind: Kind, source: Source) -> Self {
        CacheEntry {
            resource_data: value.resource_data,
            ttl: value.ttl,
            added: Instant::now(),
            kind,
            source,
        }
    }

    pub fn into_rr_with_qname<'s>(&self, qname: &'s str) -> ResourceRecord<'s> {
        let ttl = self
            .ttl
            .saturating_sub(self.added.elapsed().as_secs() as u32);
        ResourceRecord::new(qname, self.resource_data.clone(), Some(ttl), None)
    }
}

#[derive(Default)]
pub struct Cache {
    internal: HashMap<String, Vec<CacheEntry>>,
}

impl Cache {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set(&mut self, key: String, value: ResourceRecord<'static>, kind: Kind, source: Source) {
        let cache = self.internal.entry(key).or_default();
        cache.push(CacheEntry::new(value, kind, source));
    }

    pub fn get(&self, key: &str) -> Option<&[CacheEntry]> {
        self.internal.get(key).map(|cached| cached.as_slice())
    }

    pub fn contains(&self, key: &str) -> bool {
        self.internal.contains_key(key)
    }
}
