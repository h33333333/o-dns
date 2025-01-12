use std::time::Instant;

use bitflags::bitflags;
use o_dns_lib::{ResourceData, ResourceRecord};
use sha1::Digest as _;

bitflags! {
    pub(super) struct CacheFlags: u8 {
        const AD = 1;
        const DNSSEC = 1 << 1;
    }
}

pub(super) struct CachedRecord {
    pub(super) qname: String,
    pub(super) resource_data: ResourceData<'static>,
    pub(super) ttl: u32,
    pub(super) class: u16,
    pub(super) flags: CacheFlags,
    pub(super) added: Instant,
}

impl CachedRecord {
    pub(super) fn new(value: ResourceRecord<'static>, authenticated_data: bool) -> Self {
        let mut flags = CacheFlags::empty();
        flags.set(CacheFlags::AD, authenticated_data);
        CachedRecord {
            qname: value.name.into_owned(),
            resource_data: value.resource_data,
            ttl: value.ttl,
            class: value.class,
            flags,
            added: Instant::now(),
        }
    }

    pub(super) fn get_hash(&self) -> u128 {
        let qtype: u16 = self.resource_data.get_query_type().into();

        let mut hasher = sha1::Sha1::new();

        hasher.update(self.qname.as_bytes());
        hasher.update(qtype.to_be_bytes());
        hasher.update(self.class.to_be_bytes());

        // Hash the rdata
        match &self.resource_data {
            ResourceData::UNKNOWN { rdata, .. } => {
                hasher.update(rdata);
            }
            ResourceData::A { address } => {
                hasher.update(address.octets());
            }
            ResourceData::NS { ns_domain_name } => hasher.update(ns_domain_name.as_bytes()),
            ResourceData::CNAME { cname } => hasher.update(cname.as_bytes()),
            ResourceData::AAAA { address } => hasher.update(address.octets()),
            ResourceData::OPT { .. } => unreachable!("bug: we shouldn't cache OPT RRs"),
        };

        let hash = hasher.finalize();

        u128::from_be_bytes(hash[..16].try_into().unwrap())
    }

    pub(super) fn as_rr(&self) -> ResourceRecord<'static> {
        let ttl = self.ttl.saturating_sub(self.added.elapsed().as_secs() as u32);
        ResourceRecord::new(
            self.qname.to_owned().into(),
            self.resource_data.clone(),
            Some(ttl),
            Some(self.class),
        )
    }
}
