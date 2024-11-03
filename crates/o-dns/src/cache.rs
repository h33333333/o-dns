use std::{collections::HashMap, time::Instant};

use anyhow::Context;
use bitflags::bitflags;
use o_dns_lib::{DnsPacket, QueryType, Question, ResourceData, ResourceRecord};
use sha1::Digest as _;

use crate::util::{get_caching_duration_for_packet, get_dns_query_hash, is_dnssec_qtype};

#[derive(Default)]
pub struct Cache {
    query_cache: HashMap<u128, CachedQuery>,
    rr_cache: HashMap<u128, CachedRecord>,
}

impl Cache {
    pub fn new() -> Self {
        Default::default()
    }

    // TODO: add redis-like cache cleanup routine OR just offload this logic to Redis entirely
    pub fn cache_response(&mut self, response: &DnsPacket<'static>) -> anyhow::Result<()> {
        let cache_for = get_caching_duration_for_packet(response);

        if cache_for < 15 {
            // TODO: this may need to be revisited later
            // No point in caching packets with TTL lower than 15s IMO
            return Ok(());
        }

        let mut cached_query = CachedQuery::new(response, cache_for);
        let sections = [
            (&response.answers, &mut cached_query.answers),
            (&response.authorities, &mut cached_query.authorities),
            (&response.additionals, &mut cached_query.additionals),
        ];

        sections
            .into_iter()
            .for_each(|(response_section, cached_section)| {
                response_section.iter().for_each(|rr| {
                    // Don't cache OPT RRs
                    if rr.resource_data.get_query_type() != QueryType::OPT {
                        let cached_rr = CachedRecord::new(rr.clone(), response.header.z[1]);
                        let hash = cached_rr.get_hash();
                        cached_section.get_or_insert_with(|| Vec::new()).push(hash);
                        self.rr_cache.insert(hash, cached_rr);
                    }
                });
            });

        let hash = get_dns_query_hash(
            response
                .questions
                .get(0)
                .context("malformed response packet: question is missing")?,
        );

        self.query_cache.insert(hash, cached_query);

        Ok(())
    }

    pub fn question_lookup(
        &self,
        question: &Question,
        response_packet: &mut DnsPacket,
        dnssec: bool,
    ) -> bool {
        let hash = get_dns_query_hash(question);
        let Some(cached_query) = self.query_cache.get(&hash) else {
            tracing::debug!(
                qname = ?question.qname,
                qtype = ?question.query_type,
                "Cache miss"
            );
            return false;
        };

        if (cached_query.added.elapsed().as_secs() as u32) >= cached_query.ttd {
            tracing::debug!(
                qname = ?question.qname,
                qtype = ?question.query_type,
                "Found entry in cache, but it's stale. Doing a lookup"
            );
            return false;
        }

        if dnssec && !cached_query.flags.contains(CacheFlags::DNSSEC) {
            tracing::debug!(
                qname = ?question.qname,
                qtype = ?question.query_type,
                "Found entry in cache, but it's missing DNSSEC. Doing a lookup with DNSSEC"
            );
            return false;
        }

        tracing::debug!(
            qname = ?question.qname,
            qtype = ?question.query_type,
            remaining_time = (cached_query.ttd.saturating_sub(cached_query.added.elapsed().as_secs() as u32)),
            "Found cached query"
        );

        // Check whether other queries didn't override authenticated data that we need
        let require_ad = cached_query.flags.contains(CacheFlags::AD);
        response_packet.header.z[1] = require_ad;
        let include_dnssec_rrs = dnssec || is_dnssec_qtype(question.query_type.into());

        // Process each section
        let sections = [
            (
                &cached_query.answers,
                &mut response_packet.answers,
                &mut response_packet.header.answer_rr_count,
            ),
            (
                &cached_query.authorities,
                &mut response_packet.authorities,
                &mut response_packet.header.authority_rr_count,
            ),
            (
                &cached_query.additionals,
                &mut response_packet.additionals,
                &mut response_packet.header.additional_rr_count,
            ),
        ];

        for (cached_section, response_section, count) in sections {
            if let Some(records) = cached_section {
                for rr_hash in records.iter() {
                    let Some(cached_rr) = self.rr_cache.get(rr_hash) else {
                        tracing::debug!(
                            qname = ?question.qname,
                            qtype = ?question.query_type,
                            rr_hash,
                            "RR is missing. Doing a lookup"
                        );
                        return false;
                    };

                    if !include_dnssec_rrs
                        && is_dnssec_qtype(cached_rr.resource_data.get_query_type().into())
                    {
                        continue;
                    }

                    if require_ad && !cached_rr.flags.contains(CacheFlags::AD) {
                        tracing::debug!(
                            qname = ?cached_rr.qname,
                            qtype = ?cached_rr.resource_data.get_query_type(),
                            "DNSSEC-validated RR was overridden. Doing a lookup"
                        );
                        return false;
                    }

                    response_section.push(cached_rr.into_rr());
                    *count += 1;
                }
            }
        }

        true
    }
}

bitflags! {
    struct CacheFlags: u8 {
        const AD = 1;
        const DNSSEC = 1 << 1;
    }
}

struct CachedRecord {
    qname: String,
    resource_data: ResourceData<'static>,
    ttl: u32,
    class: u16,
    flags: CacheFlags,
    added: Instant,
}

impl CachedRecord {
    fn new(value: ResourceRecord<'static>, authenticated_data: bool) -> Self {
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

    fn get_hash(&self) -> u128 {
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
            ResourceData::AAAA { address } => hasher.update(&address.octets()),
            ResourceData::OPT { .. } => unreachable!("bug: we shouldn't cache OPT RRs"),
        };

        let hash = hasher.finalize();

        u128::from_be_bytes(hash[..16].try_into().unwrap())
    }

    fn into_rr(&self) -> ResourceRecord<'static> {
        let ttl = self
            .ttl
            .saturating_sub(self.added.elapsed().as_secs() as u32);
        ResourceRecord::new(
            self.qname.to_owned().into(),
            self.resource_data.clone(),
            Some(ttl),
            Some(self.class),
        )
    }
}

struct CachedQuery {
    answers: Option<Vec<u128>>,
    authorities: Option<Vec<u128>>,
    additionals: Option<Vec<u128>>,
    flags: CacheFlags,
    added: Instant,
    ttd: u32,
}

impl CachedQuery {
    fn new(response_packet: &DnsPacket<'_>, ttd: u32) -> Self {
        let mut flags = CacheFlags::empty();
        flags.set(CacheFlags::AD, response_packet.header.z[1]);

        if let Some(edns_data) = response_packet.edns.and_then(|idx| {
            response_packet
                .additionals
                .get(idx)
                .and_then(|rr| rr.get_edns_data())
        }) {
            flags.set(CacheFlags::DNSSEC, edns_data.dnssec_ok_bit);
        }

        CachedQuery {
            answers: None,
            authorities: None,
            additionals: None,
            flags,
            added: Instant::now(),
            ttd,
        }
    }
}
