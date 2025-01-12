mod cached_query;
mod cached_record;

use anyhow::Context;
use cached_query::CachedQuery;
use cached_record::{CacheFlags, CachedRecord};
use hashlink::LinkedHashMap;
use o_dns_lib::{DnsPacket, QueryType, Question};

use crate::util::{get_caching_duration_for_packet, get_dns_query_hash, is_dnssec_qtype};

const DEFAULT_CACHE_CAPACITY: usize = 1000;

pub struct Cache {
    query_cache: LinkedHashMap<u128, CachedQuery>,
    rr_cache: LinkedHashMap<u128, CachedRecord>,
}

impl Cache {
    pub fn with_capacity(capacity: usize) -> Self {
        Cache {
            query_cache: LinkedHashMap::with_capacity(capacity),
            rr_cache: LinkedHashMap::with_capacity(capacity),
        }
    }

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

        sections.into_iter().for_each(|(response_section, cached_section)| {
            response_section.iter().for_each(|rr| {
                // Don't cache OPT RRs
                if rr.resource_data.get_query_type() != QueryType::OPT {
                    let cached_rr = CachedRecord::new(rr.clone(), response.header.z[1]);
                    let hash = cached_rr.get_hash();
                    cached_section.get_or_insert(Vec::new()).push(hash);
                    self.rr_cache.insert(hash, cached_rr);
                }
            });
        });

        let hash = get_dns_query_hash(
            response
                .questions
                .first()
                .context("malformed response packet: question is missing")?,
        );

        self.query_cache.insert(hash, cached_query);

        Ok(())
    }

    pub fn question_lookup(&self, question: &Question, response_packet: &mut DnsPacket, dnssec: bool) -> bool {
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
            "Cache hit"
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

                    if !include_dnssec_rrs && is_dnssec_qtype(cached_rr.resource_data.get_query_type().into()) {
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

                    response_section.push(cached_rr.as_rr());
                    *count += 1;
                }
            }
        }

        true
    }
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            query_cache: LinkedHashMap::with_capacity(DEFAULT_CACHE_CAPACITY),
            rr_cache: LinkedHashMap::with_capacity(DEFAULT_CACHE_CAPACITY),
        }
    }
}
