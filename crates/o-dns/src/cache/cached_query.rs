use std::time::Instant;

use o_dns_lib::DnsPacket;

use super::cached_record::CacheFlags;

pub(super) struct CachedQuery {
    pub(super) answers: Option<Vec<u128>>,
    pub(super) authorities: Option<Vec<u128>>,
    pub(super) additionals: Option<Vec<u128>>,
    pub(super) flags: CacheFlags,
    pub(super) added: Instant,
    pub(super) ttd: u32,
}

impl CachedQuery {
    pub(super) fn new(response_packet: &DnsPacket<'_>, ttd: u32) -> Self {
        let mut flags = CacheFlags::empty();
        flags.set(CacheFlags::AD, response_packet.header.z[1]);

        if let Some(edns_data) = response_packet
            .edns
            .and_then(|idx| response_packet.additionals.get(idx).and_then(|rr| rr.get_edns_data()))
        {
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
