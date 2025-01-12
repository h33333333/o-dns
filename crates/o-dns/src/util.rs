use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use o_dns_lib::{DnsPacket, QueryType, Question, ResourceData, ResourceRecord, ResponseCode};
use sha1::Digest;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};

use crate::{DEFAULT_EDNS_BUF_CAPACITY, EDNS_DO_BIT};

pub fn get_response_dns_packet(
    request_packet: Option<&DnsPacket>,
    response_code: Option<ResponseCode>,
) -> DnsPacket<'static> {
    let mut packet = DnsPacket::new();
    packet.header.is_response = true;
    packet.header.recursion_available = true;
    if let Some(request_packet) = request_packet {
        packet.header.id = request_packet.header.id;
        packet.header.recursion_desired = request_packet.header.recursion_desired;
        // CD bit
        packet.header.z[2] = request_packet.header.z[2];
        // Include OPT RR if requestor supports EDNS
        if let Some(edns_data) = request_packet
            .edns
            .and_then(|idx| request_packet.additionals.get(idx).and_then(|rr| rr.get_edns_data()))
        {
            let flags = edns_data.dnssec_ok_bit.then_some(EDNS_DO_BIT);
            packet
                .additionals
                .push(get_edns_rr(DEFAULT_EDNS_BUF_CAPACITY as u16, None, flags));
            packet.header.additional_rr_count += 1;
            packet.edns = Some(0);
        }
    };
    if let Some(rcode) = response_code {
        packet.header.response_code = rcode;
    }
    packet
}

pub fn get_query_dns_packet(id: Option<u16>, enable_dnssec: bool) -> DnsPacket<'static> {
    let mut packet = DnsPacket::new();
    packet.header.id = id.unwrap_or_default();
    packet.header.recursion_desired = true;
    // AD bit
    packet.header.z[1] = true;
    // EDNS
    let flags = enable_dnssec.then_some(EDNS_DO_BIT);
    packet
        .additionals
        .push(get_edns_rr(DEFAULT_EDNS_BUF_CAPACITY as u16, None, flags));
    packet.header.additional_rr_count += 1;
    packet.edns = Some(0);
    packet
}

pub fn get_edns_rr(buf_size: u16, options: Option<HashMap<u16, Cow<'_, [u8]>>>, flags: Option<u32>) -> ResourceRecord {
    ResourceRecord::new("".into(), ResourceData::OPT { options }, flags, Some(buf_size))
}

pub fn get_dns_query_hash(question: &Question) -> u128 {
    let mut hasher = sha1::Sha1::new();

    // Hash the question itself
    hasher.update(question.qname.as_bytes());
    hasher.update(Into::<u16>::into(question.query_type).to_be_bytes());
    hasher.update(question.qclass.to_be_bytes());

    let hash = hasher.finalize();
    // Reduce the output hash to first 16 bytes in order to fit it into a single u128
    // NOTE: it increases chances of hash collissions, but it shouldn't affect this server in any meaningful way
    // It's still worth looking into fixing this at some point in the future though
    u128::from_be_bytes(hash[..16].try_into().unwrap())
}

pub fn hash_to_u128(data: impl AsRef<[u8]>, prefix: Option<&[u8]>) -> u128 {
    let mut hasher = sha1::Sha1::new();

    prefix.into_iter().for_each(|prefix| hasher.update(prefix));
    hasher.update(data);

    let hash = hasher.finalize();
    u128::from_be_bytes(hash[..16].try_into().unwrap())
}

// TODO: add these RRs to o-dns-lib?
pub fn is_dnssec_qtype(qtype: u16) -> bool {
    match qtype {
        // DS | RRSIG | NSEC | DNSKEY | NSEC3
        43 | 46 | 47 | 48 | 50 => true,
        _ => false,
    }
}

pub fn get_caching_duration_for_packet(packet: &DnsPacket<'_>) -> u32 {
    match packet.header.response_code {
        // Cache for the lowest TTL from all response RRs OR for 5 minutes
        ResponseCode::Success => get_minimum_ttl_for_packet(packet).unwrap_or(60 * 5),
        // TODO: cache NXDOMAIN for SOA TTL (or 1 min if SOA is missing)
        ResponseCode::Refused | ResponseCode::NameError => 60, // Cache for 1 min
        ResponseCode::ServerFailure => 30,                     // Cache for 30s
        ResponseCode::NotImplemented => 60 * 5,                // Cache for 5 min
        ResponseCode::FormatError | ResponseCode::Unknown => 0, // Don't cache these responses
    }
}

pub fn get_minimum_ttl_for_packet(packet: &DnsPacket<'_>) -> Option<u32> {
    packet
        .answers
        .iter()
        .chain(packet.authorities.iter())
        .chain(packet.additionals.iter())
        .filter(|rr| rr.resource_data.get_query_type() != QueryType::OPT)
        .map(|rr| rr.ttl)
        .min()
}

pub async fn read_checksum(path: impl AsRef<Path>) -> anyhow::Result<Option<[u8; 20]>> {
    let mut checksum_buf = [0; 20];

    let mut checksum_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(path)
        .await
        .context("failed to open the checksum file")?;

    let read = checksum_file
        .read(&mut checksum_buf)
        .await
        .context("failed to read the checksum")?;

    if read == 0 {
        Ok(None)
    } else {
        Ok(Some(checksum_buf))
    }
}

pub async fn write_to_file(path: impl AsRef<Path>, data: &[u8]) -> anyhow::Result<()> {
    let mut checksum_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .await
        .context("failed open the file")?;

    checksum_file.write_all(data).await.context("failed to write the data")
}
