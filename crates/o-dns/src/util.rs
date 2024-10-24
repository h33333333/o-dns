use std::{borrow::Cow, collections::HashMap};

use o_dns_lib::{DnsHeader, DnsPacket, Question, ResourceData, ResourceRecord, ResponseCode};
use sha1::Digest;

pub fn get_empty_dns_packet(
    response_code: Option<ResponseCode>,
    request_header: Option<&DnsHeader>,
    edns_buf_size: Option<usize>,
) -> DnsPacket<'static> {
    let mut packet = DnsPacket::new();
    packet.header.is_response = true;
    packet.header.recursion_available = true;
    if let Some(buf_size) = edns_buf_size {
        packet.additionals.push(get_edns_rr(buf_size as u16, None));
        packet.header.additional_rr_count += 1;
        packet.edns = Some(0);
    }
    if let Some(rcode) = response_code {
        packet.header.response_code = rcode;
    }
    if let Some(header) = request_header {
        packet.header.id = header.id;
        packet.header.recursion_desired = header.recursion_desired;
    }
    packet
}

pub fn get_edns_rr(buf_size: u16, options: Option<HashMap<u16, Cow<'_, [u8]>>>) -> ResourceRecord {
    ResourceRecord::new(
        "".into(),
        ResourceData::OPT { options },
        Some(0),
        Some(buf_size),
    )
}

pub fn get_dns_query_hash(
    header: &DnsHeader,
    question: &Question,
    opt_rr: Option<&ResourceRecord>,
) -> u128 {
    let mut hasher = sha1::Sha1::new();

    // Hash the RD bit as it changes how a query is processed
    hasher.update(&[header.recursion_desired as u8]);
    // Hash the Z->CD bit as it changes how DNSSEC queries are processed
    hasher.update(&[header.z[1] as u8]);

    // Hash the question itself
    hasher.update(question.qname.as_bytes());
    hasher.update(Into::<u16>::into(question.query_type).to_be_bytes());

    // Hash EDNS-related data
    if let Some((edns_data, _)) = opt_rr.and_then(|rr| {
        rr.get_edns_data()
            .map(|edns_data| (edns_data, &rr.resource_data))
    }) {
        hasher.update(&[edns_data.dnssec_ok_bit as u8]);
        // TODO: also hash certain options, as they may change the response?
    }

    let hash = hasher.finalize();
    // Reduce the output hash to first 16 bytes in order to fit it into a single u128
    // NOTE: it increases chances of hash collissions, but it shouldn't affect this server in any meaningful way
    // It's still worth looking into fixing this at some point in the future though
    u128::from_be_bytes(hash[..16].try_into().unwrap())
}
