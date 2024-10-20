use std::{borrow::Cow, collections::HashMap};

use o_dns_lib::{DnsHeader, DnsPacket, ResourceData, ResourceRecord, ResponseCode};

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
    ResourceRecord::new("", ResourceData::OPT { options }, Some(0), Some(buf_size))
}
