use crate::DEFAULT_BUF_CAPACITY;
use o_dns_lib::{DnsHeader, DnsPacket, ResourceData, ResourceRecord, ResponseCode};

pub fn get_empty_dns_packet(
    response_code: Option<ResponseCode>,
    request_header: Option<&DnsHeader>,
    include_edns: bool,
) -> DnsPacket<'static> {
    let mut packet = DnsPacket::new();
    packet.header.is_response = true;
    packet.header.recursion_available = true;
    if include_edns {
        let edns_rr = ResourceRecord::new(
            "",
            ResourceData::OPT { options: None },
            Some(0),
            Some(DEFAULT_BUF_CAPACITY as u16),
        );
        packet.additionals.push(edns_rr);
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
