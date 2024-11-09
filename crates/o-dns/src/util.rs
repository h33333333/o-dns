use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;
use o_dns_lib::{DnsPacket, QueryType, Question, ResourceData, ResourceRecord, ResponseCode};
use regex::Regex;
use sha1::Digest;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::{Denylist, Hosts, DEFAULT_EDNS_BUF_CAPACITY, EDNS_DO_BIT};

trait EntryFromStr {
    fn process_line(&mut self, line: &mut str) -> anyhow::Result<()>;
}

impl EntryFromStr for Hosts {
    fn process_line(&mut self, line: &mut str) -> anyhow::Result<()> {
        let (domain, remaining_line) = parse_domain_name(line).context("failed to parse domain")?;

        let (ip_addr, remaining_line) = {
            let mut it = remaining_line.splitn(2, ' ');
            let raw_ip_addr = it.next().context("missing IP address")?;
            let ip_addr: IpAddr = raw_ip_addr.parse().context("failed to parse IP address")?;
            (ip_addr, it.next().unwrap_or(""))
        };

        let rd = match ip_addr {
            IpAddr::V4(address) => ResourceData::A { address },
            IpAddr::V6(address) => ResourceData::AAAA { address },
        };

        // TODO: store labels in the hosts for future use
        let _label = parse_label(remaining_line);

        // Can't happen as we only create A/AAAA records
        self.add_entry(hash_to_u128(domain, None), rd)
            .context("bug: non A/AAAA/CNAME record?")?;

        Ok(())
    }
}

impl EntryFromStr for Denylist {
    fn process_line(&mut self, line: &mut str) -> anyhow::Result<()> {
        let remaining_line = if line.starts_with('/') {
            // Handle regex
            let (regex_str, remaining_line) = parse_regex(line).context("failed to parse regex")?;

            let regex =
                Regex::new(regex_str).map_err(|e| anyhow::anyhow!("failed to compile regex '{}': {}", regex_str, e))?;

            self.add_regex(regex);

            remaining_line
        } else {
            // Handle domain
            let (domain, remaining_line) = parse_domain_name(line).context("failed to parse domain")?;

            self.add_entry(hash_to_u128(domain, None));

            remaining_line
        };

        // TODO: store labels in the denylist for future use
        let _label = parse_label(remaining_line);

        Ok(())
    }
}

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

pub async fn parse_hosts_file(path: &Path, whitelist: &mut Hosts) -> anyhow::Result<()> {
    parse_list_file(path, whitelist)
        .await
        .context("error while parsing the hosts file")
}

pub async fn parse_denylist_file(path: &Path, denylist: &mut Denylist) -> anyhow::Result<()> {
    parse_list_file(path, denylist)
        .await
        .context("error while parsing the denylist file")
}

async fn parse_list_file<T: EntryFromStr>(path: &Path, processor: &mut T) -> anyhow::Result<()> {
    let mut file = BufReader::new(
        File::open(path)
            .await
            .map_err(|e| anyhow::anyhow!("error while opening the file {:?}: {}", path, e))?,
    );

    let mut line = String::new();
    loop {
        // Clear the buffer
        line.clear();

        if file.read_line(&mut line).await.context("error while reading a line")? == 0 {
            // Reached EOF
            break;
        }

        // Remove any leading whitespaces
        let trimmed_len = line.trim_start().len();
        let domain_start_idx = line.len() - trimmed_len;
        let remaining_line = &mut line[domain_start_idx..];

        // Skip comments and empty lines
        if remaining_line.is_empty() || remaining_line.starts_with('#') {
            continue;
        }

        if let Err(e) = processor.process_line(remaining_line) {
            tracing::debug!("Error while processing the line '{}': {}", remaining_line, e);
            continue;
        }
    }

    Ok(())
}

fn parse_label(line: &str) -> Option<&str> {
    line.find('[').and_then(|label_start_idx| {
        line[label_start_idx..]
            .find(']')
            .and_then(|label_end_idx| line.get(label_start_idx + 1..label_end_idx))
    })
}

/// Parses a regex formatted like `/<re>/`
fn parse_regex(mut line: &mut str) -> anyhow::Result<(&mut str, &mut str)> {
    if !line.starts_with('/') {
        anyhow::bail!("line doesn't contain a regex");
    }

    // Skip the leading '/'
    line = &mut line[1..];
    let regex_length = line
        .bytes()
        .scan(false, |escaped_symbol, byte| {
            if byte == b'/' && !*escaped_symbol {
                return None;
            }
            *escaped_symbol = byte == b'\\' && !*escaped_symbol;
            Some(())
        })
        .count();

    let (regex, remaining_line) = line.split_at_mut(regex_length);

    if !remaining_line.starts_with('/') {
        // Regex with a missing closing delimiter
        anyhow::bail!("malformed regex");
    }

    // Remove the remaining '/'
    Ok((regex, &mut remaining_line[1..]))
}

fn parse_domain_name(line: &mut str) -> Option<(&mut str, &mut str)> {
    let mut domain_length = 0;
    let mut is_wildcard_label = false;
    for (idx, byte) in unsafe { line.as_bytes_mut().iter_mut().enumerate() } {
        if is_wildcard_label && *byte != b'.' {
            // Protect against entries like '*test.abc'
            return None;
        } else {
            is_wildcard_label = false;
        }

        if byte.is_ascii_alphanumeric() {
            byte.make_ascii_lowercase();
            domain_length += 1;
        } else if idx > 0 && (*byte == b'.' || *byte == b'-') {
            domain_length += 1;
        } else if idx == 0 && (*byte == b'*') {
            // A wildcard domain
            domain_length += 1;
            is_wildcard_label = true;
        } else {
            // Stop iterating as we encountered an invalid character.
            // Process whatever we gathered at this point and continue to the next line
            break;
        }
    }
    let domain = &line[..domain_length];

    // Return early if encountered a malformed line with a single domain label
    let tld_start_idx = domain.rfind('.')?;

    if tld_start_idx == domain.len() - 1 {
        // Malformed line: 'example.'
        return None;
    }

    let tld = &domain[tld_start_idx + 1..];
    if tld.len() < 2 || !tld.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        // Bad TLD: 'example.b' or 'example.t3st'
        None
    } else {
        let (domain, remaining_line) = line.split_at_mut(domain_length);

        // Account for any leading whitespaces in the remaining line
        let whitespace_length = remaining_line.len() - remaining_line.trim_start().len();
        let remaining_line = &mut remaining_line[whitespace_length..];

        Some((domain, remaining_line))
    }
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
