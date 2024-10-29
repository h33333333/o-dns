use anyhow::Context;
use o_dns_lib::{DnsHeader, DnsPacket, Question, ResourceData, ResourceRecord, ResponseCode};
use regex::Regex;
use sha1::Digest;
use std::{borrow::Cow, collections::HashMap, net::IpAddr, path::Path};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use crate::{Denylist, Hosts};

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

            let regex = Regex::new(regex_str)
                .map_err(|e| anyhow::anyhow!("failed to compile regex '{}': {}", regex_str, e))?;

            self.add_regex(regex);

            remaining_line
        } else {
            // Handle domain
            let (domain, remaining_line) =
                parse_domain_name(line).context("failed to parse domain")?;

            self.add_entry(hash_to_u128(domain, None));

            remaining_line
        };

        // TODO: store labels in the denylist for future use
        let _label = parse_label(remaining_line);

        Ok(())
    }
}

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

        if file
            .read_line(&mut line)
            .await
            .context("error while reading a line")?
            == 0
        {
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
            tracing::debug!(
                "Error while processing the line '{}': {}",
                remaining_line,
                e
            );
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
            if byte == b'\\' && !*escaped_symbol {
                *escaped_symbol = true;
            } else {
                *escaped_symbol = false;
            }
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
    for (idx, byte) in unsafe { line.as_bytes_mut().into_iter().enumerate() } {
        if is_wildcard_label && !(*byte == b'.') {
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
