use anyhow::Context;
use o_dns_lib::{DnsHeader, DnsPacket, Question, ResourceData, ResourceRecord, ResponseCode};
use regex::Regex;
use sha1::Digest;
use std::{borrow::Cow, collections::HashMap, path::Path};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

use crate::Blacklist;

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

pub async fn parse_blacklist_file(path: &Path, blacklist: &mut Blacklist) -> anyhow::Result<()> {
    let mut file = BufReader::new(
        File::open(path)
            .await
            .with_context(|| format!("error while opening the blacklist file '{:?}'", path))?,
    );

    let mut line = String::new();
    loop {
        // Clear the buffer
        line.clear();

        if file
            .read_line(&mut line)
            .await
            .context("error while reading a line from the blacklist file")?
            == 0
        {
            // Reached EOF
            break;
        }

        // Skip comments and empty lines
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        };

        let remaining_line = {
            let trimmed_len = line.trim_start().len();
            let domain_start_idx = line.len() - trimmed_len;
            let remaining_line = &mut line.as_mut_str()[domain_start_idx..];

            if remaining_line.starts_with('/') {
                // It's a regex
                let Ok((regex, remaining_line)) = parse_regex(remaining_line) else {
                    // Malformed regex
                    continue;
                };
                let regex = match Regex::new(regex) {
                    Ok(regex) => regex,
                    Err(e) => {
                        tracing::debug!(%regex, "Error while parsing a regex: {}", e);
                        continue;
                    }
                };
                blacklist.add_regex(regex);
                remaining_line
            } else {
                // It should be a domain name otherwise
                let Some((domain, remaining_line)) = parse_domain_name(remaining_line) else {
                    // Malformed domain
                    tracing::debug!("Error while parsing a domain: {}", remaining_line);
                    continue;
                };
                blacklist.add_entry(domain);
                remaining_line
            }
        };

        // TODO: store labels in the blacklist for future use
        let _label = remaining_line.find('[').and_then(|label_start_idx| {
            remaining_line[label_start_idx..]
                .find(']')
                .map(|label_end_idx| remaining_line.get(label_start_idx + 1..label_end_idx))
        });
    }

    Ok(())
}

/// Parses a regex formatted like `/<re>/`
pub fn parse_regex(mut line: &mut str) -> anyhow::Result<(&mut str, &mut str)> {
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

pub fn parse_domain_name(line: &mut str) -> Option<(&mut str, &mut str)> {
    let mut domain_length = 0;
    for (idx, byte) in unsafe { line.as_bytes_mut().into_iter().enumerate() } {
        if byte.is_ascii_alphanumeric() {
            byte.make_ascii_lowercase();
            domain_length += 1;
        } else if idx > 0 && (*byte == b'.' || *byte == b'-') {
            domain_length += 1;
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
        Some(line.split_at_mut(domain_length))
    }
}
