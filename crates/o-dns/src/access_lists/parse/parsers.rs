use std::path::Path;

use sha1::Digest as _;
use sqlx::SqliteConnection;

use super::process_line::EntryFromStr;

pub(super) async fn parse_list_file<T: EntryFromStr>(
    path: &Path,
    db: &mut SqliteConnection,
    expected_checksum: Option<[u8; 20]>,
) -> anyhow::Result<Option<[u8; 20]>> {
    let mut data = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow::anyhow!("error while opening the file {:?}: {}", path, e))?;

    // Calculate a checksum for the current file
    let mut hasher = sha1::Sha1::new();
    hasher.update(data.as_bytes());
    let file_checksum = hasher.finalize().into();

    // Verify the cheksum
    if let Some(expected_checksum) = expected_checksum {
        if file_checksum == expected_checksum {
            // No need to update the entries
            tracing::debug!(path=?path, "Checksums matched, no need to update the list");
            return Ok(None);
        }
    }

    let mut remaining_file = data.as_mut_str();
    loop {
        if remaining_file.is_empty() {
            // Reached EOF
            break;
        };

        let line_break_pos = remaining_file.find('\n');

        let split_pos = line_break_pos.unwrap_or(remaining_file.len());
        let (current_line, after) = remaining_file.split_at_mut(split_pos);
        // Skip the line break if it's present
        remaining_file = &mut after[line_break_pos.map_or(0, |_| 1)..];

        // Remove any leading whitespaces
        let trimmed_len = current_line.trim_start().len();
        let domain_start_idx = current_line.len() - trimmed_len;
        let remaining_line = &mut current_line[domain_start_idx..];

        // Skip comments and empty lines
        if remaining_line.is_empty() || remaining_line.starts_with('#') {
            continue;
        }

        if let Err(e) = T::process_line(remaining_line, db).await {
            tracing::debug!("Error while processing the line '{}': {}", remaining_line, e);
            continue;
        }
    }

    Ok(Some(file_checksum))
}

pub(super) fn parse_label(line: &str) -> Option<&str> {
    line.find('[').and_then(|label_start_idx| {
        line[label_start_idx..]
            .find(']')
            .and_then(|label_end_idx| line.get(label_start_idx + 1..label_end_idx))
    })
}

/// Parses a regex formatted like `/<re>/`
pub(super) fn parse_regex(mut line: &mut str) -> anyhow::Result<(&mut str, &mut str)> {
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

pub(super) fn parse_domain_name(line: &mut str) -> Option<(&mut str, &mut str)> {
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
