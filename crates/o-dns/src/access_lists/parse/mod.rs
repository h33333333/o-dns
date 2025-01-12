mod parsers;
mod process_line;

use std::path::Path;

use anyhow::Context;
use parsers::parse_list_file;
use sqlx::SqliteConnection;

use crate::{Denylist, Hosts};

pub async fn parse_hosts_file(
    path: &Path,
    db: &mut SqliteConnection,
    expected_checksum: Option<[u8; 20]>,
) -> anyhow::Result<Option<[u8; 20]>> {
    parse_list_file::<Hosts>(path, db, expected_checksum)
        .await
        .context("error while parsing the hosts file")
}

pub async fn parse_denylist_file(
    path: &Path,
    db: &mut SqliteConnection,
    expected_checksum: Option<[u8; 20]>,
) -> anyhow::Result<Option<[u8; 20]>> {
    parse_list_file::<Denylist>(path, db, expected_checksum)
        .await
        .context("error while parsing the denylist file")
}
