mod util;

use std::net::IpAddr;

use regex::Regex;
pub use util::hash_to_u128;

#[derive(Debug, Clone, Copy)]
pub enum ResponseSource {
    Denylist,
    Allowlist,
    Cache,
    NoRecurse,
    Upstream,
}

#[derive(Debug)]
pub enum AccessListEntryKind {
    DenyRegex((u32, Option<Regex>)),
    DenyDomain(u128),
    Hosts((u128, IpAddr)),
}

#[derive(Debug)]
pub enum DnsServerCommand {
    AddNewListEntry(AccessListEntryKind),
    RemoveListEntry(AccessListEntryKind),
}
