use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use o_dns_lib::{QueryType, ResourceData};
use regex::Regex;

use crate::util::hash_to_u128;

#[derive(Debug)]
pub enum ListEntryKind {
    DenyRegex((u32, Option<Regex>)),
    DenyDomain(u128),
    Hosts((u128, IpAddr)),
}

#[derive(Default)]
pub struct Hosts {
    map: HashMap<u128, Vec<ResourceData<'static>>>,
}

impl Hosts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(&mut self, qname_hash: u128, rdata: ResourceData<'static>) -> anyhow::Result<()> {
        match rdata.get_query_type() {
            QueryType::A | QueryType::AAAA | QueryType::CNAME => {
                self.map
                    .entry(qname_hash)
                    .and_modify(|records| records.push(rdata.clone()))
                    .or_insert_with(|| vec![rdata]);
                Ok(())
            }
            _ => anyhow::bail!("Only custom A/AAAA/CNAME records are supported"),
        }
    }

    pub fn remove_entry(&mut self, qname_hash: u128, qtype: QueryType) {
        self.map
            .get_mut(&qname_hash)
            .into_iter()
            .for_each(|vec| vec.retain(|rr| rr.get_query_type() != qtype));
    }

    pub fn get_entry(&self, qname: &str) -> Option<&[ResourceData<'static>]> {
        self.map
            .get(&hash_to_u128(qname, None))
            .map(|records| records.as_slice())
            .or_else(|| self.find_wildcard_match(qname))
    }

    fn find_wildcard_match(&self, qname: &str) -> Option<&[ResourceData<'static>]> {
        find_wildcard_parts(qname)
            .map(|part| hash_to_u128(part, Some(b"*.")))
            .find_map(|hash| self.map.get(&hash).map(|records| records.as_slice()))
    }
}

#[derive(Default, Debug)]
pub struct Denylist {
    entries: HashSet<u128>,
    regexes: Vec<(u32, Regex)>,
}

impl Denylist {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(&mut self, qname_hash: u128) {
        self.entries.insert(qname_hash);
    }

    pub fn remove_entry(&mut self, qname_hash: u128) {
        self.entries.remove(&qname_hash);
    }

    pub fn add_regex(&mut self, id: u32, re: Regex) {
        self.regexes.push((id, re));
    }

    pub fn remove_regex(&mut self, id_to_delete: u32) {
        self.regexes.retain(|(id, _)| *id != id_to_delete);
    }

    pub fn contains_entry(&self, qname: &str) -> bool {
        // Look for a direct match first
        if self.entries.contains(&hash_to_u128(qname, None)) {
            return true;
        }

        // Look for a wildcard match
        if self.find_wildcard_match(qname) {
            return true;
        };

        // Compare the qname against all regexes that we have
        self.regexes.iter().any(|(_, re)| re.is_match(qname))
    }

    fn find_wildcard_match(&self, qname: &str) -> bool {
        find_wildcard_parts(qname)
            .map(|part| hash_to_u128(part, Some(b"*.")))
            .find_map(|hash| self.entries.contains(&hash).then_some(()))
            .is_some()
    }
}

fn find_wildcard_parts(qname: &str) -> impl Iterator<Item = &str> {
    qname
        .split('.')
        .enumerate()
        .skip(1)
        .filter(|(_, label)| !label.is_empty())
        .filter_map(move |(idx, _)| qname.splitn(idx + 1, '.').last())
}
