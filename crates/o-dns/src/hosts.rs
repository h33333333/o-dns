use std::collections::{HashMap, HashSet};

use crate::util::hash_to_u128;
use o_dns_lib::{QueryType, ResourceData};
use regex::Regex;

#[derive(Default)]
pub struct Whitelist {
    map: HashMap<u128, Vec<ResourceData<'static>>>,
}

impl Whitelist {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(
        &mut self,
        qname_hash: u128,
        rdata: ResourceData<'static>,
    ) -> anyhow::Result<()> {
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
pub struct Blacklist {
    entries: HashSet<u128>,
    regexes: Vec<Regex>,
}

impl Blacklist {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(&mut self, qname_hash: u128) {
        self.entries.insert(qname_hash);
    }

    pub fn add_regex(&mut self, re: Regex) {
        self.regexes.push(re);
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
        self.regexes.iter().find(|re| re.is_match(qname)).is_some()
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
