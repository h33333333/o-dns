use std::collections::{HashMap, HashSet};

use o_dns_lib::{QueryType, ResourceData};
use regex::Regex;
use sha1::{Digest, Sha1};

#[derive(Default)]
pub struct Hosts {
    hosts: HashMap<String, Vec<ResourceData<'static>>>,
}

impl Hosts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(&mut self, qname: String, rdata: ResourceData<'static>) -> anyhow::Result<()> {
        match rdata.get_query_type() {
            QueryType::A | QueryType::AAAA | QueryType::CNAME => {
                self.hosts
                    .entry(qname)
                    .and_modify(|records| records.push(rdata.clone()))
                    .or_insert_with(|| vec![rdata]);
                Ok(())
            }
            _ => anyhow::bail!("Only custom A/AAAA/CNAME records are supported"),
        }
    }

    pub fn get_entry(&self, qname: &str) -> Option<&[ResourceData<'static>]> {
        self.hosts.get(qname).map(|records| records.as_slice())
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

    pub fn add_entry(&mut self, qname: &str) {
        let mut hasher = Sha1::new();
        hasher.update(qname);
        let hash = hasher.finalize();
        // Reduce the output hash to first 16 bytes in order to fit it into a single u128
        let hash = u128::from_be_bytes(hash[..16].try_into().unwrap());

        self.entries.insert(hash);
    }

    pub fn add_regex(&mut self, re: Regex) {
        self.regexes.push(re);
    }

    pub fn contains_entry(&self, qname: &str) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(qname);
        let hash = hasher.finalize();
        // Reduce the output hash to first 16 bytes in order to fit it into a single u128
        let hash = u128::from_be_bytes(hash[..16].try_into().unwrap());

        // Look for a direct match first
        if self.entries.contains(&hash) {
            return true;
        }

        // Compare the qname against all regexes that we have
        self.regexes.iter().find(|re| re.is_match(qname)).is_some()
    }
}
