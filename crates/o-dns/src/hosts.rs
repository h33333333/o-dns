use std::collections::{HashMap, HashSet};

use o_dns_lib::{QueryType, ResourceData};
use regex::Regex;
use sha1::{Digest, Sha1};

use crate::util::hash_to_u128;

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
            .get(&hash_to_u128(qname))
            .map(|records| records.as_slice())
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
        if self.entries.contains(&hash_to_u128(qname)) {
            return true;
        }

        // Look for a wildcard match
        for (idx, label) in qname.split('.').enumerate().skip(1) {
            if label.is_empty() {
                continue;
            }

            let remaining_qname = qname.splitn(idx + 1, '.').last().unwrap();

            let mut hasher = Sha1::new();
            hasher.update("*.");
            hasher.update(remaining_qname);

            let hash = hasher.finalize();
            let hash = u128::from_be_bytes(hash[..16].try_into().unwrap());

            if self.entries.contains(&hash) {
                return true;
            }
        }

        // Compare the qname against all regexes that we have
        self.regexes.iter().find(|re| re.is_match(qname)).is_some()
    }
}
