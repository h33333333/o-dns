use std::collections::HashSet;

use regex::Regex;

use super::util::find_wildcard_parts;
use crate::util::hash_to_u128;

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
