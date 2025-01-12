use std::collections::HashMap;

use o_dns_lib::{QueryType, ResourceData};

use super::util::find_wildcard_parts;
use crate::util::hash_to_u128;

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
