use std::collections::{HashMap, HashSet};

use o_dns_lib::{QueryType, ResourceData};

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

#[derive(Default)]
pub struct Blacklist {
    entries: HashSet<String>,
}

impl Blacklist {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_entry(&mut self, qname: String) {
        self.entries.insert(qname);
    }

    pub fn contains_entry(&self, qname: &str) -> bool {
        self.entries.contains(qname)
    }
}
