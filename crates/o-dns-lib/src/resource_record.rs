#[cfg(feature = "edns")]
use std::num::NonZero;
use std::{
    borrow::Cow,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Context;

use crate::{utils::get_max_encoded_qname_size, ByteBuf, EncodeToBuf, FromBuf, QueryType};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResourceRecord<'a> {
    pub name: Cow<'a, str>,
    pub class: u16,
    pub ttl: u32,
    pub resource_data: ResourceData<'a>,
}

impl<'a> ResourceRecord<'a> {
    pub fn new<'s: 'a>(
        name: &'s str,
        resource_data: ResourceData<'a>,
        ttl: Option<u32>,
        class: Option<u16>,
    ) -> Self {
        ResourceRecord {
            name: name.into(),
            ttl: ttl.unwrap_or_default(),
            class: class.unwrap_or(1),
            resource_data,
        }
    }

    #[cfg(feature = "edns")]
    pub fn get_edns_data(&self) -> Option<EdnsData> {
        match self.resource_data.get_query_type() {
            QueryType::OPT => {
                let udp_payload_size = self.class as usize;
                let ttl_bytes = self.ttl.to_be_bytes();
                let extended_rcode = NonZero::new(ttl_bytes[0]);
                let version = ttl_bytes[1];
                let dnssec_ok_bit = ttl_bytes[2] & 0x80 == 0x80;
                Some(EdnsData {
                    udp_payload_size,
                    extended_rcode,
                    dnssec_ok_bit,
                    version,
                })
            }
            _ => None,
        }
    }
}

impl FromBuf for ResourceRecord<'_> {
    fn from_buf(buf: &mut ByteBuf<'_>) -> anyhow::Result<ResourceRecord<'static>> {
        let name = buf.read_qname().context("NAME is missing")?;
        let query_type: QueryType = buf.read_u16().context("TYPE is missing")?.into();
        let class = buf.read_u16().context("CLASS is missing")?;
        let ttl = buf
            .read_u16()
            .and_then(|msb| buf.read_u16().map(|lsb| ((msb as u32) << 16) | lsb as u32))
            .context("TTL is missing")?;
        let resource_data =
            ResourceData::from_buf_with_type(buf, query_type).context("can't decode RDATA")?;
        Ok(ResourceRecord {
            name,
            ttl,
            resource_data,
            class,
        })
    }
}

impl<'a> EncodeToBuf for ResourceRecord<'a> {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        mut label_cache: Option<&mut HashMap<&'cache str, usize>>,
    ) -> anyhow::Result<()> {
        buf.write_qname(&self.name, label_cache.as_deref_mut())
            .context("writing NAME")?;
        buf.write_u16(self.resource_data.get_query_type().into())
            .context("writing TYPE")?;
        buf.write_u16(self.class).context("writing CLASS")?;
        buf.write_bytes(&self.ttl.to_be_bytes(), None)
            .context("writing TTL")?;

        self.resource_data
            .encode_to_buf_with_cache(buf, label_cache)
            .context("writing RDATA")?;

        Ok(())
    }

    fn get_encoded_size(&self) -> usize {
        get_max_encoded_qname_size(&self.name) + 2 /* CLASS */ + 4 /* TTL */ + self.resource_data.get_encoded_size()
    }
}

#[derive(Debug)]
#[cfg(feature = "edns")]
pub struct EdnsData {
    pub udp_payload_size: usize,
    pub extended_rcode: Option<NonZero<u8>>,
    /// Is set to `true` by DNSSEC-aware clients
    pub dnssec_ok_bit: bool,
    pub version: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ResourceData<'a> {
    UNKNOWN {
        qtype: u16,
        rdata: Cow<'a, [u8]>,
    },
    A {
        address: Ipv4Addr,
    },
    NS {
        ns_domain_name: Cow<'a, str>,
    },
    CNAME {
        cname: Cow<'a, str>,
    },
    AAAA {
        address: Ipv6Addr,
    },
    #[cfg(feature = "edns")]
    OPT {
        options: Option<HashMap<u16, Cow<'a, [u8]>>>,
    },
}

impl<'a> ResourceData<'a> {
    pub fn from_buf_with_type(
        buf: &mut ByteBuf<'a>,
        query_type: QueryType,
    ) -> anyhow::Result<ResourceData<'static>> {
        let rd_length = buf.read_u16().context("RDLENGTH is missing")?;
        Ok(match query_type {
            QueryType::UNKNOWN(query_type) => {
                let data = buf
                    .read_bytes(rd_length as usize)
                    .context("UNKNOWN record: RDATA is missing")?;
                ResourceData::UNKNOWN {
                    qtype: query_type,
                    rdata: data.to_vec().into(),
                }
            }
            QueryType::A => {
                if rd_length != 4 {
                    anyhow::bail!("A record: unexpected RDLENGTH {}", rd_length);
                }
                let address_raw = buf.read_bytes(4).context("A record: ADDRESS is missing")?;
                let address = Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(address_raw).unwrap());
                ResourceData::A { address }
            }
            QueryType::NS => {
                let ns_domain_name = buf.read_qname().context("NS record: NSDNAME is missing")?;
                ResourceData::NS { ns_domain_name }
            }
            QueryType::CNAME => {
                let cname = buf.read_qname().context("CNAME record: CNAME is missing")?;
                ResourceData::CNAME { cname }
            }
            QueryType::AAAA => {
                if rd_length != 16 {
                    anyhow::bail!("AAAA record: unexpected RDLENGTH {}", rd_length);
                }
                let address_raw = buf
                    .read_bytes(16)
                    .context("AAAA record: ADDRESS is missing")?;
                let address = Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(address_raw).unwrap());
                ResourceData::AAAA { address }
            }
            #[cfg(feature = "edns")]
            QueryType::OPT => {
                let mut remaining_rd_length = rd_length;
                let mut options: Option<HashMap<_, _>> = None;
                while remaining_rd_length != 0 {
                    let option = buf.read_u16().with_context(|| {
                        format!(
                            "OPT record: option code is missing at RDLENGTH offset {}",
                            rd_length - remaining_rd_length
                        )
                    })?;
                    let option_length = buf.read_u16().with_context(|| {
                        format!("OPT record: option length is missing for option {}", option)
                    })?;
                    let option_data =
                        buf.read_bytes(option_length as usize).with_context(|| {
                            format!(
                                "OPT record: option data of length {} is missing for option {}",
                                option_length, option
                            )
                        })?;
                    options
                        .get_or_insert_with(|| Default::default())
                        .insert(option, option_data.to_vec().into());
                    remaining_rd_length -= 4 + option_length;
                }
                ResourceData::OPT { options }
            }
            QueryType::ANY => anyhow::bail!("ANY record doesn't exist"),
        })
    }

    pub fn get_query_type(&self) -> QueryType {
        match self {
            ResourceData::UNKNOWN { qtype, .. } => QueryType::UNKNOWN(*qtype),
            ResourceData::A { .. } => QueryType::A,
            ResourceData::NS { .. } => QueryType::NS,
            ResourceData::CNAME { .. } => QueryType::CNAME,
            ResourceData::AAAA { .. } => QueryType::AAAA,
            #[cfg(feature = "edns")]
            ResourceData::OPT { .. } => QueryType::OPT,
        }
    }
}

impl<'a> EncodeToBuf for ResourceData<'a> {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        label_cache: Option<&mut HashMap<&'cache str, usize>>,
    ) -> anyhow::Result<()> {
        match self {
            ResourceData::UNKNOWN { rdata: data, .. } => {
                buf.write_u16(data.len() as u16)
                    .context("UNKNOWN record: writing RDLENGTH")?;
                buf.write_bytes(data, None)
                    .context("UNKNOWN record: writing RDATA")?;
            }
            ResourceData::A { address } => {
                buf.write_u16(4).context("A record: writing RDLENGTH")?;
                buf.write_bytes(&address.octets(), None)
                    .context("A record: writing address")?;
            }
            ResourceData::NS { ns_domain_name } => {
                let rdata_pos = buf.len();
                // We don't know how many bytes qname encoding will take in advance,
                // so we can just write a stub value and replace it later
                buf.write_u16(0)
                    .context("NS record: writing stub RDLENGTH")?;
                let qname_length = buf
                    .write_qname(ns_domain_name, label_cache)
                    .context("NS record: writing NSDNAME")?;
                // Set actual RDLENGTH
                buf.set_u16(rdata_pos, qname_length as u16)
                    .context("NS record: writing RDLENGTH")?;
            }
            ResourceData::CNAME { cname } => {
                let rdata_pos = buf.len();
                // We don't know how many bytes qname encoding will take in advance,
                // so we can just write a stub value and replace it later
                buf.write_u16(0)
                    .context("CNAME record: writing stub RDLENGTH")?;
                let qname_length = buf
                    .write_qname(cname, label_cache)
                    .context("CNAME record: writing CNAME")?;
                // Set actual RDLENGTH
                buf.set_u16(rdata_pos, qname_length as u16)
                    .context("CNAME record: writing RDLENGTH")?;
            }
            ResourceData::AAAA { address } => {
                buf.write_u16(16).context("AAAA record: writing RDLENGTH")?;
                buf.write_bytes(&address.octets(), None)
                    .context("AAAA record: writing ADDRESS")?;
            }
            #[cfg(feature = "edns")]
            ResourceData::OPT { options } => {
                let rdata_pos = buf.len();
                // We don't know how many bytes options will take in advance,
                // so we can just write a stub value and replace it later
                buf.write_u16(0)
                    .context("OPT record: writing stub RDLENGTH")?;

                let mut rd_length = 0;
                if let Some(options) = options {
                    options
                        .iter()
                        .try_for_each(|(&option_code, option_data)| {
                            buf.write_u16(option_code).with_context(|| {
                                format!(
                                    "OPT record: error while writing option code {}",
                                    option_code
                                )
                            })?;
                            buf.write_u16(option_data.len() as u16).with_context(|| {
                                format!(
                                    "OPT record: error while writing option length for option {}",
                                    option_code
                                )
                            })?;
                            buf.write_bytes(option_data, None).with_context(|| {
                                format!(
                                    "OPT record: error while writing option data for option {}",
                                    option_code
                                )
                            })?;
                            rd_length += 4 + option_data.len();

                            anyhow::Result::<()>::Ok(())
                        })
                        .context("OPT record: writing options")?;
                }

                // Set actual RDLENGTH
                buf.set_u16(rdata_pos, rd_length as u16)
                    .context("OPT record: writing RDLENGTH")?;
            }
        };

        Ok(())
    }

    fn get_encoded_size(&self) -> usize {
        let mut size = 2 /* RDLENGTH */;
        match self {
            ResourceData::UNKNOWN { rdata, .. } => {
                size += rdata.len();
            }
            ResourceData::A { .. } => {
                size += 4 /* Ipv4Addr */;
            }
            ResourceData::NS { ns_domain_name } => {
                size += get_max_encoded_qname_size(ns_domain_name);
            }
            ResourceData::CNAME { cname } => {
                size += get_max_encoded_qname_size(cname);
            }
            ResourceData::AAAA { .. } => {
                size += 16 /* Ipv6Addr */;
            }
            #[cfg(feature = "edns")]
            ResourceData::OPT { options } => {
                options.iter().for_each(|options| {
                    options.values().for_each(|option| {
                        size += 2 /* option code */ + 2 /* option length */ + option.len();
                    })
                });
            }
        }
        size
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{arb_resource_data, arb_resource_record};

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn resource_data_roundtrip(resource_data in arb_resource_data()) {
            let qtype = resource_data.get_query_type();
            let mut buf = ByteBuf::new_empty(None);
            resource_data.encode_to_buf(&mut buf).expect("shouldn't have failed");
            let roundtripped_rd = ResourceData::from_buf_with_type(&mut buf, qtype).expect("shouldn't have failed");
            prop_assert_eq!(resource_data, roundtripped_rd, "ResourceData roundtrip test failed");
        }

        #[test]
        fn resource_record_roundtrip(resource_record in arb_resource_record()) {
            let mut buf = ByteBuf::new_empty(None);
            resource_record.encode_to_buf(&mut buf).expect("shouldn't have failed");
            let roundtripped_rr = ResourceRecord::from_buf(&mut buf).expect("shouldn't have failed");
            prop_assert_eq!(resource_record, roundtripped_rr, "ResourceRecord roundtrip test failed");
        }
    }
}
