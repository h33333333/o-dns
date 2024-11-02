use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

use prop::strategy::Union;
#[cfg(feature = "edns")]
use proptest::collection::hash_map;
use proptest::collection::vec;
use proptest::prelude::*;

use crate::{QueryType, Question, ResourceData, ResourceRecord};

prop_compose! {
    pub fn arb_question()(qname in arb_qname(), query_type: QueryType, qclass: u16) -> Question<'static> {
        Question { qname, query_type, qclass}
    }
}

prop_compose! {
    pub fn arb_resource_record()(name in arb_qname(), resource_data in arb_resource_data(), class: u16, ttl: u32) -> ResourceRecord<'static> {
        ResourceRecord { name, class, ttl, resource_data }
    }
}

pub fn arb_resource_data() -> impl Strategy<Value = ResourceData<'static>> {
    let variants = vec![
        vec(any::<u8>(), 1..100)
            .prop_map(Cow::Owned)
            .prop_map(|rdata| ResourceData::UNKNOWN {
                // Use the reserved QTYPE to avoid collisions with QTYPEs that we handle
                qtype: 65535,
                rdata,
            })
            .boxed(),
        any::<Ipv4Addr>()
            .prop_map(|address| ResourceData::A { address })
            .boxed(),
        arb_qname()
            .prop_map(|qname| ResourceData::NS {
                ns_domain_name: qname,
            })
            .boxed(),
        arb_qname()
            .prop_map(|qname| ResourceData::CNAME { cname: qname })
            .boxed(),
        any::<Ipv6Addr>()
            .prop_map(|address| ResourceData::AAAA { address })
            .boxed(),
        #[cfg(feature = "edns")]
        proptest::option::of(hash_map(
            any::<u16>(),
            vec(any::<u8>(), 1..100).prop_map(Cow::Owned),
            1..10,
        ))
        .prop_map(|options| ResourceData::OPT { options })
        .boxed(),
    ];

    Union::new(variants)
}

fn arb_qname() -> impl Strategy<Value = Cow<'static, str>> {
    proptest::string::string_regex(r"(([a-za-z0-9][a-za-z0-9-]{1,62}\.)+[a-za-z0-9]{2,63})|")
        .expect("regex should be valid")
        .prop_map(Cow::Owned)
}
