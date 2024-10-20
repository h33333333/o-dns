#[cfg(test)]
pub(crate) mod test_utils;

mod buf;
mod dns_header;
mod question;
mod resource_record;

pub use buf::{ByteBuf, EncodeToBuf, FromBuf};
pub use dns_header::{DnsHeader, QueryOpcode, ResponseCode};
pub use question::{QueryType, Question};
#[cfg(feature = "edns")]
pub use resource_record::EdnsData;
pub use resource_record::{ResourceData, ResourceRecord};

use anyhow::Context;
use core::str;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct DnsPacket<'a> {
    pub header: DnsHeader,
    #[cfg(feature = "edns")]
    /// Idx of the OPT RR, if present
    pub edns: Option<usize>,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub authorities: Vec<ResourceRecord<'a>>,
    pub additionals: Vec<ResourceRecord<'a>>,
}

impl<'a> DnsPacket<'a> {
    pub fn new() -> Self {
        DnsPacket::default()
    }
}

impl FromBuf for DnsPacket<'_> {
    fn from_buf(buf: &mut ByteBuf<'_>) -> anyhow::Result<DnsPacket<'static>> {
        let header = DnsHeader::from_buf(buf).context("header parsing error")?;

        let mut questions = Vec::with_capacity(header.question_count as usize);
        for idx in 0..header.question_count {
            let question = Question::from_buf(buf)
                .with_context(|| format!("question parsing error at idx {}", idx))?;
            questions.push(question);
        }

        let mut answers = Vec::with_capacity(header.answer_rr_count as usize);
        for idx in 0..header.answer_rr_count {
            let answer = ResourceRecord::from_buf(buf)
                .with_context(|| format!("answer RR parsing error at idx {}", idx))?;
            answers.push(answer);
        }

        let mut authorities = Vec::with_capacity(header.authority_rr_count as usize);
        for idx in 0..header.authority_rr_count {
            let authority = ResourceRecord::from_buf(buf)
                .with_context(|| format!("authority RR parsing error at idx {}", idx))?;
            authorities.push(authority);
        }

        #[cfg(feature = "edns")]
        let mut edns = None;
        let mut additionals = Vec::with_capacity(header.additional_rr_count as usize);
        for idx in 0..header.additional_rr_count {
            let additional = ResourceRecord::from_buf(buf)
                .with_context(|| format!("additional RR parsing error at idx {}", idx))?;
            #[cfg(feature = "edns")]
            if additional.resource_data.get_query_type() == QueryType::OPT {
                if let Some(old_idx) = edns.replace(additionals.len()) {
                    anyhow::bail!("Multiple OPT records at positions {} and {}", old_idx, idx)
                }
            }
            additionals.push(additional);
        }

        Ok(DnsPacket {
            header,
            questions,
            #[cfg(feature = "edns")]
            edns,
            answers,
            authorities,
            additionals,
        })
    }
}

impl<'a> EncodeToBuf for DnsPacket<'a> {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        mut label_cache: Option<&mut HashMap<&'cache str, usize>>,
    ) -> anyhow::Result<()> {
        self.header.encode_to_buf(buf).context("writing header")?;
        self.questions
            .iter()
            .enumerate()
            .try_for_each(|(idx, question)| {
                question
                    .encode_to_buf_with_cache(buf, label_cache.as_deref_mut())
                    .with_context(|| format!("writing question at idx {}", idx))
            })
            .context("writing questions")?;
        self.answers
            .iter()
            .enumerate()
            .try_for_each(|(idx, answer)| {
                answer
                    .encode_to_buf_with_cache(buf, label_cache.as_deref_mut())
                    .with_context(|| format!("writing answer RR at idx {}", idx))
            })
            .context("writing answer RRs")?;
        self.authorities
            .iter()
            .enumerate()
            .try_for_each(|(idx, authority)| {
                authority
                    .encode_to_buf_with_cache(buf, label_cache.as_deref_mut())
                    .with_context(|| format!("writing authority RR at idx {}", idx))
            })
            .context("writing authority RRs")?;

        self.additionals
            .iter()
            .enumerate()
            .try_for_each(|(idx, additional)| {
                additional
                    .encode_to_buf_with_cache(buf, label_cache.as_deref_mut())
                    .with_context(|| format!("writing additional RR at idx {}", idx))
            })
            .context("writing additional RRs")?;

        Ok(())
    }

    fn encode_to_buf(&self, buf: &mut ByteBuf) -> anyhow::Result<()> {
        let mut label_cache = HashMap::new();
        self.encode_to_buf_with_cache(buf, Some(&mut label_cache))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prop::collection::vec;
    use proptest::prelude::*;
    use test_utils::{arb_question, arb_resource_record};

    prop_compose! {
        fn arb_dns_header_with_counts(
            question_count: u16,
            answer_rr_count: u16,
            authority_rr_count: u16,
            additional_rr_count: u16
        )(
            id: u16,
            is_response: bool,
             opcode: QueryOpcode,
            is_authoritative: bool,
            truncation: bool,
            recursion_desired: bool,
            recursion_available: bool,
            z: [bool; 3],
            response_code : ResponseCode
        ) -> DnsHeader {
            DnsHeader {
                id,
                is_response,
                opcode,
                is_authoritative,
                truncation,
                recursion_desired,
                recursion_available,
                z,
                response_code,
                question_count,
                answer_rr_count,
                authority_rr_count,
                additional_rr_count
            }
        }
    }

    fn arb_dns_packet() -> impl Strategy<Value = DnsPacket<'static>> {
        (0..5u16, 0..5u16, 0..5u16, 0..5u16)
            .prop_flat_map(
                |(questions_len, answers_len, authorities_len, additionals_len)| {
                    let additionals = vec(arb_resource_record(), additionals_len as usize);
                    #[cfg(feature = "edns")]
                    let additionals =
                        additionals.prop_filter("DNS packet with multiple OPT RRs", |vec| {
                            (0..=1).contains(
                                &vec.iter()
                                    .filter(|rr| {
                                        rr.resource_data.get_query_type() == QueryType::OPT
                                    })
                                    .count(),
                            )
                        });
                    (
                        arb_dns_header_with_counts(
                            questions_len,
                            answers_len,
                            authorities_len,
                            additionals_len,
                        ),
                        vec(arb_question(), questions_len as usize),
                        vec(arb_resource_record(), answers_len as usize),
                        vec(arb_resource_record(), authorities_len as usize),
                        additionals,
                    )
                        .prop_map(
                            |(header, questions, answers, authorities, additionals)| {
                                #[cfg(feature = "edns")]
                                let edns = additionals.iter().position(|rr| {
                                    rr.resource_data.get_query_type() == QueryType::OPT
                                });
                                DnsPacket {
                                    header,
                                    #[cfg(feature = "edns")]
                                    edns,
                                    questions,
                                    answers,
                                    authorities,
                                    additionals,
                                }
                            },
                        )
                },
            )
            .boxed()
    }

    proptest! {
        #[test]
        fn dns_packet_roundtrip(dns_packet in arb_dns_packet()) {
            let mut buf = ByteBuf::new_empty(None);
            dns_packet.encode_to_buf(&mut buf).expect("shouldn't have failed");
            let roundtripped_dns_packet = DnsPacket::from_buf(&mut buf).expect("shouldn't have failed");
            prop_assert_eq!(dns_packet, roundtripped_dns_packet, "DnsPacket roundtrip test failed");
        }
    }
}
