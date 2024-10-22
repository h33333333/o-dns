#[cfg(test)]
pub(crate) mod test_utils;

mod buf;
mod dns_header;
mod question;
mod resource_record;
mod utils;

use buf::EncodedSize;
pub use buf::{ByteBuf, EncodeToBuf, FromBuf};
use cfg_if::cfg_if;
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
        max_size: Option<usize>,
    ) -> anyhow::Result<usize> {
        if max_size.is_some_and(|max_size| max_size < 12) {
            anyhow::bail!("max size is too low: can't fit DNS header")
        }

        let mut dns_packet_encoded_size = 12;

        #[cfg(feature = "edns")]
        if let Some(opt_rr) = self.edns.and_then(|idx| self.additionals.get(idx)) {
            let opt_rr_size = opt_rr.get_encoded_size(None);
            if max_size.is_some_and(|max_size| opt_rr_size + dns_packet_encoded_size > max_size) {
                anyhow::bail!("max size is too low: can't fit OPT RR");
            }
            // Account for edns size, as it should always be present
            dns_packet_encoded_size += opt_rr_size;
        }

        // Clone the header in order to update RR counts
        let mut header = self.header.clone();

        // Remember header's position in order to update the truncation bit and RR counts
        let dns_header_pos = buf.len();
        // Header's size is already accounted for
        self.header
            .encode_to_buf(buf, None)
            .context("writing header")?;

        // Track whether we truncated any RRs/questions while encoding
        let mut truncation = false;
        self.questions
            .iter()
            .enumerate()
            .try_for_each(|(idx, question)| {
                let encoded_size = question
                    .encode_to_buf_with_cache(
                        buf,
                        label_cache.as_deref_mut(),
                        max_size.map(|max_size| max_size - dns_packet_encoded_size),
                    )
                    .with_context(|| format!("writing question at idx {}", idx))?;
                if encoded_size == 0 {
                    truncation = true;
                    header.question_count -= 1;
                } else {
                    dns_packet_encoded_size += encoded_size;
                }
                anyhow::Result::<()>::Ok(())
            })
            .context("writing questions")?;

        self.answers
            .iter()
            .enumerate()
            .try_for_each(|(idx, answer)| {
                let encoded_size = answer
                    .encode_to_buf_with_cache(
                        buf,
                        label_cache.as_deref_mut(),
                        max_size.map(|max_size| max_size - dns_packet_encoded_size),
                    )
                    .with_context(|| format!("writing answer RR at idx {}", idx))?;
                if encoded_size == 0 {
                    truncation = true;
                    header.answer_rr_count -= 1;
                } else {
                    dns_packet_encoded_size += encoded_size;
                }
                anyhow::Result::<()>::Ok(())
            })
            .context("writing answer RRs")?;

        self.authorities
            .iter()
            .enumerate()
            .try_for_each(|(idx, authority)| {
                let encoded_size = authority
                    .encode_to_buf_with_cache(
                        buf,
                        label_cache.as_deref_mut(),
                        max_size.map(|max_size| max_size - dns_packet_encoded_size),
                    )
                    .with_context(|| format!("writing authority RR at idx {}", idx))?;
                if encoded_size == 0 {
                    truncation = true;
                    header.authority_rr_count -= 1;
                } else {
                    dns_packet_encoded_size += encoded_size;
                }
                anyhow::Result::<()>::Ok(())
            })
            .context("writing authority RRs")?;

        self.additionals
            .iter()
            .enumerate()
            .try_for_each(|(idx, additional)| {
                #[cfg(feature = "edns")]
                let max_size = match additional.resource_data.get_query_type() {
                    // Already accounted for, so safe to write
                    QueryType::OPT => None,
                    // Otherwise process as every other RR type
                    _ => max_size,
                };
                let encoded_size = additional
                    .encode_to_buf_with_cache(
                        buf,
                        label_cache.as_deref_mut(),
                        max_size.map(|max_size| max_size - dns_packet_encoded_size),
                    )
                    .with_context(|| format!("writing additional RR at idx {}", idx))?;
                cfg_if! {
                    if #[cfg(feature = "edns")] {
                        // OPT RR is already accounted for
                        if additional.resource_data.get_query_type() != QueryType::OPT {
                            dns_packet_encoded_size += encoded_size;
                        }
                    } else {
                        dns_packet_encoded_size += encoded_size;
                    }
                }
                if encoded_size == 0 {
                    truncation = true;
                    header.additional_rr_count -= 1;
                }
                anyhow::Result::<()>::Ok(())
            })
            .context("writing additional RRs")?;

        if truncation {
            header.truncation = truncation;
            // Update flags
            buf.set_u16(dns_header_pos + 2, header.get_flags())
                .context("updating header flags")?;
            // Update question count
            buf.set_u16(dns_header_pos + 4, header.question_count)
                .context("updating question count")?;
            // Update answer RR count
            buf.set_u16(dns_header_pos + 6, header.answer_rr_count)
                .context("updating answer RR count")?;
            // Update authority RR count
            buf.set_u16(dns_header_pos + 8, header.authority_rr_count)
                .context("updating authority RR count")?;
            // Update additional RR count
            buf.set_u16(dns_header_pos + 10, header.additional_rr_count)
                .context("updating addditional RR count")?;
        }

        Ok(dns_packet_encoded_size)
    }

    fn encode_to_buf(&self, buf: &mut ByteBuf, max_size: Option<usize>) -> anyhow::Result<usize> {
        let mut label_cache = HashMap::new();
        self.encode_to_buf_with_cache(buf, Some(&mut label_cache), max_size)
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
            let encoded_size = dns_packet.encode_to_buf(&mut buf, None).expect("shouldn't have failed");
            assert_eq!(encoded_size, buf.len());
            let roundtripped_dns_packet = DnsPacket::from_buf(&mut buf).expect("shouldn't have failed");
            prop_assert_eq!(dns_packet, roundtripped_dns_packet, "DnsPacket roundtrip test failed");
        }
    }
}
