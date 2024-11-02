use crate::{
    buf::EncodedSize, utils::get_max_encoded_qname_size, ByteBuf, EncodeToBuf, FromBuf, IN_CLASS,
};
use anyhow::Context;
use std::{borrow::Cow, collections::HashMap};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    AAAA,
    #[cfg(feature = "edns")]
    OPT,
    ANY,
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            28 => QueryType::AAAA,
            #[cfg(feature = "edns")]
            41 => QueryType::OPT,
            255 => QueryType::ANY,
            _ => QueryType::UNKNOWN(value),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(val: QueryType) -> Self {
        match val {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::AAAA => 28,
            #[cfg(feature = "edns")]
            QueryType::OPT => 41,
            QueryType::ANY => 255,
            QueryType::UNKNOWN(qtype) => qtype,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Question<'a> {
    pub qname: Cow<'a, str>,
    pub query_type: QueryType,
    pub qclass: u16,
}

impl<'a> Question<'a> {
    pub fn new(qname: &'a str, query_type: QueryType, qclass: Option<u16>) -> Self {
        Self {
            qname: Cow::Borrowed(qname),
            query_type,
            qclass: qclass.unwrap_or(IN_CLASS),
        }
    }

    pub fn into_owned(self) -> Question<'static> {
        Question {
            qname: self.qname.into_owned().into(),
            query_type: self.query_type,
            qclass: self.qclass,
        }
    }
}

impl<'a> FromBuf for Question<'a> {
    fn from_buf(buf: &mut ByteBuf) -> anyhow::Result<Question<'static>> {
        let qname = buf.read_qname().context("QNAME is missing")?;
        let qtype_raw = buf.read_u16().context("QTYPE is missing")?;
        let class = buf.read_u16().context("QCLASS is missing")?;

        Ok(Question {
            qname,
            query_type: qtype_raw.into(),
            qclass: class,
        })
    }
}

impl<'a> EncodeToBuf for Question<'a> {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        label_cache: Option<&mut HashMap<&'cache str, usize>>,
        max_size: Option<usize>,
    ) -> anyhow::Result<usize> {
        let encoded_size = self.get_encoded_size(label_cache.as_deref());
        if max_size.is_some_and(|max_size| encoded_size > max_size) {
            return Ok(0);
        }
        buf.write_qname(&self.qname, label_cache)
            .context("writing QNAME")?;
        buf.write_u16(self.query_type.into())
            .context("writing QTYPE")?;
        buf.write_u16(self.qclass).context("writing QCLASS")?;

        Ok(encoded_size)
    }
}

impl EncodedSize for Question<'_> {
    fn get_encoded_size(&self, label_cache: Option<&HashMap<&str, usize>>) -> usize {
        let qname_size = get_max_encoded_qname_size(&self.qname, label_cache);
        qname_size + 2 /* QTYPE */ + 2 /* CLASS */
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::arb_question;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn question_roundtrip(question in arb_question()) {
            let mut buf = ByteBuf::new_empty(None);
            let encoded_size = question.encode_to_buf(&mut buf, None).expect("shouldn't have failed");
            assert_eq!(encoded_size, buf.len());
            let roundtripped_question = Question::from_buf(&mut buf).expect("shouldn't have failed");
            prop_assert_eq!(question, roundtripped_question, "Question roundtrip test failed");
        }
    }
}
