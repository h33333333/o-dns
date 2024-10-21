use std::collections::HashMap;

use anyhow::Context;

use crate::{ByteBuf, EncodeToBuf, FromBuf};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum QueryOpcode {
    /// Standard query
    #[default]
    QUERY,
    /// Inverse query
    IQUERY,
    /// Status request
    STATUS,
    /// 3-15 opcodes
    UNKNOWN,
}

impl From<u8> for QueryOpcode {
    fn from(value: u8) -> Self {
        match value {
            0 => QueryOpcode::QUERY,
            1 => QueryOpcode::IQUERY,
            2 => QueryOpcode::STATUS,
            _ => QueryOpcode::UNKNOWN,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ResponseCode {
    #[default]
    Success,
    /// Server was unable to interpret the query
    FormatError,
    /// Server was unnable to process the query due to an internal error
    ServerFailure,
    /// Domain name referenced in the query doesn't exist
    NameError,
    /// Requested type of query is not supported by the server
    NotImplemented,
    /// Server refuses to complete the specified operation
    Refused,
    // 6-15 codes
    Unknown,
}

impl From<u8> for ResponseCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ResponseCode::Success,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct DnsHeader {
    /// Unique ID of this request.
    /// A query and its response **must have the same ID**.
    pub id: u16,
    /// Query/Response
    pub is_response: bool,
    /// Kind of query
    pub opcode: QueryOpcode,
    /// Set by the server. Indicates whether a server is authoritative
    pub is_authoritative: bool,
    /// Is set if packet is larger than **512 bytes**
    pub truncation: bool,
    /// Set by the sender. Enables recursive resolution
    pub recursion_desired: bool,
    /// Set by the server. Indicate whether recursion is allowed
    pub recursion_available: bool,
    /// Used for DNSSEC
    pub z: [bool; 3],
    /// Set by the server. Indicates status of the response
    pub response_code: ResponseCode,
    /// Number of entries in the *Question* section
    pub question_count: u16,
    /// Number of entries in the *Answer* section
    pub answer_rr_count: u16,
    /// Number of entries in the *Authority* section
    pub authority_rr_count: u16,
    /// Number of entries in the *Additional* section
    pub additional_rr_count: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        DnsHeader::default()
    }

    pub fn get_flags(&self) -> u16 {
        let first_byte = (self.is_response as u8) << 7
            | (self.opcode as u8) << 3
            | (self.is_authoritative as u8) << 2
            | (self.truncation as u8) << 1
            | self.recursion_desired as u8;
        let second_byte = (self.recursion_available as u8) << 7
            | (self.z[0] as u8) << 6
            | (self.z[1] as u8) << 5
            | (self.z[2] as u8) << 4
            | self.response_code as u8;
        (first_byte as u16) << 8 | (second_byte as u16)
    }
}

impl FromBuf for DnsHeader {
    fn from_buf(buf: &mut ByteBuf) -> anyhow::Result<Self> {
        let id = buf.read_u16().context("id is missing")?;
        let flags = buf.read_u16().context("flags are missing")?;

        let is_response = ((flags & 0x8000) >> 15) == 1;
        let opcode: QueryOpcode = (((flags & 0x7800) >> 11) as u8).into();
        let is_authoritative = ((flags & 0x400) >> 10) == 1;
        let truncation = ((flags & 0x200) >> 9) == 1;
        let recursion_desired = ((flags & 0x100) >> 8) == 1;
        let recursion_available = ((flags & 0x80) >> 7) == 1;
        let z = {
            let bit_1 = ((flags & 0x40) >> 6) == 1;
            let bit_2 = ((flags & 0x20) >> 5) == 1;
            let bit_3 = ((flags & 0x10) >> 4) == 1;
            [bit_1, bit_2, bit_3]
        };
        let response_code: ResponseCode = ((flags & 0xf) as u8).into();
        let question_count = u16::from_be_bytes(
            buf.read_bytes(2)
                .context("question count is missing")?
                .try_into()
                .unwrap(),
        );
        let answer_rr_count = u16::from_be_bytes(
            buf.read_bytes(2)
                .context("answer RR count is missing")?
                .try_into()
                .unwrap(),
        );
        let authority_rr_count = u16::from_be_bytes(
            buf.read_bytes(2)
                .context("authority RR count is missing")?
                .try_into()
                .unwrap(),
        );
        let additional_rr_count = u16::from_be_bytes(
            buf.read_bytes(2)
                .context("additional RR count is missing")?
                .try_into()
                .unwrap(),
        );

        Ok(DnsHeader {
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
            additional_rr_count,
        })
    }
}

impl EncodeToBuf for DnsHeader {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        _label_cache: Option<&mut HashMap<&'cache str, usize>>,
    ) -> anyhow::Result<()> {
        buf.write_u16(self.id).context("writing ID")?;
        buf.write_u16(self.get_flags()).context("writing flags")?;
        buf.write_u16(self.question_count)
            .context("writing question count")?;
        buf.write_u16(self.answer_rr_count)
            .context("writing answer count")?;
        buf.write_u16(self.authority_rr_count)
            .context("writing authority count")?;
        buf.write_u16(self.additional_rr_count)
            .context("writing additional count")?;

        Ok(())
    }

    fn get_encoded_size(&self) -> usize {
        2 /* ID */ + 2 /* flags */ + 2 /* question count */
            + 2 /* answer count */ + 2 /* authority count */ + 2 /* additional count */
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dns_header_parsing() {
        let stub_header = &mut [
            0x0, 0xff, 0x95, 0xa4, 0x0, 0x6, 0x0, 0x7, 0x0, 0x8, 0x0, 0x9,
        ];
        let mut buf = ByteBuf::new(stub_header);
        let header = DnsHeader::from_buf(&mut buf).expect("shouldn't have failed");

        assert_eq!(header.id, 255);
        assert!(header.is_response);
        assert_eq!(header.opcode, QueryOpcode::STATUS);
        assert!(header.is_authoritative);
        assert!(!header.truncation);
        assert!(header.recursion_desired);
        assert!(header.recursion_available);
        assert!(!header.z[0]);
        assert!(header.z[1]);
        assert!(!header.z[2]);
        assert_eq!(header.question_count, 6);
        assert_eq!(header.answer_rr_count, 7);
        assert_eq!(header.authority_rr_count, 8);
        assert_eq!(header.additional_rr_count, 9);
    }

    proptest! {
        #[test]
        fn dns_header_roundtrip(dns_header: DnsHeader) {
            let mut buf = ByteBuf::new_empty(None);
            dns_header.encode_to_buf(&mut buf).expect("shouldn't have failed");
            let roundtripped_header = DnsHeader::from_buf(&mut buf).expect("shouldn't have failed");
            prop_assert_eq!(dns_header, roundtripped_header, "DnsHeader roundtrip test failed");
        }
    }
}
