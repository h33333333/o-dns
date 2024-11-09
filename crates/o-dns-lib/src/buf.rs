use core::str;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::ops::{Deref, DerefMut};

use anyhow::Context;

pub trait FromBuf: Sized {
    fn from_buf(buf: &mut ByteBuf) -> anyhow::Result<Self>;
}

pub trait EncodeToBuf {
    fn encode_to_buf_with_cache<'cache, 'r: 'cache>(
        &'r self,
        buf: &mut ByteBuf,
        label_cache: Option<&mut HashMap<&'cache str, usize>>,
        max_size: Option<usize>,
    ) -> anyhow::Result<usize>;

    fn encode_to_buf(&self, buf: &mut ByteBuf, max_size: Option<usize>) -> anyhow::Result<usize> {
        self.encode_to_buf_with_cache(buf, None, max_size)
    }
}

pub trait EncodedSize {
    fn get_encoded_size(&self, label_cache: Option<&HashMap<&str, usize>>) -> usize;
}

pub struct ByteBuf<'a> {
    buf: Cow<'a, [u8]>,
    // TODO: make writing to this buf respect `pos` to allow reusing buffer with existing data
    // for writing without clearing it first
    pos: usize,
}

impl<'a> Deref for ByteBuf<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buf.as_ref()
    }
}

impl<'a> DerefMut for ByteBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.to_mut()
    }
}

impl<'a> AsRef<[u8]> for ByteBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl<'a> ByteBuf<'a> {
    pub fn new(src: &impl AsRef<[u8]>) -> ByteBuf<'_> {
        ByteBuf {
            buf: Cow::Borrowed(src.as_ref()),
            pos: 0,
        }
    }

    pub fn new_from_vec(src: Vec<u8>) -> ByteBuf<'static> {
        ByteBuf {
            buf: Cow::Owned(src),
            pos: 0,
        }
    }

    pub fn new_empty(capacity: Option<usize>) -> ByteBuf<'static> {
        ByteBuf {
            buf: Cow::Owned(Vec::with_capacity(capacity.unwrap_or(512))),
            pos: 0,
        }
    }

    pub fn into_inner(self) -> Cow<'a, [u8]> {
        self.buf
    }

    pub fn get_inner_mut(&mut self) -> &mut Vec<u8> {
        self.buf.to_mut()
    }

    pub fn clear(&mut self) {
        self.buf.to_mut().clear();
    }

    pub fn reset_pos(&mut self) {
        self.pos = 0;
    }

    pub fn resize(&mut self, new_len: usize) {
        self.buf.to_mut().resize(new_len, 0);
    }

    pub fn read_u8(&mut self) -> anyhow::Result<u8> {
        self.read_bytes(1)
            .and_then(|bytes| bytes.first().copied().context("bug: should be present"))
    }

    pub fn write_u8(&mut self, data: u8) {
        self.buf.to_mut().push(data);
    }

    pub fn set_u8(&mut self, pos: usize, data: u8) -> anyhow::Result<()> {
        self.ensure_length(1, Some(pos))?;
        self.buf.to_mut()[pos] = data;
        Ok(())
    }

    pub fn read_u16(&mut self) -> anyhow::Result<u16> {
        self.read_bytes(2)
            .and_then(|bytes| TryInto::<[u8; 2]>::try_into(bytes).context("bug: should be exactly two bytes in length"))
            .map(u16::from_be_bytes)
    }

    pub fn peek_u16(&self, pos: usize) -> anyhow::Result<u16> {
        self.peek_bytes(pos, 2)
            .and_then(|bytes| TryInto::<[u8; 2]>::try_into(bytes).context("bug: should be exactly two bytes in length"))
            .map(u16::from_be_bytes)
    }

    pub fn write_u16(&mut self, data: u16) -> anyhow::Result<()> {
        self.write_bytes(&data.to_be_bytes(), None)
    }

    pub fn set_u16(&mut self, pos: usize, data: u16) -> anyhow::Result<()> {
        self.write_bytes(&data.to_be_bytes(), Some(pos))
    }

    pub fn read_bytes(&mut self, n: usize) -> anyhow::Result<&[u8]> {
        self.ensure_length(n, None)?;
        let pos = self.pos;
        self.pos += n;
        self.get_range(pos, n)
            .ok_or_else(|| anyhow::anyhow!("bug: should be present"))
    }

    pub fn peek_bytes(&self, pos: usize, n: usize) -> anyhow::Result<&[u8]> {
        self.ensure_length(n, None)?;
        self.get_range(pos, n).context("bug: should be present")
    }

    pub fn write_bytes(&mut self, data: &[u8], at_pos: Option<usize>) -> anyhow::Result<()> {
        let buf: &mut dyn Write = if let Some(pos) = at_pos {
            let buf_len = self.buf.len();
            if buf_len <= pos + data.len() {
                let required_bytes = pos + data.len() - buf_len;
                self.buf.to_mut().resize(buf_len + required_bytes, 0);
            }
            &mut self.buf.to_mut().get_mut(pos..pos + data.len()).unwrap()
        } else {
            self.buf.to_mut()
        };
        buf.write_all(data)
            .context("error while writing data to the underlying buffer")
    }

    pub fn get_qname_length(&self) -> anyhow::Result<usize> {
        let mut pos = self.pos;
        loop {
            self.ensure_length(1, Some(pos))
                .context("malformed packet: expected QNAME label length")?;
            let label_length = self.buf[pos];
            if label_length & 0xC0 == 0xC0 {
                // Jump directive consists of two bytes
                self.ensure_length(2, Some(pos))
                    .context("malformed packet: expected second jump ptr byte in QNAME")?;
                // Skip two jump ptr bytes and return, as we don't care about the QNAME itself
                pos += 2;
                break;
            } else {
                // Account for label length
                self.ensure_length(1 + label_length as usize, Some(pos))
                    .context("malformed packet: expected QNAME label length")?;
                pos += 1 + label_length as usize;

                // Last label, nothing more to parse
                if label_length == 0 {
                    break;
                }
            }
        }

        Ok(pos - self.pos)
    }

    pub fn read_qname(&mut self) -> anyhow::Result<Cow<'static, str>> {
        let mut jumped = false;
        let mut pos = self.pos;
        let mut labels = Vec::new();
        loop {
            self.ensure_length(1, Some(pos))
                .context("malformed packet: expected QNAME label length")?;
            let label_length = self.buf[pos];
            if label_length & 0xC0 == 0xC0 {
                // Jump directive consists of two bytes
                self.ensure_length(2, Some(pos))
                    .context("malformed packet: expected second jump ptr byte in QNAME")?;
                let ptr_second_byte = self.buf[pos + 1] as u16;
                // Construct a jump offset by clearing two MSB bits and joining two bytes
                let offset = ((label_length as u16 ^ 0xC0) << 8) | ptr_second_byte;
                pos = offset as usize;

                if !jumped {
                    // Skip two jump ptr bytes if jumped for the first time to continue parsing after processing QNAME
                    self.pos += 2;
                    jumped = true;
                }
            } else {
                // Account for label length
                pos += 1;

                if label_length != 0 {
                    let label = self.buf.get(pos..pos + label_length as usize).with_context(|| {
                        format!(
                            "malformed packet: expected label of length {} at byte {}",
                            label_length, pos
                        )
                    })?;
                    let label = str::from_utf8(label)
                        .with_context(|| format!("malformed packet: QNAME label at byte {} is not UTF-8", pos))?;
                    labels.push(label);

                    pos += label_length as usize;
                }

                // Update the position if we didn't encounter a jump directive before
                if !jumped {
                    self.pos = pos;
                }

                // Last label, nothing more to parse
                if label_length == 0 {
                    break;
                }
            }
        }

        let qname = if labels.is_empty() {
            "".into()
        } else {
            labels.join(".").into()
        };

        Ok(qname)
    }

    pub fn write_qname<'cache, 'key: 'cache>(
        &mut self,
        qname: &'key str,
        label_cache: Option<&mut HashMap<&'cache str, usize>>,
    ) -> anyhow::Result<usize> {
        let mut total_qname_length = 0;

        let label_start_position = self.buf.len();
        let mut used_cache = false;
        for (idx, label) in qname.split('.').enumerate() {
            if label.len() > 0x3f {
                anyhow::bail!("label is too long ({}): {}", label.len(), label);
            }

            if !label.is_empty() {
                let remaining_qname = qname.splitn(idx + 1, '.').last().unwrap();

                let cached_position = label_cache.as_ref().and_then(|cache| cache.get(remaining_qname));

                if let Some(offset) = cached_position {
                    let jump_ptr = 0xc000 | (*offset as u16);
                    self.write_u16(jump_ptr).context("writing jump PTR")?;
                    used_cache = true;
                } else {
                    self.write_u8(label.len() as u8);
                    self.write_bytes(label.as_bytes(), None)
                        .with_context(|| format!("error while writing label '{}' to the underlying buffer", label))?;
                }

                if used_cache {
                    // PTR bytes
                    total_qname_length += 2;
                    break;
                } else {
                    total_qname_length += 1 + label.as_bytes().len();
                };
            }
        }

        if total_qname_length > 0 {
            label_cache.and_then(|cache| cache.insert(qname, label_start_position));
        }

        if !used_cache {
            self.write_u8(0);
            // Account for the null byte
            total_qname_length += 1;
        }

        Ok(total_qname_length)
    }

    fn ensure_length(&self, n: usize, pos: Option<usize>) -> anyhow::Result<()> {
        if self.buf.len() < pos.unwrap_or(self.pos) + n {
            anyhow::bail!("underlying buffer is too small")
        }
        Ok(())
    }

    fn get_range(&self, pos: usize, len: usize) -> Option<&[u8]> {
        self.buf.get(pos..pos + len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_empty_qname() {
        let qname = &[0x0];
        let mut buf = ByteBuf::new(qname);
        let result = buf.read_qname().expect("shouldn't have failed");
        assert_eq!(result, "");
    }

    #[test]
    fn read_valid_qname() {
        let qname = &[0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0];
        let mut buf = ByteBuf::new(qname);
        let result = buf.read_qname().expect("shouldn't have failed");
        assert_eq!(result, "google.com");
    }

    #[test]
    #[should_panic(expected = "malformed packet: expected label of length 111 at byte 3")]
    fn read_invalid_qname() {
        let qname = &[0x1, 0x67, 0x6f];
        let mut buf = ByteBuf::new(qname);
        buf.read_qname().unwrap();
    }

    #[test]
    #[should_panic(expected = "expected QNAME label length")]
    fn read_qname_without_zero_byte() {
        let qname = &[0x2, 0x67, 0x6f];
        let mut buf = ByteBuf::new(qname);
        buf.read_qname().unwrap();
    }

    #[test]
    fn write_empty_qname() {
        let mut buf = ByteBuf::new_empty(None);
        buf.write_qname("", None).expect("shouldn't have failed");
        assert_eq!(&*buf, &[0x0])
    }

    #[test]
    fn write_qname() {
        let qname = "google.com";
        let mut buf = ByteBuf::new_empty(None);
        buf.write_qname(qname, None).expect("shouldn't have failed");
        assert_eq!(
            &*buf,
            &[0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0,]
        )
    }

    #[test]
    fn write_qname_with_cache() {
        let qname = "api.google.com";
        let domain = qname.split_once('.').unwrap().1;
        let mut buf = ByteBuf::new_empty(None);
        let mut cache = HashMap::new();

        // Should write 'google.com' and add it to cache
        buf.write_qname(domain, Some(&mut cache))
            .expect("shouldn't have failed");
        assert_eq!(cache.len(), 1);
        assert!(cache.get(domain).is_some_and(|pos| *pos == 0));

        // Should write 'api' and point to the rest of the qname using a jump ptr
        buf.write_qname(qname, Some(&mut cache)).expect("shouldn't have failed");
        // Should have cached a new label
        assert_eq!(cache.len(), 2);
        assert!(cache.get(qname).is_some_and(|pos| *pos == 12));

        assert_eq!(
            &*buf,
            &[0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x3, 0x61, 0x70, 0x69, 0xc0, 0x0]
        )
    }

    #[test]
    #[should_panic(
        expected = "label is too long (64): very_very_very_very_very_very_long_label_that_exceeds_max_length"
    )]
    fn write_qname_with_long_label() {
        let qname = "very_very_very_very_very_very_long_label_that_exceeds_max_length.com";
        let mut buf = ByteBuf::new_empty(None);
        buf.write_qname(qname, None).unwrap();
    }

    #[test]
    fn qname_roundtrip() {
        let qname = "google.com";
        let mut buf = ByteBuf::new_empty(None);
        buf.write_qname(qname, None).expect("shouldn't have failed");
        let roundtripped = buf.read_qname().expect("shouldn't have failed");
        assert_eq!(qname, roundtripped);
    }
}
