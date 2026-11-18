//! Reads the numbers and lists of sing's `varbin`, in which binary
//! rule-sets are written: uvarint counts, big-endian integers.

use anyhow::{anyhow, Result};

pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(anyhow!("unexpected end of data"));
        }
        let (taken, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(taken)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    pub(crate) fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(anyhow!("uvarint overflows"))
    }

    /// A count, which cannot be more than what is left to read, each item
    /// taking `item_len` bytes at least.
    pub(crate) fn count(&mut self, item_len: usize) -> Result<usize> {
        let count = self.uvarint()?;
        if count > (self.data.len() / item_len.max(1)) as u64 {
            return Err(anyhow!("count {} past the end of data", count));
        }
        Ok(count as usize)
    }

    pub(crate) fn u64_be(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }

    pub(crate) fn u16_be(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u64_slice(&mut self) -> Result<Vec<u64>> {
        let count = self.count(8)?;
        (0..count).map(|_| self.u64_be()).collect()
    }

    pub(crate) fn u16_slice(&mut self) -> Result<Vec<u16>> {
        let count = self.count(2)?;
        (0..count).map(|_| self.u16_be()).collect()
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.count(1)?;
        self.take(len)
    }

    pub(crate) fn strings(&mut self) -> Result<Vec<String>> {
        let count = self.count(1)?;
        (0..count)
            .map(|_| {
                String::from_utf8(self.bytes()?.to_vec()).map_err(|_| anyhow!("invalid utf-8"))
            })
            .collect()
    }

    /// An address: its length, 4 or 16, then its bytes. One of 16 is
    /// IPv6, an IPv4-mapped one too, as Go's netip and sing-box read it.
    pub(crate) fn addr(&mut self) -> Result<std::net::IpAddr> {
        match self.uvarint()? {
            4 => {
                let b: [u8; 4] = self.take(4)?.try_into().expect("4 bytes");
                Ok(std::net::IpAddr::from(b))
            }
            16 => {
                let b: [u8; 16] = self.take(16)?.try_into().expect("16 bytes");
                Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)))
            }
            n => Err(anyhow!("invalid address length {}", n)),
        }
    }
}
