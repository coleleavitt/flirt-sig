//! Reader for IDA FLIRT `.sig` signature files.
//!
//! The layout follows the reader in IDA 9.5's `libida.so`. Format versions 5 to 11 are
//! covered: [`Signature::parse`] consumes every byte of each of the 212 signature files
//! shipped with IDA 9.5. Version 12 and later are rejected, as IDA 9.5 does.
//!
//! A signature file is a header followed by a prefix tree of byte patterns. Each leaf holds
//! one or more [`Module`]s: the full pattern, a CRC-16 over the bytes after the pattern, the
//! public names the module defines, and optional tail bytes, a referenced name and
//! (version 11) relocation sites.
//!
//! [`Matcher`] checks modules against code: pattern, CRC-16, tail bytes and expected
//! instruction bits. [`Matcher::resolve`] adds the name checks and the arbitration
//! between candidates, using names and references the caller supplies through
//! [`CodeInfo`].

mod matcher;
mod reader;
mod resolve;

use std::io::{self, Read};
use std::sync::Arc;

pub use matcher::{Endian, Matcher};
use reader::Reader;
pub use resolve::{CodeInfo, Resolution};

/// Errors from [`Signature::parse`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a FLIRT signature file (missing IDASGN magic)")]
    BadMagic,
    #[error("unsupported signature version {0} (IDA 9.5 reads up to 11)")]
    UnsupportedVersion(u8),
    #[error("unexpected end of data at offset {offset:#x}")]
    Truncated { offset: usize },
    #[error("{remaining} bytes left after the pattern tree")]
    TrailingData { remaining: usize },
    #[error("cannot decompress the pattern tree")]
    Decompress(#[source] io::Error),
    #[error("the parsed signature would take more than {MAX_EXPANSION} bytes per byte of the file")]
    TooLarge,
    #[error("pattern tree node at offset {offset:#x} runs past the header's pattern length")]
    PatternTooLong { offset: usize },
}

/// [`Signature::parse`] fails with [`Error::TooLarge`] when the decompressed pattern tree
/// and the parsed modules would take more than this many bytes per byte of the file.
/// The signature files shipped with IDA 9.5 take at most 81 (`arc/millicode.sig`).
pub const MAX_EXPANSION: usize = 256;

/// Header flag: a startup signature, matched at the program entry point.
pub const FLAG_STARTUP: u16 = 0x01;
/// Header flag: the pattern tree is deflate-compressed (raw deflate before version 7,
/// a zlib stream from version 7).
pub const FLAG_ZLIB: u16 = 0x10;
/// Header flag: the pattern tree is a zstd frame (version 11).
pub const FLAG_ZSTD: u16 = 0x40;

/// The fixed header of a signature file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub processor: u8,
    pub file_formats: u32,
    pub os_types: u16,
    pub app_types: u16,
    /// `FLAG_*` bits.
    pub flags: u16,
    /// The 16-bit module count of the original header; see [`Header::module_count`].
    pub module_count_v5: u16,
    pub ctype_crc: u16,
    pub ctype_name: Vec<u8>,
    /// Present from version 5.
    pub ctype_crc_alt: Option<u16>,
    /// Present from version 6.
    pub module_count: Option<u32>,
    /// Bytes per pattern; 32 before version 8.
    pub pattern_len: u16,
    /// Present from version 10.
    pub ctype_crc_3v: Option<u16>,
    /// Present from version 11.
    pub toolchain: Option<u8>,
    pub library_name: String,
}

/// A parsed signature file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub header: Header,
    pub modules: Vec<Module>,
}

/// One library module: a leaf of the pattern tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    /// The leading bytes of the module; `None` is a wildcard byte. The modules of one
    /// leaf of the pattern tree share it.
    pub pattern: Arc<[Option<u8>]>,
    /// Number of bytes after the pattern covered by [`Module::crc`].
    pub crc_len: u8,
    /// See [`crc16`].
    pub crc: u16,
    pub length: u32,
    pub publics: Vec<Public>,
    pub tail_bytes: Vec<TailByte>,
    pub reference: Option<Reference>,
    /// Relocation and reference sites (version 11).
    pub sites: Vec<Site>,
    /// Alternative site lists (version 11).
    pub alt_sites: Vec<Vec<Site>>,
}

/// A name the module defines, at an offset from the module start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    pub offset: i64,
    pub flags: u8,
    pub name: Vec<u8>,
    pub insn_bits: Option<InsnBits>,
    pub extra_40: Option<Extra40>,
}

/// A byte the module must contain at `offset`, outside the pattern and CRC range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailByte {
    pub offset: u32,
    pub value: u8,
}

/// A name the module refers to at `offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Negative when the stored name ends in a NUL byte.
    pub offset: i64,
    pub name: Vec<u8>,
}

/// A relocation or reference site (version 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub offset: u32,
    pub name: Vec<u8>,
    pub flags: u8,
    pub insn_bits: Option<InsnBits>,
    pub extra_40: Option<Extra40>,
    /// Payload of flag 0x08; its meaning is not decoded.
    pub extra_08: Option<u32>,
}

/// Expected instruction bits: `insn & mask == value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsnBits {
    pub mask: u32,
    pub value: u32,
}

/// Payload of flag 0x40 on publics and sites; its meaning is not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extra40(pub u32, pub u16, pub u8);

impl Signature {
    /// Parses a whole signature file.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        let header = Header::read(&mut r)?;
        let mut budget = Budget(data.len().saturating_mul(MAX_EXPANSION));
        let body = r.take(r.remaining())?;
        let body = decompress(body, &header, budget.0)?;
        budget.charge(body.len())?;

        let mut r = Reader::new(&body);
        let mut modules = Vec::new();
        read_tree(&mut r, &header, &mut budget, &mut modules)?;
        if r.remaining() != 0 {
            return Err(Error::TrailingData {
                remaining: r.remaining(),
            });
        }
        Ok(Self { header, modules })
    }
}

impl Header {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.take(6).map_err(|_| Error::BadMagic)? != b"IDASGN" {
            return Err(Error::BadMagic);
        }
        let version = r.u8()?;
        if version >= 12 {
            return Err(Error::UnsupportedVersion(version));
        }
        let processor = r.u8()?;
        let file_formats = r.le32()?;
        let os_types = r.le16()?;
        let app_types = r.le16()?;
        let flags = r.le16()?;
        let module_count_v5 = r.le16()?;
        let ctype_crc = r.le16()?;
        let ctype_name = r.take(12)?;
        let ctype_name = ctype_name
            .split(|&b| b == 0)
            .next()
            .unwrap_or_default()
            .to_vec();
        let name_len = r.u8()?;
        let ctype_crc_alt = (version >= 5).then(|| r.le16()).transpose()?;
        let module_count = (version >= 6).then(|| r.le32()).transpose()?;
        let pattern_len = if version >= 8 { r.le16()? } else { 32 };
        let ctype_crc_3v = (version >= 10).then(|| r.le16()).transpose()?;
        let toolchain = (version >= 11).then(|| r.u8()).transpose()?;
        let library_name = r
            .take(name_len.into())?
            .iter()
            .map(|&b| char::from(b))
            .collect();
        Ok(Self {
            version,
            processor,
            file_formats,
            os_types,
            app_types,
            flags,
            module_count_v5,
            ctype_crc,
            ctype_name,
            ctype_crc_alt,
            module_count,
            pattern_len,
            ctype_crc_3v,
            toolchain,
            library_name,
        })
    }
}

/// Bytes the parsed signature may still take; see [`MAX_EXPANSION`].
struct Budget(usize);

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        self.0 = self.0.checked_sub(bytes).ok_or(Error::TooLarge)?;
        Ok(())
    }
}

/// Decompresses the pattern tree, failing with [`Error::TooLarge`] past `limit` bytes.
fn decompress(body: &[u8], header: &Header, limit: usize) -> Result<Vec<u8>, Error> {
    let compressed = header.flags & (FLAG_ZSTD | FLAG_ZLIB) != 0;
    if !compressed {
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    let read = if header.flags & FLAG_ZSTD != 0 {
        let mut input = body;
        ruzstd::decoding::StreamingDecoder::new(&mut input)
            .map_err(io::Error::other)
            .and_then(|d| read_capped(d, limit, &mut out))
    } else if header.version < 7 {
        // Versions 5 and 6 store raw deflate data; later versions add the zlib wrapper.
        read_capped(flate2::read::DeflateDecoder::new(body), limit, &mut out)
    } else {
        read_capped(flate2::read::ZlibDecoder::new(body), limit, &mut out)
    };
    read.map_err(Error::Decompress)?;
    if out.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Reads at most one byte more than `limit`, so the caller can tell that the limit was
/// passed.
fn read_capped(reader: impl Read, limit: usize, out: &mut Vec<u8>) -> io::Result<usize> {
    let limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(limit).read_to_end(out)
}

/// Reads the pattern tree depth-first. A node holds a run of pattern bytes and either
/// child nodes or, with no children, a leaf of modules.
fn read_tree(
    r: &mut Reader<'_>,
    header: &Header,
    budget: &mut Budget,
    out: &mut Vec<Module>,
) -> Result<(), Error> {
    let max_len = usize::from(header.pattern_len);
    let mut pattern = Vec::new();
    // Per open node: the children still to read and the pattern length before them.
    let mut open: Vec<(u16, usize)> = Vec::new();
    loop {
        let children = r.var15()?;
        if children == 0 {
            budget.charge(size_of_val(pattern.as_slice()))?;
            read_leaf(r, header.version, pattern.as_slice().into(), budget, out)?;
        } else {
            open.push((children, pattern.len()));
        }
        loop {
            let Some((left, prefix_len)) = open.last_mut() else {
                return Ok(());
            };
            pattern.truncate(*prefix_len);
            if *left > 0 {
                *left -= 1;
                break;
            }
            open.pop();
        }
        let offset = r.offset();
        let len = if header.version >= 10 {
            usize::from(r.var15()?)
        } else {
            usize::from(r.u8()?)
        };
        if pattern.len() + len > max_len {
            return Err(Error::PatternTooLong { offset });
        }
        for wild in read_wildcards(r, len)? {
            pattern.push(if wild { None } else { Some(r.u8()?) });
        }
    }
}

/// Reads the wildcard mask of a tree node with `len` pattern bytes. The most significant
/// bit belongs to the first byte.
fn read_wildcards(r: &mut Reader<'_>, len: usize) -> Result<Vec<bool>, Error> {
    let bit_of = |bits: u64, i: usize| bits >> (len - 1 - i) & 1 != 0;
    let bits = match len {
        0..0x10 => u64::from(r.var15()?),
        0x10..=0x20 => u64::from(r.var32()?),
        0x21..=0x40 => u64::from(r.var32()?) << 32 | u64::from(r.var32()?),
        _ => {
            // Long node (version 11): a little-endian bitmap.
            let mut bitmap = r.take(len >> 3)?.to_vec();
            if len & 7 != 0 {
                bitmap.push(r.u8()? & ((1 << (len & 7)) - 1));
            }
            let bit = |j: usize| bitmap[j >> 3] >> (j & 7) & 1 != 0;
            return Ok((0..len).map(|i| bit(len - 1 - i)).collect());
        }
    };
    Ok((0..len).map(|i| bit_of(bits, i)).collect())
}

fn read_leaf(
    r: &mut Reader<'_>,
    version: u8,
    pattern: Arc<[Option<u8>]>,
    budget: &mut Budget,
    out: &mut Vec<Module>,
) -> Result<(), Error> {
    let read_offset = |r: &mut Reader<'_>| {
        if version >= 9 {
            r.var32()
        } else {
            r.var15().map(u32::from)
        }
    };
    loop {
        let crc_len = r.u8()?;
        let crc = r.be16()?;
        let mut more;
        loop {
            let length = read_offset(r)?;

            let mut publics = Vec::new();
            let mut offset = 0i64;
            loop {
                let delta = read_offset(r)?;
                let (public, next) = read_public(r, version)?;
                budget.charge(size_of::<Public>() + public.name.len())?;
                let negative = version >= 11 && public.flags & 0x10 != 0;
                offset += if negative {
                    -i64::from(delta)
                } else {
                    i64::from(delta)
                };
                publics.push(Public { offset, ..public });
                more = next;
                if more & 1 == 0 {
                    break;
                }
            }

            let mut tail_bytes = Vec::new();
            if more & 2 != 0 {
                let count = if version >= 8 { r.u8()? } else { 1 };
                for _ in 0..count {
                    let offset = read_offset(r)?;
                    budget.charge(size_of::<TailByte>())?;
                    tail_bytes.push(TailByte {
                        offset,
                        value: r.u8()?,
                    });
                }
            }

            let reference = if more & 4 != 0 {
                let reference = read_reference(r, version)?;
                budget.charge(reference.name.len())?;
                Some(reference)
            } else {
                None
            };

            let sites = if version >= 11 && more & 0x20 != 0 {
                read_sites(r, budget)?
            } else {
                Vec::new()
            };
            let mut alt_sites = Vec::new();
            if version >= 11 && more & 0x40 != 0 {
                for _ in 0..r.var32()? {
                    budget.charge(size_of::<Vec<Site>>())?;
                    alt_sites.push(read_sites(r, budget)?);
                }
            }

            budget.charge(size_of::<Module>())?;
            out.push(Module {
                pattern: Arc::clone(&pattern),
                crc_len,
                crc,
                length,
                publics,
                tail_bytes,
                reference,
                sites,
                alt_sites,
            });
            if more & 8 == 0 {
                break;
            }
        }
        if more & 0x10 == 0 {
            return Ok(());
        }
    }
}

/// Reads a public name. Returns it with offset 0, plus the byte that says what follows.
fn read_public(r: &mut Reader<'_>, version: u8) -> Result<(Public, u8), Error> {
    if version >= 11 {
        let len = r.be16()?;
        let flags = r.u8()?;
        let name = r.take(len.into())?.to_vec();
        let insn_bits = read_insn_bits(r, flags)?;
        let extra_40 = read_extra_40(r, flags)?;
        let public = Public {
            offset: 0,
            flags: flags & 0xbf,
            name,
            insn_bits,
            extra_40,
        };
        return Ok((public, r.u8()?));
    }
    let mut c = r.u8()?;
    let mut flags = 0;
    if c < 0x20 {
        flags = c;
        c = r.u8()?;
    }
    let mut name = Vec::new();
    while c >= 0x20 {
        name.push(c);
        c = r.u8()?;
    }
    let public = Public {
        offset: 0,
        flags,
        name,
        insn_bits: None,
        extra_40: None,
    };
    Ok((public, c))
}

fn read_reference(r: &mut Reader<'_>, version: u8) -> Result<Reference, Error> {
    if version >= 8 {
        r.u8()?; // count; always 1, and IDA ignores it
    }
    let offset = if version >= 9 {
        r.var32()?
    } else {
        r.var15()?.into()
    };
    let len = match r.u8()? {
        0 => usize::from(r.var15()?),
        n => usize::from(n),
    };
    let mut name = r.take(len)?;
    let negative = name.last() == Some(&0);
    while let [rest @ .., 0] = name {
        name = rest;
    }
    let offset = i64::from(offset);
    Ok(Reference {
        offset: if negative { -offset } else { offset },
        name: name.to_vec(),
    })
}

fn read_sites(r: &mut Reader<'_>, budget: &mut Budget) -> Result<Vec<Site>, Error> {
    (0..r.var32()?)
        .map(|_| {
            let site = read_site(r)?;
            budget.charge(size_of::<Site>() + site.name.len())?;
            Ok(site)
        })
        .collect()
}

fn read_site(r: &mut Reader<'_>) -> Result<Site, Error> {
    let offset = r.var32()?;
    let len = r.be16()?;
    let name = r.take(len.into())?.to_vec();
    let flags = r.u8()?;
    let insn_bits = read_insn_bits(r, flags)?;
    let extra_40 = read_extra_40(r, flags)?;
    let extra_08 = (flags & 0x08 != 0).then(|| r.var32()).transpose()?;
    Ok(Site {
        offset,
        name,
        flags,
        insn_bits,
        extra_40,
        extra_08,
    })
}

fn read_insn_bits(r: &mut Reader<'_>, flags: u8) -> Result<Option<InsnBits>, Error> {
    if flags & 0x80 == 0 {
        return Ok(None);
    }
    let mask = r.var32()?;
    let value = r.var32()?;
    Ok(Some(InsnBits { mask, value }))
}

fn read_extra_40(r: &mut Reader<'_>, flags: u8) -> Result<Option<Extra40>, Error> {
    if flags & 0x40 == 0 {
        return Ok(None);
    }
    let a = r.var32()?;
    let b = r.be16()?;
    let c = r.u8()?;
    Ok(Some(Extra40(a, b, c)))
}

/// The module CRC: CRC-16/X.25 with its two result bytes swapped.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    (!crc).swap_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_is_swapped_x25() {
        // CRC-16/X.25 check value for "123456789" is 0x906e.
        assert_eq!(crc16(b"123456789"), 0x6e90);
    }

    /// A version 10 header with pattern length `pattern_len` and flags `flags`.
    fn v10_header(pattern_len: u16, flags: u16) -> Vec<u8> {
        let mut h = b"IDASGN\x0a\x00".to_vec();
        h.extend_from_slice(&[0; 6]); // file_formats, os_types
        h.extend_from_slice(&[0; 2]); // app_types
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&[0; 4 + 12]); // module_count_v5, ctype_crc, ctype_name
        h.push(0); // name length
        h.extend_from_slice(&[0; 2 + 4]); // ctype_crc_alt, module_count
        h.extend_from_slice(&pattern_len.to_le_bytes());
        h.extend_from_slice(&[0; 2]); // ctype_crc_3v
        h
    }

    /// A leaf with `count` modules of one unnamed public each.
    fn leaf(count: usize) -> Vec<u8> {
        let mut leaf = vec![0, 0, 0]; // crc_len, crc
        for i in 0..count {
            let more = if i + 1 < count { 8 } else { 0 };
            // length, delta, public flags, then no name bytes before the terminator
            leaf.extend_from_slice(&[1, 0, 0, more]);
        }
        leaf
    }

    #[test]
    fn deep_tree_does_not_recurse() {
        // 100,000 nested nodes with no pattern bytes: one child, length 0, empty mask.
        let mut sig = v10_header(32, 0);
        sig.extend(std::iter::repeat_n([1, 0, 0], 100_000).flatten());
        sig.push(0);
        sig.extend(leaf(1));
        assert_eq!(Signature::parse(&sig).unwrap().modules.len(), 1);
    }

    #[test]
    fn modules_of_a_leaf_share_the_pattern() {
        let mut sig = v10_header(32, 0);
        sig.extend_from_slice(&[1, 2, 0b00, 0x55, 0xaa, 0]); // one node: 55 aa
        sig.extend(leaf(3));
        let modules = Signature::parse(&sig).unwrap().modules;
        assert_eq!(*modules[0].pattern, [Some(0x55), Some(0xaa)]);
        assert!(
            modules
                .iter()
                .all(|m| Arc::ptr_eq(&m.pattern, &modules[0].pattern))
        );
    }

    #[test]
    fn rejects_patterns_longer_than_the_header_says() {
        let mut sig = v10_header(2, 0);
        sig.extend_from_slice(&[1, 2, 0b11, 1, 1, 0b1, 0]); // 2 wildcards, then 1 more
        sig.extend(leaf(1));
        assert!(matches!(
            Signature::parse(&sig),
            Err(Error::PatternTooLong { offset: 4 })
        ));
    }

    #[test]
    fn rejects_a_decompression_bomb() {
        use std::io::Write;

        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let mut body = ZlibEncoder::new(Vec::new(), Compression::best());
        body.write_all(&[0; 1 << 20]).unwrap();
        let mut sig = v10_header(32, FLAG_ZLIB);
        sig.extend(body.finish().unwrap());
        assert!(matches!(Signature::parse(&sig), Err(Error::TooLarge)));
    }

    #[test]
    fn rejects_bad_magic_and_new_versions() {
        assert!(matches!(Signature::parse(b"NOTSIG"), Err(Error::BadMagic)));
        assert!(matches!(
            Signature::parse(b"IDASGN\x0c"),
            Err(Error::UnsupportedVersion(12))
        ));
    }
}
