//! Byte-level matching of signature modules against code.

use crate::{Module, Signature, crc16};

/// Byte order of instruction words checked by [`crate::InsnBits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Matches the modules of one [`Signature`] against code bytes.
///
/// A module matches at an address when its pattern, its CRC-16, its tail bytes and the
/// expected instruction bits of its publics and sites all agree with the code there.
/// References and site names are not checked: that needs the names of the code the
/// match calls, which the caller has to supply. Linker relaxation is not modelled.
pub struct Matcher<'a> {
    sig: &'a Signature,
    endian: Endian,
    nodes: Vec<Node>,
}

/// A byte-level trie over the module patterns. Node 0 is the root.
#[derive(Default)]
struct Node {
    /// Children for a concrete byte, sorted by byte.
    exact: Vec<(u8, usize)>,
    wildcard: Option<usize>,
    /// Indices of the modules whose pattern ends here.
    modules: Vec<usize>,
}

/// Modules that match at one offset of a scan.
#[derive(Debug)]
pub struct Hit<'a> {
    pub offset: usize,
    pub modules: Vec<&'a Module>,
}

impl<'a> Matcher<'a> {
    pub fn new(sig: &'a Signature, endian: Endian) -> Self {
        let mut nodes = vec![Node::default()];
        for (index, module) in sig.modules.iter().enumerate() {
            let mut at = 0;
            for &byte in &module.pattern {
                at = child(&mut nodes, at, byte);
            }
            nodes[at].modules.push(index);
        }
        Self { sig, endian, nodes }
    }

    /// The modules that match `code`, which starts at the candidate address.
    pub fn match_at(&self, code: &[u8]) -> Vec<&'a Module> {
        let mut found = Vec::new();
        self.walk(0, code, 0, &mut found);
        found.retain(|m| self.leaf_matches(m, code));
        found
    }

    /// Tries every offset of `code`. After a hit, the scan continues after the longest
    /// matching module.
    pub fn scan(&self, code: &[u8]) -> Vec<Hit<'a>> {
        let mut hits = Vec::new();
        let mut offset = 0;
        while offset < code.len() {
            let modules = self.match_at(&code[offset..]);
            let Some(len) = modules.iter().map(|m| m.length as usize).max() else {
                offset += 1;
                continue;
            };
            hits.push(Hit { offset, modules });
            offset += len.max(1);
        }
        hits
    }

    fn walk(&self, node: usize, code: &[u8], depth: usize, found: &mut Vec<&'a Module>) {
        let node = &self.nodes[node];
        found.extend(node.modules.iter().map(|&i| &self.sig.modules[i]));
        let Some(&byte) = code.get(depth) else {
            return;
        };
        if let Ok(i) = node.exact.binary_search_by_key(&byte, |&(b, _)| b) {
            self.walk(node.exact[i].1, code, depth + 1, found);
        }
        if let Some(next) = node.wildcard {
            self.walk(next, code, depth + 1, found);
        }
    }

    /// Checks everything after the pattern. The CRC region starts at the header's pattern
    /// length even when the stored pattern is shorter (trailing wildcards are not stored),
    /// and tail byte offsets count from the end of the CRC region.
    fn leaf_matches(&self, m: &Module, code: &[u8]) -> bool {
        let crc_start = usize::from(self.sig.header.pattern_len);
        let crc_end = crc_start + usize::from(m.crc_len);
        if code.len() < (m.length as usize).max(crc_end) {
            return false;
        }
        if crc16(&code[crc_start..crc_end]) != m.crc {
            return false;
        }
        let tails_ok = m
            .tail_bytes
            .iter()
            .all(|t| code.get(crc_end + t.offset as usize) == Some(&t.value));
        let publics_ok = m.publics.iter().all(|p| match p.insn_bits {
            Some(bits) => {
                usize::try_from(p.offset).is_ok_and(|off| self.insn_matches(code, off, bits))
            }
            None => true,
        });
        let sites_ok = m.sites.iter().all(|s| match s.insn_bits {
            Some(bits) => self.insn_matches(code, s.offset as usize, bits),
            None => true,
        });
        tails_ok && publics_ok && sites_ok
    }

    fn insn_matches(&self, code: &[u8], offset: usize, bits: crate::InsnBits) -> bool {
        let Some(word) = code.get(offset..offset + 4) else {
            return false;
        };
        let word = [word[0], word[1], word[2], word[3]];
        let insn = match self.endian {
            Endian::Little => u32::from_le_bytes(word),
            Endian::Big => u32::from_be_bytes(word),
        };
        (insn ^ bits.value) & bits.mask == 0
    }
}

fn child(nodes: &mut Vec<Node>, at: usize, byte: Option<u8>) -> usize {
    let next = nodes.len();
    match byte {
        None => match nodes[at].wildcard {
            Some(existing) => return existing,
            None => nodes[at].wildcard = Some(next),
        },
        Some(byte) => match nodes[at].exact.binary_search_by_key(&byte, |&(b, _)| b) {
            Ok(i) => return nodes[at].exact[i].1,
            Err(i) => nodes[at].exact.insert(i, (byte, next)),
        },
    }
    nodes.push(Node::default());
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Header, InsnBits, Public, Site, TailByte};

    fn header(pattern_len: u16) -> Header {
        Header {
            version: 11,
            processor: 0,
            file_formats: 0,
            os_types: 0,
            app_types: 0,
            flags: 0,
            module_count_v5: 0,
            ctype_crc: 0,
            ctype_name: Vec::new(),
            ctype_crc_alt: None,
            module_count: None,
            pattern_len,
            ctype_crc_3v: None,
            toolchain: None,
            library_name: String::new(),
        }
    }

    fn module(pattern: &[Option<u8>], name: &str, crc_len: u8, crc: u16, length: u32) -> Module {
        Module {
            pattern: pattern.to_vec(),
            crc_len,
            crc,
            length,
            publics: vec![Public {
                offset: 0,
                flags: 0,
                name: name.into(),
                insn_bits: None,
                extra_40: None,
            }],
            tail_bytes: Vec::new(),
            reference: None,
            sites: Vec::new(),
            alt_sites: Vec::new(),
        }
    }

    fn names(modules: &[&Module]) -> Vec<String> {
        let mut names: Vec<_> = modules
            .iter()
            .map(|m| String::from_utf8_lossy(&m.publics[0].name).into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn pattern_crc_and_tail_bytes() {
        let code = [0x55, 0x48, 0x89, 0xe5, 0xaa, 0xbb, 0xcc, 0x90];
        let mut with_tail = module(&[Some(0x55), None, Some(0x89)], "tail", 2, 0, 8);
        // Pattern length 4, CRC over bytes 4..6, tail offset 1 is byte 7.
        with_tail.crc = crc16(&code[4..6]);
        with_tail.tail_bytes = vec![TailByte {
            offset: 1,
            value: 0x90,
        }];
        let mut bad_tail = with_tail.clone();
        bad_tail.publics[0].name = b"bad_tail".to_vec();
        bad_tail.tail_bytes[0].value = 0x91;
        let mut bad_crc = with_tail.clone();
        bad_crc.publics[0].name = b"bad_crc".to_vec();
        bad_crc.crc ^= 1;
        let short = module(&[Some(0x55), Some(0x48)], "short", 0, 0, 2);
        let too_long = module(&[Some(0x55)], "too_long", 0, 0, 9);
        let sig = Signature {
            header: header(4),
            modules: vec![with_tail, bad_tail, bad_crc, short, too_long],
        };
        let matcher = Matcher::new(&sig, Endian::Little);
        assert_eq!(names(&matcher.match_at(&code)), ["short", "tail"]);
    }

    #[test]
    fn instruction_bits() {
        // BL with a 26-bit immediate: only the opcode bits are fixed.
        let code = 0x9400_1234u32.to_le_bytes();
        let mut m = module(&[None, None, None, None], "bl", 0, 0, 4);
        let bits = InsnBits {
            mask: 0xfc00_0000,
            value: 0x9400_0000,
        };
        m.sites = vec![Site {
            offset: 0,
            name: b"abort".to_vec(),
            flags: 0x80,
            insn_bits: Some(bits),
            extra_40: None,
            extra_08: None,
        }];
        let sig = Signature {
            header: header(4),
            modules: vec![m],
        };
        assert_eq!(Matcher::new(&sig, Endian::Little).match_at(&code).len(), 1);
        assert!(Matcher::new(&sig, Endian::Big).match_at(&code).is_empty());
    }

    #[test]
    fn scan_skips_matched_modules() {
        let code = [0xc3, 0x55, 0x55, 0xc3, 0x55];
        let sig = Signature {
            header: header(2),
            modules: vec![module(&[Some(0x55), Some(0x55)], "pair", 0, 0, 2)],
        };
        let hits = Matcher::new(&sig, Endian::Little).scan(&code);
        let offsets: Vec<_> = hits.iter().map(|h| h.offset).collect();
        assert_eq!(offsets, [1]);
    }
}
