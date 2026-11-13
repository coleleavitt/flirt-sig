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
/// [`Matcher::match_at`] checks what the bytes alone decide: the pattern, the CRC-16,
/// the tail bytes and the expected instruction bits of publics and sites.
/// [`Matcher::resolve`] adds the checks that need names of the surrounding code, which
/// the caller supplies through [`crate::CodeInfo`]. Linker relaxation is not modelled.
pub struct Matcher<'a> {
    pub(crate) sig: &'a Signature,
    endian: Endian,
    nodes: Vec<Node>,
}

/// A path-compressed trie over the module patterns. Node 0 is the root and has an empty
/// label; every other node is reached over its `label` (`None` matches any byte).
#[derive(Default)]
struct Node {
    label: Box<[Option<u8>]>,
    /// Children keyed by the first element of their label, sorted (a wildcard first).
    children: Vec<(Option<u8>, u32)>,
    /// Indices of the modules whose pattern ends here.
    modules: Vec<u32>,
}

impl<'a> Matcher<'a> {
    pub fn new(sig: &'a Signature, endian: Endian) -> Self {
        let mut nodes = vec![Node::default()];
        for (index, module) in sig.modules.iter().enumerate() {
            insert(&mut nodes, &module.pattern, index as u32);
        }
        Self { sig, endian, nodes }
    }

    /// The signature this matcher was built from.
    pub fn signature(&self) -> &'a Signature {
        self.sig
    }

    /// The modules that match `code`, which starts at the candidate address.
    pub fn match_at(&self, code: &[u8]) -> Vec<&'a Module> {
        let mut found = Vec::new();
        // Depth-first over (node, bytes matched so far); the wildcard child is visited
        // before the exact one.
        let mut stack = vec![(0, 0)];
        while let Some((node, depth)) = stack.pop() {
            let node = &self.nodes[node];
            found.extend(node.modules.iter().map(|&i| &self.sig.modules[i as usize]));
            let Some(&byte) = code.get(depth) else {
                continue;
            };
            let wildcard = node.children.first().filter(|(k, _)| k.is_none());
            let exact = node
                .children
                .binary_search_by_key(&Some(byte), |&(k, _)| k)
                .ok()
                .map(|i| &node.children[i]);
            for &(_, child) in exact.into_iter().chain(wildcard) {
                let label = &self.nodes[child as usize].label;
                let end = depth + label.len();
                let Some(bytes) = code.get(depth..end) else {
                    continue;
                };
                if label
                    .iter()
                    .zip(bytes)
                    .all(|(p, b)| p.is_none_or(|p| p == *b))
                {
                    stack.push((child as usize, end));
                }
            }
        }
        found.retain(|m| self.leaf_matches(m, code));
        found
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

fn insert(nodes: &mut Vec<Node>, pattern: &[Option<u8>], module: u32) {
    let mut at = 0;
    let mut rest = pattern;
    loop {
        let Some(&first) = rest.first() else {
            nodes[at].modules.push(module);
            return;
        };
        let new = nodes.len() as u32;
        match nodes[at].children.binary_search_by_key(&first, |&(k, _)| k) {
            Err(i) => {
                nodes[at].children.insert(i, (first, new));
                nodes.push(Node {
                    label: rest.into(),
                    children: Vec::new(),
                    modules: vec![module],
                });
                return;
            }
            Ok(i) => {
                let child = nodes[at].children[i].1 as usize;
                let label = &nodes[child].label;
                let common = label.iter().zip(rest).take_while(|(a, b)| a == b).count();
                if common < label.len() {
                    let tail: Box<[Option<u8>]> = label[common..].into();
                    let head: Box<[Option<u8>]> = label[..common].into();
                    nodes[child].label = tail;
                    let key = nodes[child].label[0];
                    nodes.push(Node {
                        label: head,
                        children: vec![(key, child as u32)],
                        modules: Vec::new(),
                    });
                    nodes[at].children[i].1 = new;
                    at = new as usize;
                } else {
                    at = child;
                }
                rest = &rest[common..];
            }
        }
    }
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
            pattern: pattern.into(),
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
    fn deep_trie_does_not_recurse() {
        // Wildcard patterns of every length up to 5,000 make a trie 5,000 nodes deep.
        let depth = 5_000;
        let modules = (1..=depth)
            .map(|len| module(&vec![None; len], "m", 0, 0, 0))
            .collect();
        let sig = Signature {
            header: header(depth as u16),
            modules,
        };
        let found = std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(move || {
                let matcher = Matcher::new(&sig, Endian::Little);
                matcher.match_at(&vec![0; depth]).len()
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(found, depth);
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
}
