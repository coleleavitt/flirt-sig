//! Name checks and arbitration between candidate modules.

use std::ops::Range;

use crate::{FLAG_STARTUP, Matcher, Module, Site};

/// Names and references of the code being matched, supplied by the caller (for example a
/// disassembler with its symbol table).
pub trait CodeInfo {
    /// The addresses that the instruction containing `address` calls, jumps to or refers
    /// to. Empty when the instruction is not known.
    ///
    /// Signatures store the offset of the operand a fixup patches, so `address` is often
    /// inside the instruction: on x86 it is the displacement of a `call` or a RIP-relative
    /// operand, on AArch64 the instruction itself.
    fn targets(&self, address: u64) -> Vec<u64>;

    /// The name at `address`, if it has one.
    fn name_at(&self, address: u64) -> Option<&[u8]>;
}

/// The outcome of [`Matcher::resolve`] at one address.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution<'a> {
    NoMatch,
    Match(&'a Module),
    /// Some modules match their bytes, but a required name check needs names that are not
    /// known yet. Try again once more of the program has names.
    Delayed,
    /// Several modules pass every check and score the same.
    Ambiguous(Vec<&'a Module>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameCheck {
    Match,
    Mismatch,
    Unknown,
}

/// Modules of at most this many bytes check every site strictly.
const TINY_MODULE: u32 = 0x10;

impl<'a> Matcher<'a> {
    /// Matches the code at `address` and settles between the byte-level candidates.
    ///
    /// A candidate is rejected when a required name check fails: its reference, and in
    /// modules of at most 16 bytes every site (an unnamed site rejects such a module).
    /// Sites naming an `__imp_` import are required in every module. When several
    /// candidates remain, each scores +4 for every site whose target has the expected
    /// name and -4 for every site whose target has another name; the highest score wins.
    /// References to the ctype table (`.`) and startup-signature references are not
    /// checked.
    pub fn resolve(&self, code: &[u8], address: u64, info: &impl CodeInfo) -> Resolution<'a> {
        let mut confirmed = Vec::new();
        let mut pending = false;
        for module in self.match_at(code) {
            match self.required_checks(module, address, info) {
                NameCheck::Match => confirmed.push(module),
                NameCheck::Unknown => pending = true,
                NameCheck::Mismatch => {}
            }
        }
        match confirmed.as_slice() {
            [] if pending => Resolution::Delayed,
            [] => Resolution::NoMatch,
            [module] => Resolution::Match(module),
            _ => arbitrate(confirmed, address, info),
        }
    }

    fn required_checks(&self, m: &Module, address: u64, info: &impl CodeInfo) -> NameCheck {
        let mut result = NameCheck::Match;
        let mut combine = |check| {
            result = match (result, check) {
                (NameCheck::Mismatch, _) | (_, NameCheck::Mismatch) => NameCheck::Mismatch,
                (NameCheck::Unknown, _) | (_, NameCheck::Unknown) => NameCheck::Unknown,
                _ => NameCheck::Match,
            };
        };
        let startup = self.sig.header.flags & FLAG_STARTUP != 0;
        if let Some(reference) = &m.reference
            && !startup
            && reference.name != b"."
            && let Ok(offset) = u64::try_from(reference.offset)
        {
            combine(check_name(info, address + offset, &reference.name));
        }
        let tiny = m.length <= TINY_MODULE;
        for site in &m.sites {
            if !is_named(site) {
                if tiny {
                    return NameCheck::Mismatch;
                }
                continue;
            }
            if tiny || site.name.starts_with(b"__imp_") {
                combine(check_name(
                    info,
                    address + u64::from(site.offset),
                    &site.name,
                ));
            }
        }
        result
    }
}

/// A site that names its target. One-character names (`?`, `.`) are placeholders, and
/// flag 0x08 marks a site without a usable name.
fn is_named(site: &Site) -> bool {
    site.name.len() >= 2 && site.flags & 0x08 == 0
}

fn names_equal(name: &[u8], expected: &[u8]) -> bool {
    name == expected || name.strip_prefix(b"__imp_") == Some(expected)
}

fn check_name(info: &impl CodeInfo, insn: u64, expected: &[u8]) -> NameCheck {
    let mut named = false;
    for target in info.targets(insn) {
        match info.name_at(target) {
            Some(name) if names_equal(name, expected) => return NameCheck::Match,
            Some(_) => named = true,
            None => {}
        }
    }
    if named {
        NameCheck::Mismatch
    } else {
        NameCheck::Unknown
    }
}

fn arbitrate<'a>(
    candidates: Vec<&'a Module>,
    address: u64,
    info: &impl CodeInfo,
) -> Resolution<'a> {
    let scored: Vec<_> = candidates
        .into_iter()
        .map(|m| (score(m, address, info), m))
        .collect();
    let best = scored.iter().map(|&(s, _)| s).max().unwrap_or_default();
    let mut top: Vec<_> = scored
        .into_iter()
        .filter(|&(s, _)| s == best)
        .map(|(_, m)| m)
        .collect();
    if top.len() == 1 {
        Resolution::Match(top.remove(0))
    } else {
        Resolution::Ambiguous(top)
    }
}

/// The arbitration score of a module: its sites, plus the best of its alternative site
/// tables. Address sites (flag 0x20) and flag-0x08 sites do not count.
fn score(m: &Module, address: u64, info: &impl CodeInfo) -> i32 {
    let body = address..address + u64::from(m.length);
    let table = |sites: &[Site]| -> i32 {
        sites
            .iter()
            .filter(|s| s.name.len() >= 2 && s.flags & 0x28 == 0)
            .map(|s| site_score(info, address + u64::from(s.offset), &s.name, &body))
            .sum()
    };
    let alternatives = m.alt_sites.iter().map(|t| table(t)).max().unwrap_or(0);
    table(&m.sites) + alternatives
}

/// +4 when the site's target has the expected name, -4 when it has another name, 0 when
/// it is unnamed or inside the module itself.
fn site_score(info: &impl CodeInfo, insn: u64, expected: &[u8], body: &Range<u64>) -> i32 {
    let mut score = 0;
    for target in info.targets(insn) {
        if body.contains(&target) {
            continue;
        }
        match info.name_at(target) {
            Some(name) if names_equal(name, expected) => return 4,
            Some(_) => score = -4,
            None => {}
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{Endian, Header, Public, Reference, Signature};

    /// Calls from instruction addresses to targets, and names of targets.
    #[derive(Default)]
    struct Fake {
        calls: HashMap<u64, u64>,
        names: HashMap<u64, Vec<u8>>,
    }

    impl Fake {
        fn call(mut self, from: u64, to: u64, name: Option<&str>) -> Self {
            self.calls.insert(from, to);
            if let Some(name) = name {
                self.names.insert(to, name.into());
            }
            self
        }
    }

    impl CodeInfo for Fake {
        fn targets(&self, address: u64) -> Vec<u64> {
            self.calls.get(&address).copied().into_iter().collect()
        }

        fn name_at(&self, address: u64) -> Option<&[u8]> {
            self.names.get(&address).map(Vec::as_slice)
        }
    }

    const BASE: u64 = 0x1000;
    const CODE: [u8; 4] = [0xe8, 0x00, 0x00, 0x00];

    fn sig(modules: Vec<Module>) -> Signature {
        Signature {
            header: Header {
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
                pattern_len: 4,
                ctype_crc_3v: None,
                toolchain: None,
                library_name: String::new(),
            },
            modules,
        }
    }

    fn module(name: &str, length: u32) -> Module {
        Module {
            pattern: CODE.iter().copied().map(Some).collect(),
            crc_len: 0,
            crc: 0,
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

    fn site(offset: u32, name: &str) -> Site {
        Site {
            offset,
            name: name.into(),
            flags: 0,
            insn_bits: None,
            extra_40: None,
            extra_08: None,
        }
    }

    fn resolved_name(r: &Resolution<'_>) -> Option<String> {
        match r {
            Resolution::Match(m) => Some(String::from_utf8_lossy(&m.publics[0].name).into()),
            _ => None,
        }
    }

    #[test]
    fn reference_must_name_the_target() {
        let mut m = module("wrapper", 4);
        m.reference = Some(Reference {
            offset: 0,
            name: b"exit".to_vec(),
        });
        let sig = sig(vec![m]);
        let matcher = Matcher::new(&sig, Endian::Little);
        let right = Fake::default().call(BASE, 0x2000, Some("exit"));
        let import = Fake::default().call(BASE, 0x2000, Some("__imp_exit"));
        let wrong = Fake::default().call(BASE, 0x2000, Some("abort"));
        let unnamed = Fake::default().call(BASE, 0x2000, None);
        assert_eq!(
            resolved_name(&matcher.resolve(&CODE, BASE, &right)).as_deref(),
            Some("wrapper")
        );
        assert_eq!(
            resolved_name(&matcher.resolve(&CODE, BASE, &import)).as_deref(),
            Some("wrapper")
        );
        assert_eq!(matcher.resolve(&CODE, BASE, &wrong), Resolution::NoMatch);
        assert_eq!(matcher.resolve(&CODE, BASE, &unnamed), Resolution::Delayed);
    }

    #[test]
    fn tiny_modules_check_every_site() {
        let mut named = module("tiny", 4);
        named.sites = vec![site(0, "exit")];
        let mut unnamed = module("unnamed_site", 4);
        unnamed.sites = vec![site(0, "?")];
        let sig = sig(vec![named, unnamed]);
        let matcher = Matcher::new(&sig, Endian::Little);
        let info = Fake::default().call(BASE, 0x2000, Some("exit"));
        assert_eq!(
            resolved_name(&matcher.resolve(&CODE, BASE, &info)).as_deref(),
            Some("tiny")
        );
        let wrong = Fake::default().call(BASE, 0x2000, Some("abort"));
        assert_eq!(matcher.resolve(&CODE, BASE, &wrong), Resolution::NoMatch);
    }

    #[test]
    fn long_modules_only_score_sites() {
        // Both modules pass the byte checks; the site names decide.
        let mut calls_exit = module("calls_exit", 64);
        calls_exit.sites = vec![site(0, "exit")];
        let mut calls_abort = module("calls_abort", 64);
        calls_abort.sites = vec![site(0, "abort")];
        let mut code = CODE.to_vec();
        code.resize(64, 0);
        let sig = sig(vec![calls_exit, calls_abort]);
        let matcher = Matcher::new(&sig, Endian::Little);
        let info = Fake::default().call(BASE, 0x2000, Some("abort"));
        assert_eq!(
            resolved_name(&matcher.resolve(&code, BASE, &info)).as_deref(),
            Some("calls_abort")
        );
        // Unnamed target: a tie.
        let unnamed = Fake::default().call(BASE, 0x2000, None);
        assert!(
            matches!(matcher.resolve(&code, BASE, &unnamed), Resolution::Ambiguous(v) if v.len() == 2)
        );
    }

    #[test]
    fn alternative_tables_score_their_best() {
        let mut m = module("tzset", 64);
        m.alt_sites = vec![vec![site(0, "dststart")], vec![site(0, "dstend")]];
        let other = module("other", 64);
        let mut code = CODE.to_vec();
        code.resize(64, 0);
        let sig = sig(vec![m, other]);
        let matcher = Matcher::new(&sig, Endian::Little);
        let info = Fake::default().call(BASE, 0x2000, Some("dstend"));
        assert_eq!(
            resolved_name(&matcher.resolve(&code, BASE, &info)).as_deref(),
            Some("tzset")
        );
    }
}
