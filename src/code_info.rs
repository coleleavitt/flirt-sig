//! A [`CodeInfo`] over an object file: names from its symbol tables, and the targets of
//! the few instruction forms that can be read without a disassembler. On x86-64 a
//! signature's fixup offset points at a 32-bit displacement relative to the end of the
//! instruction (calls, jumps and RIP-relative operands); on i386 at a relative call or
//! jump displacement, or at an absolute address; on AArch64 at a `b` or `bl`. Other
//! forms report no targets, so checks on them stay unresolved.

use std::collections::HashMap;

use flirt_sig::CodeInfo;
use object::{Architecture, Object, ObjectSection, ObjectSymbol, SectionKind};

pub struct ObjectInfo<'data> {
    architecture: Architecture,
    /// Name of each address; global symbols win over local ones.
    names: HashMap<u64, (&'data [u8], bool)>,
    code: Vec<(u64, &'data [u8])>,
}

impl<'data> ObjectInfo<'data> {
    pub fn new(file: &object::File<'data>) -> Self {
        let mut names: HashMap<u64, (&'data [u8], bool)> = HashMap::new();
        for symbol in file.symbols().chain(file.dynamic_symbols()) {
            let Ok(name) = symbol.name_bytes() else {
                continue;
            };
            if name.is_empty() || !symbol.is_definition() {
                continue;
            }
            let global = symbol.is_global();
            names
                .entry(symbol.address())
                .and_modify(|entry| {
                    if global && !entry.1 {
                        *entry = (name, global);
                    }
                })
                .or_insert((name, global));
        }
        let code = file
            .sections()
            .filter(|s| s.kind() == SectionKind::Text)
            .filter_map(|s| Some((s.address(), s.data().ok()?)))
            .collect();
        Self {
            architecture: file.architecture(),
            names,
            code,
        }
    }

    fn bytes_at(&self, address: u64, len: usize) -> Option<&'data [u8]> {
        self.code.iter().find_map(|&(start, data)| {
            let offset = usize::try_from(address.checked_sub(start)?).ok()?;
            data.get(offset..offset.checked_add(len)?)
        })
    }
}

impl CodeInfo for ObjectInfo<'_> {
    fn targets(&self, address: u64) -> Vec<u64> {
        let target = match self.architecture {
            Architecture::X86_64 => self
                .displacement(address)
                .map(|d| (address + 4).wrapping_add_signed(d.into())),
            Architecture::I386 => self.i386_target(address),
            Architecture::Aarch64 => self.aarch64_target(address),
            _ => None,
        };
        target.into_iter().collect()
    }

    fn name_at(&self, address: u64) -> Option<&[u8]> {
        self.names.get(&address).map(|&(name, _)| name)
    }
}

impl ObjectInfo<'_> {
    fn displacement(&self, address: u64) -> Option<i32> {
        let bytes = self.bytes_at(address, 4)?;
        Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i386_target(&self, address: u64) -> Option<u64> {
        let value = self.displacement(address)?;
        let opcode = self.bytes_at(address.checked_sub(1)?, 1)?[0];
        if matches!(opcode, 0xe8 | 0xe9) {
            Some((address + 4).wrapping_add_signed(value.into()))
        } else {
            Some(u64::from(value.cast_unsigned()))
        }
    }

    fn aarch64_target(&self, address: u64) -> Option<u64> {
        let word = self.bytes_at(address, 4)?;
        let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        // B and BL: bits 30..26 are 00101, then a 26-bit word offset.
        if word & 0x7c00_0000 != 0x1400_0000 {
            return None;
        }
        let offset = i64::from(((word << 6).cast_signed()) >> 6) * 4;
        Some(address.wrapping_add_signed(offset))
    }
}
