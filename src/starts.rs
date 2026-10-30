//! Function start addresses of an object file: defined function symbols, ELF
//! `.eh_frame` FDEs and PE `.pdata` entries. Stripped binaries usually keep the last two.

use std::collections::BTreeSet;

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SymbolKind};

pub fn function_starts(file: &object::File<'_>) -> BTreeSet<u64> {
    let mut starts = BTreeSet::new();
    // ARM symbols mark Thumb code with bit 0.
    let address_mask = if file.architecture() == Architecture::Arm {
        !1
    } else {
        !0
    };
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.kind() == SymbolKind::Text && symbol.is_definition() && symbol.address() != 0 {
            starts.insert(symbol.address() & address_mask);
        }
    }
    add_eh_frame_starts(file, &mut starts);
    add_pdata_starts(file, &mut starts);
    starts
}

fn add_eh_frame_starts(file: &object::File<'_>, starts: &mut BTreeSet<u64>) {
    let Some(section) = file.section_by_name(".eh_frame") else {
        return;
    };
    let Ok(data) = section.data() else {
        return;
    };
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut eh_frame = EhFrame::new(data, endian);
    eh_frame.set_address_size(if file.is_64() { 8 } else { 4 });
    let bases = BaseAddresses::default().set_eh_frame(section.address());
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry
            && let Ok(fde) = partial.parse(EhFrame::cie_from_offset)
        {
            starts.insert(fde.initial_address());
        }
    }
}

fn add_pdata_starts(file: &object::File<'_>, starts: &mut BTreeSet<u64>) {
    if file.format() != BinaryFormat::Pe {
        return;
    }
    let entry_size = match file.architecture() {
        Architecture::X86_64 => 12,
        Architecture::Aarch64 => 8,
        _ => return,
    };
    let Some(data) = file.section_by_name(".pdata").and_then(|s| s.data().ok()) else {
        return;
    };
    let image_base = file.relative_address_base();
    for entry in data.chunks_exact(entry_size) {
        let rva = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if rva != 0 {
            starts.insert(image_base + u64::from(rva));
        }
    }
}
