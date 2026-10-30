//! `flirt-sig dump <file.sig> [N|all]` prints the header, the module count and the first
//! N modules (default 5).
//!
//! `flirt-sig scan <file.sig> <binary> [--sweep]` matches the signature against the
//! executable sections of an ELF, PE or Mach-O file and prints `address name` for each
//! public of each matching module. By default it tries the function starts it can find
//! (symbols, `.eh_frame`, `.pdata`); `--sweep` tries every byte offset instead.

mod starts;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::process::ExitCode;

use flirt_sig::{Endian, Extra40, Header, Hit, InsnBits, Matcher, Module, Signature, Site};
use object::{Object, ObjectSection, SectionKind};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, sig] if cmd == "dump" => dump(sig, Some(5)),
        [cmd, sig, n] if cmd == "dump" => match n.as_str() {
            "all" => dump(sig, None),
            n => match n.parse() {
                Ok(n) => dump(sig, Some(n)),
                Err(_) => return usage(),
            },
        },
        [cmd, sig, binary] if cmd == "scan" => scan(sig, binary, false),
        [cmd, sig, binary, flag] if cmd == "scan" && flag == "--sweep" => scan(sig, binary, true),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: flirt-sig dump <file.sig> [N|all]");
    eprintln!("       flirt-sig scan <file.sig> <binary> [--sweep]");
    ExitCode::FAILURE
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn load(path: &str) -> Result<Signature, String> {
    Signature::parse(&read(path)?).map_err(|e| format!("{path}: {e}"))
}

fn dump(path: &str, count: Option<usize>) -> Result<(), String> {
    let sig = load(path)?;
    print_header(&sig.header);
    println!("modules={}", sig.modules.len());
    let count = count.unwrap_or(sig.modules.len());
    for module in sig.modules.iter().take(count) {
        println!("{}", format_module(module));
    }
    Ok(())
}

fn scan(sig_path: &str, binary_path: &str, sweep: bool) -> Result<(), String> {
    let sig = load(sig_path)?;
    let data = read(binary_path)?;
    let file = object::File::parse(&*data).map_err(|e| format!("{binary_path}: {e}"))?;
    let endian = if file.is_little_endian() {
        Endian::Little
    } else {
        Endian::Big
    };
    let matcher = Matcher::new(&sig, endian);
    let starts = if sweep {
        BTreeSet::new()
    } else {
        starts::function_starts(&file)
    };
    if !sweep && starts.is_empty() {
        return Err(format!(
            "{binary_path}: no function starts found; try --sweep"
        ));
    }
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let code = section.data().map_err(|e| format!("{binary_path}: {e}"))?;
        let base = section.address();
        let hits = if sweep {
            matcher.scan(code)
        } else {
            starts
                .range(base..base + code.len() as u64)
                .filter_map(|&address| {
                    let offset = (address - base) as usize;
                    let modules = matcher.match_at(&code[offset..]);
                    (!modules.is_empty()).then_some(Hit { offset, modules })
                })
                .collect()
        };
        for hit in hits {
            let start = base + hit.offset as u64;
            let ambiguous = hit.modules.len() > 1;
            for module in &hit.modules {
                for public in &module.publics {
                    let address = start.wrapping_add_signed(public.offset);
                    let mut line =
                        format!("{address:#x} {}", String::from_utf8_lossy(&public.name));
                    if public.offset != 0 {
                        write!(line, " [in module at {start:#x}]").unwrap();
                    }
                    if ambiguous {
                        line.push_str(" (ambiguous)");
                    }
                    println!("{line}");
                }
            }
        }
    }
    Ok(())
}

fn print_header(h: &Header) {
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".into());
    println!("version={}", h.version);
    println!("processor={}", h.processor);
    println!("file_formats={:#x}", h.file_formats);
    println!("os_types={:#x}", h.os_types);
    println!("app_types={:#x}", h.app_types);
    println!("flags={:#x}", h.flags);
    println!("module_count_v5={}", h.module_count_v5);
    println!("ctype_crc={:#06x}", h.ctype_crc);
    println!("ctype_name={}", String::from_utf8_lossy(&h.ctype_name));
    println!(
        "ctype_crc_alt={}",
        opt(h.ctype_crc_alt.map(|v| format!("{v:#06x}")))
    );
    println!(
        "module_count={}",
        opt(h.module_count.map(|v| v.to_string()))
    );
    println!("pattern_len={}", h.pattern_len);
    println!(
        "ctype_crc_3v={}",
        opt(h.ctype_crc_3v.map(|v| format!("{v:#06x}")))
    );
    println!("toolchain={}", opt(h.toolchain.map(|v| v.to_string())));
    println!("library_name={}", h.library_name);
}

fn format_module(m: &Module) -> String {
    let mut s = String::new();
    for byte in &m.pattern {
        match byte {
            Some(b) => write!(s, "{b:02X}").unwrap(),
            None => s.push_str(".."),
        }
    }
    write!(
        s,
        " crc_len={} crc={:04X} len={}",
        m.crc_len, m.crc, m.length
    )
    .unwrap();
    s.push_str(" pub=[");
    for (i, p) in m.publics.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(
            s,
            "{}/{:#x}/{}",
            p.offset,
            p.flags,
            String::from_utf8_lossy(&p.name)
        )
        .unwrap();
        push_extras(&mut s, p.insn_bits, p.extra_40, None);
    }
    s.push_str("] tail=[");
    for (i, t) in m.tail_bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(s, "{}:{:02X}", t.offset, t.value).unwrap();
    }
    s.push(']');
    if let Some(r) = &m.reference {
        write!(s, " ref={}/{}", r.offset, String::from_utf8_lossy(&r.name)).unwrap();
    }
    if !m.sites.is_empty() {
        write!(s, " sites={}", format_sites(&m.sites)).unwrap();
    }
    for alt in &m.alt_sites {
        write!(s, " alt={}", format_sites(alt)).unwrap();
    }
    s
}

fn format_sites(sites: &[Site]) -> String {
    let mut s = String::from("[");
    for (i, site) in sites.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(
            s,
            "{}/{:#x}/{}",
            site.offset,
            site.flags,
            String::from_utf8_lossy(&site.name)
        )
        .unwrap();
        push_extras(&mut s, site.insn_bits, site.extra_40, site.extra_08);
    }
    s.push(']');
    s
}

fn push_extras(s: &mut String, bits: Option<InsnBits>, x40: Option<Extra40>, x08: Option<u32>) {
    if let Some(b) = bits {
        write!(s, "/m={:#x},v={:#x}", b.mask, b.value).unwrap();
    }
    if let Some(Extra40(a, b, c)) = x40 {
        write!(s, "/x40={a:#x},{b:#x},{c:#x}").unwrap();
    }
    if let Some(v) = x08 {
        write!(s, "/x08={v:#x}").unwrap();
    }
}
