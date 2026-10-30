//! `flirt-sig <file.sig> [--dump N|all]`: prints the header, the module count and the
//! first N modules (default 5).

use std::fmt::Write as _;
use std::process::ExitCode;

use flirt_sig::{Extra40, Header, InsnBits, Module, Signature, Site};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (path, dump) = match args.as_slice() {
        [path] => (path, Some(5)),
        [path, flag, n] if flag == "--dump" => match n.as_str() {
            "all" => (path, None),
            n => match n.parse() {
                Ok(n) => (path, Some(n)),
                Err(_) => return usage(),
            },
        },
        _ => return usage(),
    };
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sig = match Signature::parse(&data) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_header(&sig.header);
    println!("modules={}", sig.modules.len());
    let count = dump.unwrap_or(sig.modules.len());
    for module in sig.modules.iter().take(count) {
        println!("{}", format_module(module));
    }
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("usage: flirt-sig <file.sig> [--dump N|all]");
    ExitCode::FAILURE
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
