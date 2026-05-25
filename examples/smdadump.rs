//! Minimal smda example / smoke test.
//!
//! Usage:
//!   cargo run --release --example smdadump -- <path-to-binary>
//!
//! Prints a summary of the disassembly result: format / architecture /
//! bitness / base addr, function count, and the first few functions with
//! their block + instruction counts. Exits non-zero on parse or
//! disassembly failure.

use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: smdadump <path-to-binary>");
            return ExitCode::from(2);
        }
    };

    // Zero-copy disassembly: load the file ourselves, then pass the buffer
    // to `parse`. The returned report borrows from `buf`, so `buf` must
    // outlive `report` (enforced by the borrow checker).
    let buf = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    // 0.5.0: positional bool args → SmdaConfig builder.
    let cfg = smda::SmdaConfig::new().path(&path);
    let report = match smda::Disassembler::parse(&buf, &cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("parse failed: {e}");
            return ExitCode::from(1);
        }
    };

    println!("path         : {path}");
    println!("format       : {:?}", report.format);
    println!("architecture : {:?}", report.architecture);
    println!("bitness      : {}", report.bitness);
    println!("base addr    : 0x{:x}", report.base_addr);
    println!("functions    : {}", report.functions.len());

    if !report.binary_info.imports.is_empty() {
        println!(
            "imports      : {} entries (showing first 5)",
            report.binary_info.imports.len()
        );
        for (dll, api, _) in report.binary_info.imports.iter().take(5) {
            println!("  {dll}!{api}");
        }
    }

    let funcs = match report.get_functions() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("get_functions failed: {e}");
            return ExitCode::from(1);
        }
    };
    let mut sorted: Vec<(&u64, &smda::function::Function)> = funcs.iter().collect();
    sorted.sort_by_key(|(addr, _)| **addr);

    println!("--- first 10 functions ---");
    for (addr, func) in sorted.iter().take(10) {
        let blocks = match func.get_blocks() {
            Ok(b) => b.len(),
            Err(_) => 0,
        };
        let insns = func.get_num_instructions().unwrap_or(0);
        let outrefs = func.get_num_outrefs().unwrap_or(0);
        println!(
            "  0x{:08x}  {:4} blocks  {:6} insns  {:4} outrefs",
            addr, blocks, insns, outrefs
        );
    }

    // Show how many functions got a name (Go pclntab, MinGW DWARF, ELF
    // symbols, Delphi VMT) plus a few examples.
    let named: Vec<(&u64, &smda::function::Function)> = sorted
        .iter()
        .filter(|(_, f)| !f.function_name().is_empty())
        .map(|(a, f)| (*a, *f))
        .collect();
    println!("--- named functions: {} ---", named.len());
    for (addr, func) in named.iter().take(10) {
        println!("  0x{:08x}  {}", addr, func.function_name());
    }

    ExitCode::SUCCESS
}
