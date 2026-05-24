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

    let report = match smda::Disassembler::disassemble_file(&path, false, false, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("disassemble_file failed: {e}");
            return ExitCode::from(1);
        }
    };

    println!("path         : {path}");
    println!("format       : {:?}", report.format);
    println!("architecture : {:?}", report.architecture);
    println!("bitness      : {}", report.bitness);
    println!("base addr    : 0x{:x}", report.base_addr);
    println!("functions    : {}", report.functions.len());

    if !report.imports.is_empty() {
        println!(
            "imports      : {} entries (showing first 5)",
            report.imports.len()
        );
        for (dll, api, _) in report.imports.iter().take(5) {
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

    ExitCode::SUCCESS
}
