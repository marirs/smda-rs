# smda

[![CI](https://github.com/marirs/smda-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/smda.svg)](https://crates.io/crates/smda)
[![Docs.rs](https://docs.rs/smda/badge.svg)](https://docs.rs/smda)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)

A minimalist recursive x86 / x64 disassembler library, optimized for accurate Control Flow Graph (CFG) recovery from PE / ELF binaries and arbitrary memory dumps.

The output is a collection of functions, basic blocks, and instructions with their respective edges (block-to-block, function-to-function). Optionally, references to the Windows API can be inferred via the ApiScout method.

`smda-rs` is a Rust port of [danielplohmann/smda](https://github.com/danielplohmann/smda) (Python). It powers [capa-rs](https://github.com/marirs/capa-rs), the Rust port of Mandiant's capability extractor.

## What changed in 0.3.0

This is a substantial overhaul of the disassembly backend:

- **Decoder swap: capstone → [iced-x86](https://crates.io/crates/iced-x86).** Pure-Rust, ~2–3× faster than capstone, and gives every consumer typed `Mnemonic` / `OpKind` / `Register` / `FlowControl` enums without re-parsing strings. The old text-based output is preserved bit-for-bit via a `capstone_compat_formatter` so capa-rs and any other downstream that regex-matches operand strings keeps working unchanged.
- **No more C/C++ build dependency** (capstone-sys is gone). Builds on Linux / macOS / Windows with stock rustup.
- **Rust 2024 edition, MSRV 1.95.**
- **Lighter SHA-256.** Switched from `ring` to `sha2` for the buffer hash — drops a large C dependency for a single hash.
- **All dependencies on latest major versions** (`iced-x86 1`, `goblin 0.10`, `thiserror 2`, `itertools 0.14`, `hex 0.4`, `regex 1`, `serde 1`).

See [CHANGELOG.md](CHANGELOG.md) for the full list of breaking changes.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
smda = "0.3"
```

Then disassemble a file:

```rust
use smda::Disassembler;

fn main() -> smda::Result<()> {
    // disassemble_file(path, high_accuracy, resolve_tailcalls, optional_buffer)
    let report = Disassembler::disassemble_file(
        "Sample.exe",
        false,  // high-accuracy heuristics (slower)
        false,  // tail-call resolution
        None,
    )?;

    println!("format       : {:?}", report.format);
    println!("architecture : {:?}", report.architecture);
    println!("bitness      : {}", report.bitness);
    println!("base addr    : 0x{:x}", report.base_addr);
    println!("functions    : {}", report.functions.len());

    for (addr, func) in report.get_functions()?.iter().take(5) {
        let blocks = func.get_blocks()?;
        let insns  = func.get_num_instructions()?;
        println!("  0x{:08x}  {} blocks, {} insns", addr, blocks.len(), insns);
    }
    Ok(())
}
```

## Typed iced accessors

Every `Instruction` exposes both the legacy capstone-shaped fields *and* the fully-decoded iced instruction, so you can pick whichever interface is more ergonomic.

```rust
use smda::function::Instruction;
use iced_x86::{FlowControl, Mnemonic, OpKind};

fn classify(ins: &Instruction) {
    // Legacy fields (preserved for backward compat with capa-rs)
    println!(
        "{:08x}  {:7} {}",
        ins.offset,
        ins.mnemonic,
        ins.operands.as_deref().unwrap_or(""),
    );

    // New typed accessors — no string parsing
    if ins.is_call() {
        println!("  -> call");
    }
    if ins.is_conditional_jmp() {
        println!("  -> Jcc to 0x{:x}", ins.near_branch_target());
    }
    if ins.mnemonic_enum() == Mnemonic::Xor
        && ins.op_count() == 2
        && ins.op_kind(0) == OpKind::Register
        && ins.op_kind(1) == OpKind::Register
        && ins.op_register(0) == ins.op_register(1)
    {
        println!("  -> register clear ({:?})", ins.op_register(0));
    }
    if ins.flow_control() == FlowControl::Return {
        println!("  -> return");
    }
}
```

## Feature coverage

- **Input formats**: PE (32 / 64-bit), ELF (32 / 64-bit), raw memory dumps with optional base address.
- **Function discovery**: prologue scan, call-target propagation, indirect-call analysis, jump-table recovery, tail-call analysis, alignment / NOP-gap walking, mnemonic TF-IDF confidence scoring.
- **Per-function output**: basic blocks, in / out references, API calls (ApiScout-style), block-to-block edges.
- **Architecture**: x86 / x86_64.

Not currently implemented (vs. upstream Python smda; planned for 0.3.1):

- 64-bit GCC `endbr64`-style prologue scans.
- Exception-handler-based candidate seeding (Python `IntelInstructionEscaper` §2.4.7).
- Delphi VMT scanning.

## Requirements

- Rust **1.95** or newer (2024 edition).
- No C/C++ toolchain required — pure Rust.

## Compatibility note (for capa-rs users)

The `Instruction::mnemonic` and `Instruction::operands` strings are formatted through a configured iced `IntelFormatter` (`capstone_compat_formatter`) that matches capstone's output byte-for-byte (lowercase, `0x` prefix, spaces around memory `+`, full memory-size annotations). Existing regex-based capa rules continue to match. New consumers should prefer the typed iced accessors instead of re-parsing strings.

## Why a Rust port?

`smda-rs` exists to give [capa-rs](https://github.com/marirs/capa-rs) and other Rust-side static-analysis tools a fast, dependency-light recursive disassembler without pulling in capstone, vivisect, or a Python runtime.

## Used by

- [capa-rs](https://github.com/marirs/capa-rs) — static capability extractor for PE / ELF / shellcode / .NET binaries.

## License

Licensed under the [MIT License](LICENSE).

## Acknowledgements

- [danielplohmann/smda](https://github.com/danielplohmann/smda) — original Python implementation by Daniel Plohmann and Steffen Enders.
- [iced-x86](https://github.com/icedland/iced) — the Rust decoder powering the disassembler backend.
