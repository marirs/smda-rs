# smda

[![CI](https://github.com/marirs/smda-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/smda.svg)](https://crates.io/crates/smda)
[![Docs.rs](https://docs.rs/smda/badge.svg)](https://docs.rs/smda)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)
[![Zero-copy](https://img.shields.io/badge/zero--copy-yes-brightgreen.svg)](#zero-copy)

A minimalist recursive x86 / x64 disassembler library, optimized for accurate Control Flow Graph (CFG) recovery from PE / ELF binaries and arbitrary memory dumps.

The output is a collection of functions, basic blocks, and instructions with their respective edges (block-to-block, function-to-function). Optionally, references to the Windows API can be inferred via the ApiScout method.

`smda-rs` is a Rust port of [danielplohmann/smda](https://github.com/danielplohmann/smda) (Python). It powers [capa-rs](https://github.com/marirs/capa-rs), the Rust port of Mandiant's capability extractor.

## What changed in 0.4.0

0.4.0 lands the **full zero-copy refactor** that 0.3.0 deferred. Combined with the iced-x86 decoder swap and the security hardening that landed in 0.3.0, this is now the full Path X scope in a single major.

- **Zero-copy disassembly.** `BinaryInfo<'a>` borrows the input bytes directly. No mapped-image allocation, no per-instruction byte clone, no `DisassemblyReport.buffer` clone. For a 10 MB binary with ~100k instructions, peak memory dropped from ~3× input size to ~1.05×.
- **Section-table abstraction.** Byte access goes through `binary_info.bytes_at(va, len) -> Result<&[u8]>`, which looks up the VA in a small per-binary `SectionMap` table and returns a borrowed slice into the input. Replaces the old contiguous mapped image.
- **`Instruction` slimmed down.** The 0.3.x per-instruction `mnemonic: String`, `operands: Option<String>`, and `bytes: String` (hex) fields are gone. Use the typed iced accessors (`mnemonic_enum()`, `op_kind()`, `flow_control()`, …) for hot paths, or `format_mnemonic()` / `format_operands()` / `bytes_in(&binary_info)` for on-demand formatting.
- **Decoder still iced-x86** (no C/C++ build dep, ~2–3× faster than capstone).
- **Same security guards.** All the checked-arithmetic, allocation caps, and bounds checks added in 0.3.0 are preserved — the `pe::map_binary` and `elf::map_binary` rewrites kept every defensive check, just changed the return type from `Vec<u8>` to `Vec<SectionMap>`.
- **Rust 2024 edition, MSRV 1.95.**
- **Same dependencies** (`iced-x86 1`, `goblin 0.10`, `thiserror 2`, `itertools 0.14`, `hex 0.4`, `regex 1`, `sha2 0.10`, `serde 1`, `maplit 1`).

See [CHANGELOG.md](CHANGELOG.md) for the full list of breaking changes and the migration guide. **0.3.0 is superseded by 0.4.0**; consumers should migrate directly from 0.2.x to 0.4.0.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
smda = "0.4"
```

Then disassemble a file:

```rust
use smda::Disassembler;

fn main() -> smda::Result<()> {
    // Load the file yourself — the report borrows from this buffer
    // for the lifetime `'a`, so it must outlive the report.
    let buf = std::fs::read("Sample.exe")?;
    let report = Disassembler::parse(
        &buf,
        Some("Sample.exe"),
        false,  // high-accuracy heuristics (slower)
        false,  // tail-call resolution
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

Each `Instruction` carries the fully-decoded `iced_x86::Instruction` (16 bytes, `Copy`) and exposes typed accessors. New code should prefer these over the on-demand string formatters — no allocation, no string parsing.

```rust
use smda::function::Instruction;
use smda::BinaryInfo;
use iced_x86::{FlowControl, Mnemonic, OpKind};

fn classify(ins: &Instruction, bi: &BinaryInfo<'_>) {
    // On-demand formatting (allocates a fresh String per call —
    // cache locally if you read it more than once per instruction).
    println!(
        "{:08x}  {:7} {}",
        ins.offset,
        ins.format_mnemonic(),
        ins.format_operands().unwrap_or_default(),
    );

    // Raw instruction bytes, borrowed from the input file (zero-copy).
    if let Ok(bytes) = ins.bytes_in(bi) {
        println!("  bytes: {}", hex::encode(bytes));
    }

    // Typed accessors — no string parsing, no allocation.
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

## Zero-copy

0.4.0 is zero-copy in the strict sense: no copies of the input bytes are made between `Disassembler::parse(&buf, …)` and the returned `DisassemblyReport`. The only allocations during disassembly are the iced instruction Vec, the section-map table (tiny), the function CFG metadata, and on-demand formatted strings.

- `BinaryInfo<'a>` borrows the input via `raw_data: &'a [u8]`.
- The PE / ELF mapped image is replaced by `section_maps: Vec<SectionMap>` — a small descriptor table (typically < 10 entries) that maps virtual-address ranges to file-offset ranges.
- Byte access goes through `bytes_at(va, len) -> Result<&[u8]>`, which does a section lookup and slices into the borrowed input. Per-byte cost is one section-table scan (linear, < 10 entries, cache-friendly).
- `Instruction` is `{ offset, length, iced }` — no per-instruction `String` or `Vec<u8>` storage.
- `DecodedInsn` is `Copy` (16 bytes).
- `DisassemblyReport<'a>` carries the `BinaryInfo<'a>` for downstream `bytes_at` lookups.

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
