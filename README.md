# smda

[![CI](https://github.com/marirs/smda-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/smda.svg)](https://crates.io/crates/smda)
[![Docs.rs](https://docs.rs/smda/badge.svg)](https://docs.rs/smda)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)
[![Zero-copy](https://img.shields.io/badge/zero--copy-yes-brightgreen.svg)](#zero-copy)

A minimalist recursive x86 / x64 / AArch64 disassembler library, optimized for accurate Control Flow Graph (CFG) recovery from PE, ELF, and Mach-O binaries and arbitrary memory dumps.

The output is a collection of functions, basic blocks, and instructions with their respective edges (block-to-block, function-to-function). Optionally, references to the Windows API can be inferred via the ApiScout method.

`smda-rs` is a Rust port of [danielplohmann/smda](https://github.com/danielplohmann/smda) (Python). It powers [capa-rs](https://github.com/marirs/capa-rs), the Rust port of Mandiant's capability extractor.

## Features
- **Zero-copy disassembly.** `BinaryInfo<'a>` borrows the input bytes directly. No mapped-image allocation, no per-instruction byte clone, no `DisassemblyReport.buffer`.
- **Modern Linux ELF coverage:** added GCC / clang `endbr64` (`F3 0F 1E FA`) plus the extended GCC AMD64 prologue family (`48 89 5C 24 ??`, `48 83 EC ??`, `41 57 41 56`)$
- **Linux exit-syscall recognition:** `mov eax, 60; syscall` (and `exit_group` / `int 0x80` equivalents) now end the containing function correctly.
- **PE exports as candidate seeds:** the export RVA list, previously only surfaced in the public report, now seeds the function-candidate scanner. Free coverage win on s$
- **New report fields:** `report.oep` (original entry point VA), `function.is_exported` (PE only), `function.stringrefs` (VAs of stack-string writes — wires up the exist$
- **New lookups:** `report.find_function_by_offset(addr)` / `find_block_by_offset(addr)`.
- **Timeout support:** `Disassembler::parse_with_timeout(..., Duration)` + new `Error::AnalysisTimeout` for batch processors of untrusted samples.
- **Section-table abstraction.** Byte access goes through `binary_info.bytes_at(va, len) -> Result<&[u8]>`, which looks up the VA in a small per-binary `SectionMap` tabl$
- **`Instruction` slimmed down.** The 0.3.x per-instruction `mnemonic: String`, `operands: Option<String>`, and `bytes: String` (hex) fields are gone. Use the typed iced$
- **Decoders are pure-Rust** — `iced-x86` for x86 (no C/C++ build dep, ~2–3× faster than capstone) and `disarm64` for AArch64 (table-generated from the ARM ISA JSON, MIT$
- **Same security guards.** All the checked-arithmetic, allocation caps, and bounds checks added in 0.3.0 are preserved — the `pe::map_binary` and `elf::map_binary` rewr$
- **Input formats**: PE (32 / 64-bit), ELF (32 / 64-bit), Mach-O (Intel + ARM64, thin and fat).
- **Architectures**: x86, x86_64, AArch64 (0.6.0+).
- **Function discovery**: prologue scan (MSVC + GCC / clang `endbr64` family + ARM64 `stp x29, x30, [sp, #-N]!`), call-target propagation, PE exception-handler (`.pdata`) seeding, PE export-table seeding.
- **Per-function output**: basic blocks, in / out references, API calls (ApiScout — embedded Win7 + WinXP DBs), stack-string refs, block-to-block edges, `is_exported`, PIC + opcode hashes, dominator tree + nesting depth.
- **Report-level**: `oep`, `find_function_by_offset` / `find_block_by_offset` lookups, per-disassembly timeout via `parse_with_timeout`.

### Architecture-aware decoding (0.6.0)

The decoder lives behind a small `Decoder` trait with two backends:

- **`X86Decoder`** — wraps `iced_x86`. Variable-width, 32 / 64-bit modes. Same x86 path as 0.5.x; zero behavioural change.
- **`Aarch64Decoder`** — wraps [`disarm64`](https://crates.io/crates/disarm64). Fixed 4-byte instructions, 64-bit only. Validated at 98%+ clean memory-operand extraction on real Apple-silicon ARM64 binaries (Rust release builds, `/bin/ls`) before integration.

**Smda decides which decoder to use.** The caller passes `&[u8]`; smda inspects the header and routes:
- ELF `e_machine == EM_AARCH64` (183) → AArch64.
- PE `coff_header.machine == 0xAA64` → AArch64.
- Mach-O `cputype == CPU_TYPE_ARM64` (0x100000C) → AArch64. For fat (universal) binaries, the slice preference is configurable via `SmdaConfig::macho_arch_preference`: default is `HostNative` (picks the slice matching the host machine — ARM64 on Apple-silicon, x86_64 on Intel/AMD Linux/Windows), with explicit `Aarch64First` / `X86_64First` / `X86First` overrides for analysts who want consistent slice selection regardless of host.
- Everything else falls through to the existing x86 32/64-bit detection.

`DecodedInsn` is an enum (`X86(IcedInsn)` / `Aarch64(ArmInsn)`); the typed accessors on `function::Instruction` (`mnemonic_enum`, `op_kind`, `memory_base`, `flow_control`, `is_call`, `is_jmp`, `is_ret`, `format_mnemonic`, `format_operands`, `length`, `bytes_in`, `get_printable_len`) keep their 0.5.x signatures and dispatch internally.

**ARM64 function-discovery depth in 0.6.0 is minimum-viable** — exports + entry point as candidate seeds, then the recursive call-target propagation does the rest. A typical ARM64 *executable* with no exports will surface 1 function (the entry point) and everything it calls; an ARM64 *dylib* with N exports surfaces N + transitively-reachable functions. The x86 prologue-scan analysers don't have ARM64 equivalents in this release — that, plus the deeper passes (jump-table walking, indirect-call register tracking, tail-call detection past `b`/`bl`, ARM64 PE `.pdata` packed unwind, typed AArch64 operand extraction for downstream `offset:` rules in capa-rs, AArch64 mnemonic IDF), is the 0.6.1 work. x86/x64 binaries are unaffected — same code, same output as 0.5.2.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
smda = "0.6"
```

Then disassemble a file:

```rust
use smda::{Disassembler, SmdaConfig};

fn main() -> smda::Result<()> {
    // Load the file yourself — the report borrows from this buffer
    // for the lifetime `'a`, so it must outlive the report.
    let buf = std::fs::read("Sample.exe")?;

    // 0.5.0: positional bool args were replaced by SmdaConfig so new
    // analysis knobs land without further API breaks. Every field has
    // a sensible default; chain only what you need.
    let cfg = SmdaConfig::new()
        .path("Sample.exe")
        .high_accuracy(false)        // slower, finds more functions
        .resolve_tailcalls(false);   // promote tail-call targets to functions

    let report = Disassembler::parse(&buf, &cfg)?;

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

For raw memory dumps (shellcode, unpacked modules — **x86 / x64 only in 0.6.0**; ARM64 shellcode needs file-format wrapping until 0.6.1 ships an arch arg here):

```rust
use smda::{Disassembler, SmdaConfig};
use std::time::Duration;

let shellcode: &[u8] = &[/* … */];
let cfg = SmdaConfig::new().timeout(Duration::from_secs(10));
let report = Disassembler::parse_buffer(
    shellcode,
    0x1000,     // virtual base address
    64,         // bitness (32 or 64)
    &cfg,
)?;
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

## Requirements

- Rust **1.95** or newer (2024 edition).
- No C/C++ toolchain required — pure Rust.

## Why a Rust port?

`smda-rs` exists to give [capa-rs](https://github.com/marirs/capa-rs) and other Rust-side static-analysis tools a fast, dependency-light recursive disassembler without pulling in capstone, vivisect, or a Python runtime.

## Used by

- [capa-rs](https://github.com/marirs/capa-rs) — static capability extractor for PE / ELF / shellcode / .NET binaries.

## License

Licensed under the [MIT License](LICENSE).

## Acknowledgements

- [danielplohmann/smda](https://github.com/danielplohmann/smda) — original Python implementation by Daniel Plohmann and Steffen Enders.
- [iced-x86](https://github.com/icedland/iced) — the Rust decoder powering the disassembler backend.
