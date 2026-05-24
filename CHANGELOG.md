# Changelog

All notable changes to **smda** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-05-24 — Full zero-copy

Supersedes 0.3.0. The 0.3.0 release was a partial increment — it shipped
the iced-x86 decoder swap and the security hardening, but the planned
zero-copy refactor was deferred. 0.4.0 lands that work. Downstream
consumers should migrate directly from 0.2.x to 0.4.0 (skipping 0.3.0).
0.3.0 remains functional for anyone who already pulled it; it is not
yanked, but it is not recommended for new dependents.

### Memory impact

For a 10 MB binary with ~100k decoded instructions, peak memory drops
from roughly 3× the input size to roughly 1.05× (input bytes + the iced
instruction Vec + a small section table). Concretely:

- The mapped-image `Vec<u8>` in `BinaryInfo.binary` is gone. Replaced
  by a `Vec<SectionMap>` (typically < 10 entries) describing where each
  section lives in both file and virtual-address space.
- `DisassemblyReport.buffer: Vec<u8>` (clone of the mapped image) is
  gone.
- Per-`Instruction` String fields (`mnemonic`, `operands`, `bytes` hex)
  are gone. Replaced by `format_mnemonic()` / `format_operands()` /
  `bytes_in(&binary_info)` helpers that allocate only when called.
- Per-`DecodedInsn` `bytes: Vec<u8>` is gone. `DecodedInsn` is now
  16-byte `Copy`, making the analyser's per-instruction state cheaper
  to move around.

### Breaking changes

- **New `BinaryInfo<'a>` lifetime parameter.** Borrows the input bytes
  for `'a`. Constructed via `BinaryInfo::from_buffer(&buf)`. The empty
  default is `BinaryInfo::empty() -> BinaryInfo<'static>`.
- **`BinaryInfo` API changes:**
  - `binary: Vec<u8>` → removed.
  - `raw_data: Vec<u8>` → `raw_data: &'a [u8]`.
  - New: `section_maps: Vec<SectionMap>`, `binary_size: u64` (now the
    VA range, not the file size).
  - New helpers: `bytes_at(va, len)`, `bytes_at_best_effort(va, max)`,
    `section_slices()`, `compute_binary_size()`.
- **New `DisassemblyResult<'a>` / `Disassembler<'a>` lifetime
  parameters.**
- **`DisassemblyReport<'a>` carries `binary_info: BinaryInfo<'a>`** —
  the old `buffer: Vec<u8>` field is gone. Consumers that previously
  did `report.buffer[idx]` should call `report.binary_info.bytes_at(va, len)`
  with the virtual address instead.
- **`Disassembler::disassemble_file` is removed.** The new entry point
  is `Disassembler::parse(raw: &'a [u8], path: Option<&str>,
  high_accuracy, resolve_tailcalls) -> Result<DisassemblyReport<'a>>`.
  Callers load the file themselves:
  ```rust
  let buf = std::fs::read("Sample.exe")?;
  let report = smda::Disassembler::parse(&buf, Some("Sample.exe"), false, false)?;
  ```
- **`Disassembler::new()` is removed** (replaced by `with_binary` used
  internally; public callers go through `parse`).
- **`Instruction` String fields removed.** Replace `instruction.mnemonic`
  with `instruction.format_mnemonic()`, `instruction.operands` with
  `instruction.format_operands()`, `instruction.bytes` with
  `instruction.bytes_in(&binary_info)` or `instruction.bytes_hex(&binary_info)`.
  For hot-path consumers that read the same instruction repeatedly,
  cache the formatted string locally; for typed comparisons use
  `instruction.mnemonic_enum()` / `op_kind()` / `flow_control()`.
- **`DecodedInsn.bytes: Vec<u8>` removed.** `DecodedInsn` is now `Copy`.
- **`SectionMap` exported** at the crate root for callers that want to
  inspect the section table directly.

### Added

- `BinaryInfo::bytes_at(va, len) -> Result<&[u8]>` — primary byte
  accessor. Section-table lookup + slice into borrowed input. Returns
  `Err(NotEnoughBytesError)` on out-of-section or short reads.
- `BinaryInfo::bytes_at_best_effort(va, max_len) -> Result<&[u8]>` —
  returns up to `max_len` bytes; used by the iced decoder's lookahead
  window.
- `BinaryInfo::section_slices() -> impl Iterator<Item = (u64, &[u8])>` —
  per-section iteration for regex scanners.
- `Disassembler::parse(&'a [u8], …) -> Result<DisassemblyReport<'a>>` —
  zero-copy disassembly entry.
- `Instruction::format_mnemonic` / `format_operands` / `bytes_in` /
  `bytes_hex` helpers.
- `DecodedInsn::bytes_in` helper.

### Internal

- `pe::map_binary` and `elf::map_binary` rewritten to return
  `Vec<SectionMap>` instead of allocating a contiguous mapped image.
  All security guards from 0.3.0 (checked arithmetic, allocation caps,
  PE header bounds, ELF `sh_addralign=0` guard, segment / section
  overflow guards) are preserved.
- All regex-based candidate scanners in `function_candidate_manager`
  and `jump_table_analyser` iterate `section_slices()` and translate
  match positions to VAs.
- All byte-helper callsites (`get_byte`, `get_raw_byte`, `get_bytes`,
  `get_raw_bytes`, `dereference_dword`, `dereference_qword`) go
  through `bytes_at` with checked arithmetic.

### Verified

Smoke-tested against 7 PE / ELF / .NET samples — `mimikatz.exe_`,
`Demo64.dll` (the 0.3.0 `.pdata` regression case), three .NET PEs, two
ELFs. Function counts, import counts, and per-function block / insn /
outref counts are **bit-for-bit identical** to the 0.3.0 baseline.


## [0.3.0] — 2026-05-24

### Security & robustness

Hardened the PE / ELF parsers against malformed and adversarial inputs.
Every panic path reachable from a crafted binary that the audit identified
has been replaced with a returned `Error`.

- **CRIT** Fixed `locate_exception_handler_candidates` crash on every 64-bit
  PE with a `.pdata` section. `lib.rs::get_sections()` was returning
  *file offsets* (`pointer_to_raw_data`) but the caller treated the
  tuple values as VAs and subtracted `base_addr`, causing a u64
  underflow → out-of-bounds slice. `get_sections()` now returns mapped
  virtual addresses (matching what `report::get_section` also expects),
  and the caller does its own checked conversion + bounds clamp.
- **CRIT** Fixed ELF `sh_addralign = 0` division-by-zero panic in
  `elf::get_code_areas`. Skipped alignment for `sh_addralign` of 0 or 1
  (both mean "no alignment" per the ELF spec).
- **CRIT** Capped ELF mapped-image allocation at 256 MB
  (`elf::MAX_MAPPED_BYTES`). Previously ELF had no cap analogous to
  PE's 100 MB limit; a single PT_LOAD with a high `p_vaddr` would
  allocate gigabytes and OOM the host.
- **CRIT** Replaced unchecked `p_vaddr + p_memsz`, `sh_addr + sh_size`,
  and the surrounding base-address subtraction in `elf::map_binary`
  with `checked_add` / `checked_sub`; overflowing segments and sections
  are now skipped rather than wrapping.
- **CRIT** Replaced unchecked `virt_size + virt_offset` and
  `raw_offset + raw_size` u32 adds in `pe::map_binary` with checked
  arithmetic; the slice copy now uses `.get_mut()` and skips sections
  whose declared ranges are out of bounds.
- **HIGH** Added end-bound checks to `dereference_dword`, `get_bytes`,
  `get_raw_bytes`, `get_byte`, and `get_raw_byte` in `lib.rs`. The
  previous implementations only checked the start address.
- **HIGH** `function_analysis_state::finalize_analysis` no longer
  indexes `instructions[len()-1]`; it uses `.last()` with a defensive
  early return.
- **HIGH** Hardened `function_candidate.rs` 5-byte read with
  `checked_add` and `.get()` (matters on 32-bit targets).
- **MED** Capped jump-table iteration in `jump_table_analyser` at 4096
  entries (the size is parsed from a user-controlled operand and could
  reach `usize::MAX`). Switched every `address + i*entry_size`
  computation to `checked_add` / `checked_mul`.
- **MED** Fixed `function_candidate_manager::next_gap_candidate` empty
  range bug (`for gap_length in 15u32..1`) that silently disabled
  multi-byte NOP gap detection. Now iterates `(2..=15).rev()`.
- **MED** Fixed `analyze_loop_instruction` and
  `analyze_cond_jmp_instruction` panic on operands whose formatted
  string is shorter than two bytes or doesn't start with `0x`. They
  now use the already-parsed `jump_destination` rather than slicing
  `op_str[2..]`.
- **MED** `resolve_pointer_reference` now uses `wrapping_add` for the
  RIP-relative pointer math (matches x86 semantics) and `checked_add`
  for the final base-address addition.
- **MED** `extract_elf_dynamic_apis_fallback_internal` and
  `get_dynamic_dependencies` use checked arithmetic on GOT/dynamic
  entry offsets.

### Added

- `error::IntegerOverflow(&'static str, u64, u64)` — distinct from
  `LogicError`; signals "malformed input" rather than "smda bug".
- `error::MalformedInputError(&'static str, u64, u64)` — returned when
  an input value exceeds a safety cap.
- `error::try_usize` / `error::safe_add` / `error::safe_sub` helpers
  that wrap `try_from` and `checked_add` / `checked_sub` with an
  `Error::IntegerOverflow` mapping.


This is a substantial overhaul of the disassembly backend. The text output (`Instruction::mnemonic`, `Instruction::operands`, `Instruction::bytes`) is preserved byte-for-byte with the old capstone-backed 0.2.x line so regex-based capa rules and other downstreams continue to match unchanged.

### Changed (breaking)

- **Decoder swap: capstone → [iced-x86](https://crates.io/crates/iced-x86).** No feature flag, no fallback — iced is the only backend. Removes the C/C++ build-time dependency on capstone-sys and brings a ~2–3× decode speedup. Capstone-byte-compatible text output is preserved via `function::capstone_compat_formatter` (a configured `iced_x86::IntelFormatter`).
- **`Instruction` gains a `pub iced: iced_x86::Instruction` field** alongside the existing string fields. New typed accessors: `mnemonic_enum()`, `code()`, `op_count()`, `op_kind()`, `op_register()`, `memory_base()`, `memory_index()`, `memory_displacement64()`, `memory_segment()`, `near_branch_target()`, `flow_control()`, `is_call()`, `is_jmp()`, `is_conditional_jmp()`, `is_ret()`.
- **`error::Error::CapstoneError` → `error::Error::DecodeError(iced_x86::DecoderError)`.** All call sites that matched on the old variant must update.
- **`DisassemblyResult::functions`** is now `HashMap<u64, Vec<Vec<DecodedInsn>>>` (per-block `DecodedInsn` carriers) instead of the old capstone-shaped tuple type. New helpers `get_blocks_as_decoded` / `get_in_refs` / `get_out_refs` / `get_block_refs` / `get_api_refs` formalise the surface.
- **Rust 2024 edition.**
- **MSRV bumped to 1.95.**
- **Indirect-call analyser** deduplicates by block start address (`HashSet<u64>`) instead of the previous `HashSet<Vec<...>>`. Equivalent behaviour, materially smaller memory.

### Added

- `function::DecodedInsn` carrier struct (`offset`, `length`, `iced`, `bytes`) used internally and exposed for advanced consumers that want to format instructions themselves.
- `function::capstone_compat_formatter()` — public helper returning a configured `IntelFormatter` you can reuse to produce capstone-byte-compatible strings from any `iced_x86::Instruction`.

### Removed

- `capstone` and `capstone-sys` dependencies (and the entire C/C++ toolchain requirement).
- `ring` dependency (replaced by `sha2` for the single buffer hash).
- `lazy_static` (replaced by `std::sync::LazyLock`).

### Dependency updates

- `iced-x86 1` *(new)* — default-features off, `std + decoder + intel + instr_info`.
- `goblin` 0.5 → **0.10** (defaults + `alloc`).
- `thiserror` 1 → **2** (with `#[from]` conversion for `iced_x86::DecoderError`, `regex::Error`, `hex::FromHexError`, `std::num::ParseIntError`, `std::io::Error`).
- `itertools` 0.10 → **0.14**.
- `hex` → **0.4** (defaults, needed for the `std::error::Error` impl).
- `regex` (unchanged) — **1.x**.
- `sha2` *(new)* — **0.10**, default-features off.
- Removed: `capstone`, `ring`, `lazy_static`.

### Migration guide for downstream consumers

If you only ever touched `Instruction::mnemonic`, `Instruction::operands`, or `Instruction::bytes` (the capstone-shaped strings): **no changes required.** The strings are produced by a formatter explicitly configured to match capstone byte-for-byte (lowercase, `0x` numeric prefix, spaces around memory `+`, always-on memory-size annotations).

If you matched on `error::Error::CapstoneError`, update the pattern to `error::Error::DecodeError(_)`.

If you reached into `DisassemblyResult::functions` directly (the old tuple shape), switch to `get_blocks_as_decoded(function_offset)` or rebuild via `DecodedInsn` — see `function::Function::parse_blocks` for an example.

New code should prefer the typed iced accessors over re-parsing strings; they are zero-allocation and give you the full `iced_x86::Mnemonic` / `OpKind` / `Register` / `FlowControl` enums.

### Planned for 0.3.1

- 64-bit GCC `endbr64`-style prologue scans (Python upstream §2.4.4).
- Exception-handler-based candidate seeding (Python `IntelInstructionEscaper` §2.4.7).
- Optional Delphi VMT scanning.

### Planned for 0.3.2

- Post-feature security recheck (allocation caps, checked arithmetic on attacker-controlled values, unwrap audit).

[Unreleased]: https://github.com/marirs/smda-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/marirs/smda-rs/releases/tag/v0.3.0
