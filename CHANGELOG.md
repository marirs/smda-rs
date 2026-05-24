# Changelog

All notable changes to **smda** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
