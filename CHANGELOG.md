# Changelog

All notable changes to **smda** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.3] — Tail-call resolver no longer aborts on benign collisions

### Fixed

- **`TailCallAnalyser::resolve_tailcalls` no longer fatally
  propagates `Error::CollisionError`.** Four `analyse_function(…)?`
  sites in `tail_call_analyser.rs` propagated the "address already
  belongs to an existing function" sentinel as a hard error —
  aborting the whole `resolve_tailcalls` pass and, because
  `analyse_buffer:1537` propagates that via `?`, the WHOLE
  `Disassembler::parse` call. The main candidate loop in
  `analyse_buffer` (lib.rs:1510, 1517, 1525) had always swallowed
  the same Result via `.ok()` for exactly this reason — collisions
  during function discovery are expected, not fatal.

  Concrete repro: any consumer calling
  `SmdaConfig::new().resolve_tailcalls(true)` on Apple-Silicon
  /bin/ls — `Disassembler::parse` returned
  `Err(CollisionError(0x100003698))` after ~95 ms, with zero
  functions analysed. capa-rs hit this whenever it ran ARM64
  Mach-O input through the CLI (which sets `resolve_tailcalls=true`
  by default).

  Fix: a small `try_analyse` helper wraps the four call sites and
  treats `CollisionError` as success (skip this candidate, continue
  the loop). Other error variants — `LogicError`,
  `NotEnoughBytesError`, etc. — still propagate, because those
  signal real bugs.

## [0.6.2] — Code hygiene patch

No behavioural changes — pure cleanup pass after the 0.6.0/0.6.1
AArch64 work settled. Removes dead skeleton code, prunes
commented-out experiments, and corrects stale "lands in 0.6.X"
forward-pointer comments now that those releases have shipped.

### Removed

- ~30 lines of commented-out relocation-parsing skeleton in
  `label_providers::elf_symbol_provider::update`. The real
  implementation lives in `elf::extract_elf_dynamic_apis` and has
  since 0.4.x; the skeleton was misleading and confused an audit
  pass. Replaced with a comment explaining the actual separation
  of concerns.
- Commented-out `parse_exports` stub in the same file.
- Stale "0.5.0: positional bool args → SmdaConfig builder"
  version-anchor in `examples/smdadump.rs` (now-historical).

### Corrected

- 10 "lands in 0.6.0/0.6.1" / "deferred to 0.6.1" forward-pointer
  comments across `lib.rs`, `function.rs`, `disassembler/mod.rs`,
  `jump_table_analyser.rs`, `indirect_call_analyser.rs` rewritten
  to reflect the shipped state (or to point at the actual sibling
  AArch64 implementation where one exists).
- `analyse_function_aarch64` doc comment rewritten — previously
  said "MVP doesn't model PAC indirect calls, jump tables, exit
  syscalls, stack-string detection… deferred to 0.6.1", which has
  long since happened. New version documents the actual per-mnemonic
  control-flow taxonomy as it stands.
- `extract_exit_reg_imm` doc comment rewritten — previously said
  "any non-mov-to-eax-family instruction clears the tracker" but
  0.6.1 changed it to preserve across non-clobbering instructions.
- `Instruction::op_kind` doc comment now points readers at
  `disassembler::aarch64_ops` for AArch64 operand walking instead
  of misleadingly claiming it'd be added to this method "in 0.6.1".

### Dead-code sweep

Removed the crate-wide `#![allow(dead_code)]` from `lib.rs` and
triaged every surfaced warning. 12 findings; 7 fields and 4 helpers
deleted (truly dead), 4 structs annotated with explanatory
`#[allow(dead_code)]` (fields populated for `Debug` output and
downstream tooling, but no in-crate reader).

Deleted:
- `error::try_usize` / `safe_add` / `safe_sub` — unused arithmetic
  helpers; live code uses `checked_add`/`checked_mul` directly.
- `Disassembler::is_plt_got_address` — never called.
- `DisassemblyResult::analysis_timeout` (`bool`) — superseded by
  `Disassembler::analysis_timeout` (`Option<Duration>`).
- `DisassemblyResult::language` — `HashMap` never populated.
- `DisassemblyResult::code_areas` — duplicate of
  `binary_info.code_areas`.
- `FunctionAnalysisState::blocks` — Python-port leftover, never
  written nor read.
- `FunctionCandidate::rel_start_addr` — set in `new`, never read.
- `FunctionCandidate::function_start_score` — same.
- `TailCall::source_addr` — set in struct literal, never read.

Annotated (kept for `Debug` print / downstream tooling
inspection):
- `DisassemblyReport` — `binary_size`, `binweight`, `code_areas`,
  `empty_section`, `component`, `confidence_threshold`, `family`,
  `filename`, `identified_alignment`, `is_library`, `is_buffer`,
  `message`, `sha256`, `statistics`.
- `DisassemblyStatistics` — all 8 fields.
- `Function` — `characteristics`, `confidence`, `tfidf`.
- `GoSymbols` — `version`, `pclntab_offset`.

### Removed — skeleton modules

- **`label_providers::elf_api_resolver`** (file deleted) — used
  hardcoded `0x401700` start address + `0x10` stride to populate
  its `api_map`, ignoring `reloc.r_offset`. Effectively returned
  garbage on lookup and shadowed the real ELF API resolution that
  `elf::extract_elf_dynamic_apis` does (correctly, via
  `r_offset + base_addr`). The internal `api_map` was even keyed
  by `"lief"` — surviving naming from the Python port. Removed
  the `LabelProvider::ElfApi` variant + its arms.
- **`label_providers::pdb_symbol_provider`** (file deleted) — stub
  that did one thing on `update()`: insert
  `entry_point → "original_entry_point"`. No actual PDB parsing
  (the real PDB metadata work lives in `xmetadata::parse_pe` since
  0.5.0). The OEP candidate seeding it provided is redundant with
  the entry-point seeder in `analyse_buffer`. Removed the
  `LabelProvider::PdbSymbol` variant + its arms.

Net `LabelProvider` enum: 4 variants → 2 (`WinApi`, `ElfSymbol`).
No public API impact — `LabelProvider` is not re-exported from
the crate root.

## [0.6.1] — AArch64 analyser

Closes the seven x86-only analysers that 0.6.0 gated off when
`binary_info.file_architecture == Aarch64`. No API breaks — every
addition lands behind the existing arch dispatch or as new
`Function` / `Disassembler` methods that returned the
no-architecture-support default in 0.6.0.

### Added — AArch64 analyser ports

- **Structured disarm64 operand walker.** Uniform
  `{kind, reg, imm, mem}` operand surface on top of disarm64 so
  analysers no longer have to parse formatted Intel-style operand
  strings (the 0.6.0 stopgap). Mirrors the iced typed-operand walker
  that landed in capa 0.5.0. Foundation for the jump-table and
  indirect-call ports below.
- **AArch64 jump-table heuristic.** Recognises the standard ARM64
  switch-statement lowering — ADRP / ADD / LDR
  (table-of-deltas or table-of-targets) feeding into BR — and
  produces the corresponding jump targets as block-queue entries.
  Previously the analyser short-circuited via empty operand strings.
- **AArch64 indirect-call register tracking.** Small-window dataflow
  backtracks register definitions before BLR / BR so calls through
  GOT thunks or constant-loaded function pointers resolve. Mirrors
  the x86 backtracking pipeline but matches on disarm64 mnemonics.
- **AArch64 tail-call recognition past bare `b`.** The 0.6.0 walker
  promoted `b` to a known function or pending candidate as a tail
  call but left bare unresolved `b`-targets unclassified. The
  `TailCallAnalyser` now feeds off the AArch64 walker's
  `code_refs` and promotes off-function targets to candidates.
- **PE `.pdata` exception-handler sweep for ARM64 PE.** Parses the
  ARM64-flavoured `RUNTIME_FUNCTION` + packed UNWIND_INFO layout
  (distinct from x64 SEH) and produces function-start candidates.
- **AArch64 NOP detection in `next_gap_candidate`.** Adds the
  4-byte word match on `1f 20 03 d5` so gap scans don't classify
  ARM64 NOP padding as code-free data.
- **AArch64 exit-syscall recognition.** Recognises `mov w8, #93`
  (or `#94`) followed by `svc #0` as a function-terminating syscall;
  marks the block sanely-ending. Linux exit / exit_group ABI.
- **`Function::is_api_thunk` AArch64 patterns.** Adds single-`b`
  to-import and ADRP+LDR+BR through GOT/.got.plt patterns so capa
  folds thunks into their resolved API on ARM64 binaries.

## [0.6.0] — 2026-05-27 — AArch64 + Decoder-trait refactor

The 0.6.0 cycle replaces the implicit "everything is iced-x86" decoder
with an explicit `Decoder` trait + `DecodedInsn` enum so a second ISA
fits without rewriting every analyser. AArch64 (Apple-silicon Mach-O,
Linux EM_AARCH64, Windows ARM64 PE) decodes through `disarm64` and
populates the public `Function` / `Instruction` surface — capa-rs and
other downstreams can already enumerate ARM64 function CFGs after a
simple `FileArchitecture::Aarch64` thread-through.

The x86 path is functionally unchanged from 0.5.2 (same instruction
stream, same heuristics, same output for the smdadump smoke).

### Breaking changes

- **`function::DecodedInsn` was a struct; now it's an enum.** The
  carrier moved to `smda::disassembler::DecodedInsn`, an enum over
  `X86(IcedInsn)` and `Aarch64(ArmInsn)`. Pre-0.6.0 reach-through
  via the `.iced` field is no longer possible — call the typed
  accessors on the enum (`offset()`, `length()`, `op_count()`,
  `mnemonic_enum_x86()`, `flow_control_x86()`, `is_call()`,
  `is_jump()`, `is_return()`, `is_branch()`, …).
- **`function::Instruction` drops the public `iced` field.** Use
  `Instruction::iced()` (returns `Option<&iced_x86::Instruction>`)
  or pattern-match on `Instruction::decoded` (the wrapped
  `DecodedInsn` enum). The typed accessor methods
  (`mnemonic_enum()`, `op_kind(i)`, `op_register(i)`, …) keep their
  0.5.x signatures and dispatch internally — most downstreams only
  need to drop direct `.iced.` accesses.
- **`FileArchitecture::Aarch64` variant added.** Downstream `match`
  statements over `FileArchitecture` need a wildcard arm (the enum
  is `#[non_exhaustive]` so this is non-breaking at the type level,
  but any non-wildcard `match` will fail to compile).
- **`function::DecodedInsn` re-export removed.** The old path
  `smda::function::DecodedInsn` no longer resolves; consumers
  should import from `smda::disassembler::DecodedInsn`.

### Added — AArch64 backend

- **`smda::disassembler` module.** New `Decoder` trait + `X86Decoder`
  / `Aarch64Decoder` impls + `DecodedInsn` enum + per-variant typed
  accessors. The `Disassembler` carries a `Box<dyn Decoder>` (Send +
  Sync) picked from `binary_info.file_architecture`.
- **AArch64 routing in all loaders.** ELF `EM_AARCH64` (e_machine =
  183), PE `IMAGE_FILE_MACHINE_ARM64` (0xAA64), Mach-O
  `CPU_TYPE_ARM64` (0x0100_000C) now all map to
  `FileArchitecture::Aarch64` and dispatch through the disarm64
  backend.
- **Mach-O fat-binary ARM64 slice support.** New
  `macho::extract_macho` accepts ARM64 + Intel slices; fat binaries
  with both prefer ARM64 on the assumption the host is Apple-silicon.
  `macho::extract_intel` retained for source-compat.
- **AArch64 prologue start-byte seed** in the bitness vote table —
  `0xfd` (low byte of `stp x29, x30, [sp, #-N]!`) weighted so it
  doesn't perturb x86 detection.
- **`disarm64` promoted from `[dev-dependencies]` to a regular
  dependency.** The aarch64_probe example continues to pass (>95%
  clean base+disp on /bin/ls and Rust release binaries).
- **AArch64 function analyser (`analyse_function_aarch64`).** A
  parallel arm of `analyse_function` that walks the disarm64 mnemonic
  stream instead of iced `FlowControl`: direct `bl` propagates targets
  into the function-candidate queue, direct `b`/`b.cond`/`cbz`/`tbz`
  follow PC-relative imm26/imm19/imm14 targets, `ret`/`br` end blocks,
  `blr` records on `call_register_ins` for the (still x86-only)
  indirect-call analyser. With seeds from Mach-O exports + entry
  point, `/bin/ls` on Apple-silicon now produces a non-zero function
  count (vs zero before).
- **`disassembler::aarch64_branch_target_raw`** + companion
  `aarch64_is_direct_call` / `aarch64_is_unconditional_branch` /
  `aarch64_is_conditional_branch` / `aarch64_is_return` helpers.
  Encodings per ARM ARM §C6.2 (B/BL imm26, B.cond/CBZ imm19, TBZ
  imm14). Reuses the raw `u32` already retained on `ArmInsn` so we
  don't pay the trait-dispatch tax on the hot path.
- **`disarm64_defn` listed as a direct dep.** Already a transitive
  pull-in from disarm64; pinned here for the `InsnOpcode::bits()`
  trait used by the standalone (non-`ArmInsn`) target resolver.

### Migration

The most common 0.5.x callsite — `ins.iced.X` for some iced
accessor — turns into `ins.X_x86()` (returns `Option`) or stays
`ins.X()` on `function::Instruction` (where the typed wrappers
remain). A capa-rs-style consumer iterating
`Function::get_blocks()` and reading `Instruction::mnemonic_enum()`
needs no source change; consumers reading `Instruction::iced.X`
need to swap to `Instruction::iced().unwrap().X` (x86) or branch
on `Instruction::arch` (cross-arch).

## [0.5.1] — 2026-05-25 — Hardening + Mach-O polish (additive)

Patch release. No API changes from 0.5.0. Bundles the post-0.5.0
security audit fixes with two Mach-O quality-of-life improvements.

### Security (post-0.5.0 audit)

- **`pclntab.rs`: unchecked offset arithmetic on attacker-controlled
  fields.** The Go pclntab parser took `funcoff` / `nameoff` /
  `pcln_offset` values directly from the on-disk runtime table and
  added them with `+`. On malformed Go binaries this would panic in
  debug builds and silently wrap in release, leading to garbage
  symbols. All offset arithmetic in `parse_v12` / `parse_v116` /
  `parse_v118` now uses `checked_add` / `checked_mul` and skips
  individual bad entries rather than panicking or corrupting.
- **`macho.rs`: `u64 as usize` truncation on 32-bit hosts.** Casts on
  `seg.fileoff`, `seg.filesize`, `sect.size`, `import.offset`,
  `export.offset` would silently truncate to wrong values on 32-bit
  targets. Replaced with `usize::try_from`; oversized values skip the
  entry rather than corrupt.

### Security (AArch64 walker hardening)

Four MEDIUM findings from the post-0.6.0 audit that flagged ways the
new disarm64-backed `analyse_function_aarch64` walker could mis-classify
hostile or compiler-pathological code. All four are fixed below; the
x86 path is unaffected.

- **PAC indirect-branch variants now end the block.** `BRAA`, `BRAAZ`,
  `BRAB`, `BRABZ` (pointer-auth indirect branches) and `BLRAA`,
  `BLRAAZ`, `BLRAB`, `BLRABZ` (pointer-auth indirect calls) used to
  fall through the walker's match cascade and be treated as regular
  data-processing instructions, so the walker would keep decoding the
  following constant-pool words as code. They now route through the
  new `disassembler::aarch64_is_indirect_branch` /
  `aarch64_is_indirect_call` helpers and end the basic block correctly
  (with sane-ending set, matching `BR` / `BLR`).
- **`UDF` / `BRK` / `HLT` traps now end the block.** Compilers emit
  these after `noreturn` calls (`abort`, `__stack_chk_fail`) or as
  bounds-check poison; the bytes immediately following are typically
  a constant-pool literal, not code. New
  `disassembler::aarch64_is_trap` helper plus a dedicated walker arm
  set `sanely_ending` and stop the walk.
- **Out-of-image branch targets no longer pollute `code_refs` /
  `ins2fn`.** `add_code_ref` for the unconditional `b <imm26>` and
  the conditional-branch family (`b.cond`, `cbz`, `cbnz`, `tbz`,
  `tbnz`) was unconditional — corrupted `imm19` / `imm14` values
  from data-in-code or partial decode would seed phantom edges to
  unmapped addresses. Both arms are now gated by
  `is_addr_within_memory_image`, matching the existing `bl` gate.
- **`b .` self-jump no longer re-seeds the current function as a
  candidate.** The single-instruction stub-thunk path called
  `add_reference_candidate(target, i_address, …)` even when
  `target == i_address` (the classic debugger-trap / never-returns
  sentinel), creating a self-loop in the candidate queue. Now
  guarded with `if target != i_address`.

### Fixed — Mach-O discovery

- **`get_code_areas` restricted to instruction-bearing sections.** Was
  including the entire `__TEXT` segment (load-commands header + all
  sections), producing a junk 1-insn "function" at `base_addr`. Now
  iterates sections and accepts only those with
  `S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS` set, or
  whose `sectname` is `__text` / `__stubs` / `__stub_helper` /
  `__symbol_stub`. Falls back to whole-segment when section parsing
  fails (corrupted / stripped binaries).
- **Apple-clang x86_64 prologue patterns added** to
  `DEFAULT_PROLOGUES`. The pre-0.5.1 set was MSVC + GCC / clang-Linux
  flavoured and missed most Apple-built binaries (which is why
  `/bin/ls` returned zero functions in 0.5.0). Added:
  - `55 48 89 E5` (push rbp; mov rbp, rsp) — classic x86_64 prologue.
  - `48 81 EC ?? ?? ?? ??` (sub rsp, imm32) — large-frame leaf
    functions.
  - `48 89 6C 24 ??` (mov [rsp+disp8], rbp) — alternate save.
  - `41 56 53` (push r14; push rbx).
  - `41 55 41 54` (push r13; push r12).
  - `53 48 83 EC` (push rbx; sub rsp, ...).

## [0.5.0] — 2026-05-25 — Breaking-change batch

Four interlocking API breaks shipped as one coherent major bump so
downstream consumers migrate once and unlock everything below. After
this release, `FileFormat`, `FileArchitecture`, and `BinaryInfo` /
`DisassemblyReport` carry `#[non_exhaustive]` so future additions stop
costing a major.

### Breaking changes

- **`SmdaConfig` builder replaces positional `bool` args.** The old
  `Disassembler::parse(raw, path, high_accuracy, resolve_tailcalls)`
  and `parse_with_timeout(...)` signatures are removed in favour of a
  single `parse(raw, &SmdaConfig)`. `parse_buffer` likewise takes a
  config now. Future analysis knobs land as new builder methods
  without further breaks.

  Before (0.4.2):
  ```rust
  let report = Disassembler::parse(&buf, Some(path), false, false)?;
  ```

  After (0.5.0):
  ```rust
  let cfg = SmdaConfig::new().path(path);
  let report = Disassembler::parse(&buf, &cfg)?;
  ```
- **`FileFormat::MachO` + `FileFormat::Buffer` variants added.** The
  enum is now `#[non_exhaustive]`. Downstream `match` statements need
  a wildcard arm. `parse_buffer` now sets `file_format = Buffer`
  instead of the 0.4.x `ELF` cosplay.
- **`DisassemblyReport::xmetadata: Option<XMetadata>`** is a new pub
  field; `DisassemblyReport` is now `#[non_exhaustive]`. Struct-literal
  construction by downstreams is no longer supported (use the
  constructor / `..Default::default()` if you were doing this).

### Added — formats

- **MachO loader (Intel: x86_64, i386).** New `macho` module mirrors
  the `pe` / `elf` surface: `map_binary`, `get_base_address`,
  `get_bitness`, `get_code_areas`. Uses goblin's Mach-O parser. Fat
  binaries are sliced to the x86 architecture; ARM slices are
  ignored. Imports populated from the lazy bind opcodes; exports
  from the export trie.
- **Raw-buffer format tag.** `parse_buffer(...)` reports
  `FileFormat::Buffer` instead of `FileFormat::ELF`. Consumers can
  switch on `file_format` rather than `is_buffer` (both still work).

### Added — metadata

- **PE debug directory → `report.xmetadata: Option<XMetadata>`.**
  Captures CodeView/PDB GUID + age + path, debug timestamp, debug
  entry type. Useful for symbol-server (SymSrv) lookups. `None` on
  ELF / MachO / Buffer or PE without `IMAGE_DIRECTORY_ENTRY_DEBUG`.

### Internal — SemVer hardening

- `FileFormat`, `FileArchitecture` are now `#[non_exhaustive]` —
  adding variants in future minor releases is no longer breaking.
- `BinaryInfo`, `DisassemblyReport` are now `#[non_exhaustive]` —
  adding pub fields in future minor releases is no longer breaking.

### Migration guide

1. Replace `parse(&buf, Some(path), hf, rt)` with
   `parse(&buf, &SmdaConfig::new().path(path).high_accuracy(hf).resolve_tailcalls(rt))`.
2. Replace `parse_with_timeout(&buf, …, timeout)` with the same plus
   `.timeout(duration)` on the config.
3. Add a wildcard arm to any `match report.format { … }` you have
   downstream — at minimum
   `FileFormat::MachO | FileFormat::Buffer => …`.
4. If you constructed `BinaryInfo` or `DisassemblyReport` by struct
   literal, switch to the provided constructors (rare — these were
   internal in practice).

## [0.4.2] — 2026-05-25 — Analysis helpers + raw-buffer entry (additive)

Additive-only release. No breaking changes from 0.4.1; consumers can
bump `smda = "0.4"` and pick up everything below without source edits.

### Added — Function-level analysis helpers

- **`Function::dominator_tree()` / `Function::nesting_depth()`** (N15).
  Iterative dataflow dominator computation over `Function.blockrefs`;
  `nesting_depth()` returns the maximum loop-nest depth per block by
  detecting back-edges against the dominator relation. Mirrors
  `SmdaFunction.getBlockDominatorTree` / `getNestingDepth` in the Python
  upstream. Per-function CFGs are small (typically < 100 blocks) so the
  iterative algorithm is fast enough; no Lengauer-Tarjan needed.
- **`Function::pic_hash()` / `Function::opcode_hash()`** (N16).
  Position-independent SHA-256 (first 8 bytes, little-endian `u64`)
  over the function's instruction stream. PIC hash emits a canonical
  structural signature per instruction — iced `Code` variant, operand
  kinds, register operands, memory base/index/scale — and deliberately
  omits memory displacements, RIP-relative offsets, and near-branch
  targets. Immediate values are kept (they often carry semantic
  fingerprints: syscall numbers, constants, string lengths). Opcode
  hash hashes only the `Mnemonic` sequence — broadest clustering
  granularity. Block iteration is sorted by VA for HashMap-order
  determinism. Used by malware-clustering pipelines (capa-rs
  downstream, smda's own n-gram db). Mirrors `SmdaFunction.getPicHash`
  / `getOpcHash` upstream.

### Added — raw memory-dump entry point

- **`Disassembler::parse_buffer(raw, base_addr, bitness, ...)`** (N11).
  Bypass PE / ELF header parsing for shellcode / memory dumps / unpacked
  modules where there is no file format wrapper. Synthesises a single
  `SectionMap` covering the entire buffer at `base_addr`; sets
  `BinaryInfo.is_buffer = true`. Mirrors `disassembleBuffer` upstream.

### Added — symbol resolvers

- **Rust symbol demangling** (N3). New `demangle` module wraps
  `rustc-demangle` for legacy (`_ZN…`) and v0 (`_R…`) Rust mangling.
  Wired into the ELF symbol provider via `parse_symbols`; non-Rust
  names round-trip unchanged. DWARF names also flow through it
  (MinGW + Rust toolchains gain it transparently).
- **MinGW DWARF symbol resolver**. New `dwarf` module walks
  `.debug_info` / `.debug_abbrev` / `.debug_str` on PE files compiled
  with MinGW-GCC and recovers `(low_pc_va, name)` pairs from
  `DW_TAG_subprogram` DIEs. Prefers `DW_AT_linkage_name` over
  `DW_AT_name`; handles both absolute-VA (newer MinGW) and RVA
  (older MinGW) `low_pc` encodings. Silent no-op when no debug
  sections are present. Uses `gimli 0.32`.

### Added — function discovery

- **PE exception-handler reliability**. The 0.4.1 `.pdata` sweep now
  validates the full UNWIND_INFO chain (version field, in-range
  `UnwindInfoAddress`, sane `CountOfCodes`) before accepting a
  `BeginAddress` as a function candidate. Drops false-positive seeds
  from malformed `.pdata` in packed binaries.
- **Go `pclntab` parser**. New `pclntab` module detects Go binaries via
  the runtime magic (`0xFFFFFFFB` v1.2, `0xFFFFFFFA` v1.16, `0xFFFFFFF1`
  v1.18, `0xFFFFFFF0` v1.20), parses the function table, and seeds
  `function_symbols` + candidate scanner with Go function names.
  Massive name-recovery win on stripped Go binaries. Conservative
  parser: any bounds / sanity check failure skips the entry rather
  than failing the analysis.
- **Delphi VMT scanner**. New `delphi` module scans every readable
  section for the `vmtSelfPtr` self-reference signature (32-bit and
  64-bit Delphi), recovers class names from each VMT's Pascal short
  string, and walks the user-virtual-method table to seed method
  addresses as `ClassName::vmt_<index>` symbols. Conservative class-name
  filter (printable ASCII, length ≤ 100, well-formed Pascal short
  string) drops false-positive hits; vtable walk stops on null
  pointer, out-of-image pointer, or after 256 methods. Silent no-op
  on non-Delphi binaries.

### Internal — symbol pipeline

- `function_analysis_state::finalize_analysis` no longer wipes
  pre-populated `function_symbols` entries with an empty `state.label`
  (the label-provider `get_symbol` path is unimplemented today, so the
  blind insert was clobbering Go pclntab and MinGW DWARF names that
  parse_inner had seeded). The insert is now guarded:
  `if !label.is_empty() || !function_symbols.contains_key(...)`.
- `get_symbol_candidates` now also pulls addresses from pre-populated
  `function_symbols`, so seeded names become candidate function starts
  in the scanner.

### Dependencies

- Added `rustc-demangle = "0.1"` (tiny, no transitive deps).
- Added `gimli = { version = "0.32", default-features = false, features = ["read", "std"] }`
  for the MinGW DWARF parser. Pure Rust.


## [0.4.1] — 2026-05-24 — Upstream parity (additive)

Closes the bulk of the Python-upstream feature gap that 0.4.0 left
behind. All changes are additive — no breaking changes from 0.4.0, no
new public types removed or renamed. Capa-rs and other downstream
consumers can bump to `smda = "0.4"` and pick up everything below
without any code changes.

### Bug fix

- **Tail-call analyser was a no-op.** `Disassembler::parse(..., resolve_tailcalls=true)`
  did nothing in 0.3.x / 0.4.0 because `TailCallAnalyser::functions`
  was never populated (see the historical `//TODO` in
  `tail_call_analyser.rs:62`). `finalize_function` now correctly
  inserts each completed `FunctionAnalysisState` into the intervals
  table so `get_tailcalls` / `resolve_tailcalls` have data to work
  with. `FunctionAnalysisState` gained a `#[derive(Clone)]` to support
  this.

### Added — analysis accuracy (Python upstream parity)

- **GCC / clang `endbr64` prologues** (M1, mirrors Python upstream
  v2.4.4). `DEFAULT_PROLOGUES` now includes `F3 0F 1E FA` (endbr64),
  `F3 0F 1E FB` (endbr32), `48 89 5C 24 ??` (mov [rsp+disp8], rbx),
  `48 83 EC ??` (sub rsp, imm8), and `41 57 41 56` (push r15; push r14).
  Modern Linux ELFs compiled with `-fcf-protection` (default on
  Ubuntu 22.04+, Fedora 36+, RHEL 9+, Debian 12+) are no longer
  under-discovered. `common_start_bytes[64]` weights `0xF3` at 1200
  so the new heuristic dominates only on CET-enabled samples.
- **PE export-directory as candidate source** (M4). The PE export
  RVAs collected on `BinaryInfo.exports` are now seeded into the
  function-start candidate set. Trivial coverage win on stripped DLLs
  that still export their public surface.
- **Linux exit-syscall recognition** (M2, mirrors Python upstream
  v2.4.4). The analyser now tracks the most recent `mov {al, ax, eax,
  rax}, IMM` and treats a following `syscall` / `sysenter` / `int 0x80`
  as a function end when IMM is one of the known exit syscall numbers
  (60 / 231 on x86_64; 1 / 252 / 60 on x86 via int 0x80). Cleaner
  function ends in ELFs that call `_exit` / `_Exit` directly.

### Added — public surface (Python upstream parity)

- **`DisassemblyReport.oep: u64`** (N8). Original entry point as a
  virtual address. PE: `ImageBase + AddressOfEntryPoint`. ELF:
  `e_entry`. Mirrors `SmdaReport.oep` upstream. `BinaryInfo::get_oep()`
  now correctly returns the ELF entry too (was PE-only and forgot
  `+ base_addr` for PE).
- **`Function.is_exported: bool`** (N7). True if the function's offset
  matches a PE export RVA. Always false for ELF in 0.4.1 (would need
  `STB_GLOBAL` dynsym lookup — deferred to 0.5.0).
- **`Function.stringrefs: Vec<u64>`** (N12). VAs of instructions that
  store a printable ASCII / UTF-16LE immediate into a stack slot —
  the classic "stack string" pattern (`mov [rsp+N], 0x6c6c6568`
  "hell"). Populated by walking each function's blocks once via the
  existing `Instruction::get_printable_len` (which was implemented in
  0.3.0 but never invoked until now).
- **`DisassemblyReport::find_function_by_offset(addr)`** and
  **`find_block_by_offset(addr)`** (N10). Linear-scan lookups
  mirroring `SmdaReport.findFunctionByOffset` / `findBlockByOffset`
  upstream. For 100k-function binaries the scan is roughly 5 ms —
  cache the result if you call it on every instruction.
- **`Disassembler::parse_with_timeout(..., timeout)`** + new
  `Error::AnalysisTimeout(Duration)` variant (N14). Optional
  wall-clock budget for batch processors of untrusted samples.
  Checked at the top of `analyse_function`; returns
  `Err(AnalysisTimeout)` once exceeded, discarding partial state.

### Unchanged

- All `Disassembler::parse` signatures from 0.4.0.
- `BinaryInfo<'a>`, `DisassemblyResult<'a>`, `Disassembler<'a>`,
  `DisassemblyReport<'a>` shapes.
- Memory profile (additive only; no new per-instruction allocations).
- Section-map zero-copy model.

### Deferred to 0.5.0

For visibility — items considered for 0.4.1 but deferred because they
would either break the API or require a new dependency:

- M3 (exception-handler reliability — needs unwind-info parsing).
- N1 (Go `pclntab` + Go strings — large addition).
- N3 (Rust demangling — adds `rustc-demangle` dep).
- N5 (MachO support — re-enables `goblin` mach feature; also adds a
  new `FileFormat::MachO` variant which is technically breaking).
- N9 (xmetadata block — debug directory walk).
- N11 (raw memory-dump `disassembleBuffer` entry).
- N13 (`SmdaConfig` builder — supersedes positional bool args, breaking).
- N15 (DominatorTree / nesting depth).
- N16 (PIC hash + opcode hash).

Permanently out of scope: CIL backend (use `dnfile-rs`), DEX backend,
IDA exporter, ApiScout integration (already covered by
`win_api_resolver` using the embedded JSON DBs), LIEF / pdbparse.

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
