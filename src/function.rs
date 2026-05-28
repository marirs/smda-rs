//! Decoded function and instruction types.
//!
//! 0.6.0: `Instruction` now wraps a [`crate::disassembler::DecodedInsn`]
//! enum (x86 or AArch64). The 0.5.x `pub iced: iced_x86::Instruction`
//! reach-through field is gone — callers that previously did
//! `ins.iced.mnemonic()` use one of the typed accessors below
//! (`ins.mnemonic_enum()` / `ins.op_kind(i)` / …). The accessors that
//! make sense only on x86 carry an `Option<…>` return; arch-agnostic
//! helpers (`is_call`, `is_jmp`, `is_ret`) dispatch internally.
//!
//! As of 0.4.0 `Instruction` is *fully zero-copy*: only the fully-decoded
//! per-arch carrier is stored per instruction, plus offset + length. The
//! mnemonic / operands strings are formatted on demand via
//! [`Instruction::format_mnemonic`] / [`Instruction::format_operands`],
//! and the raw bytes are looked up via [`Instruction::bytes_in`] against
//! a `&BinaryInfo`.
//!
//! The capstone-compatible IntelFormatter lives in
//! [`crate::disassembler::capstone_compat_formatter`] — re-exported here
//! for downstream API compatibility.

use crate::disassembler::DecodedInsn;
use crate::{BinaryInfo, DisassemblyReport, DisassemblyResult, FileArchitecture, Result};
use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use std::collections::HashMap;

pub use crate::disassembler::capstone_compat_formatter;

/// A single decoded instruction. Wraps a [`DecodedInsn`] enum so the
/// per-instruction surface is identical for x86 and AArch64.
///
/// 0.6.0 dropped the public `iced: iced_x86::Instruction` field;
/// downstream consumers that need typed iced access should call
/// [`Instruction::iced`] (returns `Option`) or pattern-match on
/// [`Instruction::decoded`].
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub arch: FileArchitecture,
    pub bitness: u32,
    pub offset: u64,
    /// Byte length. 1–15 for x86; always 4 for AArch64.
    pub length: u32,
    /// The decoded per-arch carrier. Variant matches `arch`.
    pub decoded: DecodedInsn,
}

impl Instruction {
    /// Construct from a `DecodedInsn` carrier. Zero-allocation in 0.4.0
    /// (no string formatting at construction time).
    #[must_use]
    pub fn new(arch: FileArchitecture, bitness: u32, ins: &DecodedInsn) -> Self {
        Self {
            arch,
            bitness,
            offset: ins.offset(),
            length: ins.length() as u32,
            decoded: *ins,
        }
    }

    /// The underlying iced instruction for x86 decodes. Returns `None`
    /// on AArch64 — callers walking operands should branch on
    /// `arch` / `decoded` to pick the right path.
    #[inline]
    #[must_use]
    pub fn iced(&self) -> Option<&iced_x86::Instruction> {
        self.decoded.as_iced()
    }

    /// Format the mnemonic on demand. Allocates a fresh `String` per call —
    /// hot-path consumers that read the mnemonic repeatedly should cache
    /// the result locally or use `mnemonic_enum()` for typed comparisons
    /// (x86) / `mnemonic_aarch64()` (AArch64).
    #[must_use]
    pub fn format_mnemonic(&self) -> String {
        self.decoded.format_mnemonic()
    }

    /// Format the operands on demand. Returns `None` for zero-operand
    /// instructions (e.g. `ret`). Allocates a fresh `String` per call.
    #[must_use]
    pub fn format_operands(&self) -> Option<String> {
        self.decoded.format_operands()
    }

    /// Look up the raw instruction bytes in the given `BinaryInfo`.
    /// Zero-copy: returns a `&[u8]` borrowing from the input file.
    pub fn bytes_in<'b>(&self, binary_info: &'b BinaryInfo<'_>) -> Result<&'b [u8]> {
        binary_info.bytes_at(self.offset, self.length)
    }

    /// Convenience: hex-encoded bytes (compat shim for callers that
    /// previously read `Instruction::bytes` directly).
    pub fn bytes_hex(&self, binary_info: &BinaryInfo<'_>) -> Result<String> {
        Ok(hex::encode(self.bytes_in(binary_info)?))
    }

    // ---- typed accessors -------------------------------------------------
    //
    // Surface kept signature-compatible with 0.5.x where possible: the
    // x86-only accessors return their iced types directly when called on
    // an x86 instruction (panicking on AArch64 would be wrong; we return
    // a sentinel — see method docs). Use the `_opt` siblings when the
    // analyser wants to gracefully degrade on AArch64.

    /// iced `Mnemonic` for x86 instructions. Returns `Mnemonic::INVALID`
    /// on AArch64 (use [`Instruction::mnemonic_aarch64`] there).
    #[must_use]
    pub fn mnemonic_enum(&self) -> Mnemonic {
        self.decoded
            .mnemonic_enum_x86()
            .unwrap_or(Mnemonic::INVALID)
    }

    /// AArch64 mnemonic string (e.g. `"ldr"`, `"stp"`, `"bl"`) or
    /// `None` on x86. Allocates per call — Debug-derived from
    /// `disarm64::decoder::Mnemonic`.
    #[must_use]
    pub fn mnemonic_aarch64(&self) -> Option<String> {
        self.decoded.mnemonic_aarch64()
    }

    /// iced `Code` for x86 instructions. Returns `Code::INVALID` on
    /// AArch64.
    #[must_use]
    pub fn code(&self) -> iced_x86::Code {
        self.decoded.code_x86().unwrap_or(iced_x86::Code::INVALID)
    }

    #[must_use]
    pub fn op_count(&self) -> u32 {
        self.decoded.op_count()
    }

    /// iced `OpKind` for the i-th operand. Returns `OpKind::Register`
    /// on AArch64 (no-op sentinel — analysers should gate on `arch`
    /// before calling this). AArch64 analysers walk operands via the
    /// dedicated `disassembler::aarch64_ops` decoders instead, which
    /// work directly on the 32-bit instruction word.
    #[must_use]
    pub fn op_kind(&self, i: u32) -> OpKind {
        self.decoded.op_kind_x86(i).unwrap_or(OpKind::Register)
    }

    #[must_use]
    pub fn op_register(&self, i: u32) -> Register {
        self.decoded.op_register_x86(i).unwrap_or(Register::None)
    }

    #[must_use]
    pub fn memory_base(&self) -> Register {
        self.decoded.memory_base_x86().unwrap_or(Register::None)
    }

    #[must_use]
    pub fn memory_index(&self) -> Register {
        self.decoded.memory_index_x86().unwrap_or(Register::None)
    }

    #[must_use]
    pub fn memory_displacement64(&self) -> u64 {
        self.decoded.memory_displacement64_x86().unwrap_or(0)
    }

    #[must_use]
    pub fn memory_segment(&self) -> Register {
        self.decoded.memory_segment_x86().unwrap_or(Register::None)
    }

    #[must_use]
    pub fn near_branch_target(&self) -> u64 {
        self.decoded.near_branch_target_x86().unwrap_or(0)
    }

    #[must_use]
    pub fn flow_control(&self) -> FlowControl {
        self.decoded.flow_control_x86().unwrap_or(FlowControl::Next)
    }

    #[must_use]
    pub fn is_call(&self) -> bool {
        self.decoded.is_call()
    }

    #[must_use]
    pub fn is_jmp(&self) -> bool {
        self.decoded.is_jump()
    }

    #[must_use]
    pub fn is_conditional_jmp(&self) -> bool {
        match &self.decoded {
            DecodedInsn::X86(x) => matches!(x.iced.flow_control(), FlowControl::ConditionalBranch),
            DecodedInsn::Aarch64(a) => matches!(
                a.decoded.mnemonic,
                disarm64::decoder::Mnemonic::b_
                    | disarm64::decoder::Mnemonic::cbz
                    | disarm64::decoder::Mnemonic::cbnz
                    | disarm64::decoder::Mnemonic::tbz
                    | disarm64::decoder::Mnemonic::tbnz
            ),
        }
    }

    #[must_use]
    pub fn is_ret(&self) -> bool {
        self.decoded.is_return()
    }

    // ---- algorithms (migrated from capstone-string-parsing to typed) ------

    /// Detects "`mov [stack], <imm>`"-style stack strings. Returns the
    /// printable length of the immediate if it is ASCII / UTF-16 LE, else 0.
    ///
    /// x86 only — returns Ok(0) on AArch64 because the ARM64 pattern
    /// (MOVZ/MOVK into Rn followed by `STR Rn, \[sp, #N\]`) needs
    /// multi-instruction state to recognise. That detection lives in
    /// `Function::collect_aarch64_stack_strings` and runs separately
    /// on the per-function stringrefs accumulator.
    pub fn get_printable_len(&self) -> Result<u64> {
        let Some(iced) = self.iced() else {
            return Ok(0);
        };
        if iced.op_count() != 2 {
            return Ok(0);
        }
        let (chars, ascii_len, utf16_len): (Vec<u8>, u64, u64) = match iced.op_kind(1) {
            OpKind::Immediate8 => (vec![iced.immediate8()], 1, 0),
            OpKind::Immediate16 => (iced.immediate16().to_le_bytes().to_vec(), 2, 1),
            OpKind::Immediate32 => (iced.immediate32().to_le_bytes().to_vec(), 4, 2),
            OpKind::Immediate64 => (iced.immediate64().to_le_bytes().to_vec(), 8, 4),
            _ => return Ok(0),
        };
        if is_printable_ascii(&chars)? {
            return Ok(ascii_len);
        }
        if utf16_len > 0 && is_printable_utf16le(&chars)? {
            return Ok(utf16_len);
        }
        Ok(0)
    }

    /// Returns the absolute addresses referenced by immediate or memory
    /// operands, filtered to addresses inside the mapped image. Skips
    /// control-flow / compare / test instructions.
    ///
    /// x86 only — returns an empty Vec on AArch64. An ARM64 equivalent
    /// would need `ADR` / `ADRP` + immediate-offset resolution against
    /// the analyser's section map; not yet implemented.
    pub fn get_data_refs(&self, report: &DisassemblyReport) -> Result<Vec<u64>> {
        let Some(iced) = self.iced() else {
            return Ok(vec![]);
        };
        if !matches!(
            iced.flow_control(),
            FlowControl::Next | FlowControl::Exception
        ) {
            return Ok(vec![]);
        }
        if matches!(
            iced.mnemonic(),
            Mnemonic::Cmp
                | Mnemonic::Cmpsb
                | Mnemonic::Cmpsw
                | Mnemonic::Cmpsd
                | Mnemonic::Cmpsq
                | Mnemonic::Test
        ) {
            return Ok(vec![]);
        }
        let mut res = Vec::new();
        for i in 0..iced.op_count() {
            let value: u64 = match iced.op_kind(i) {
                OpKind::Immediate8 => iced.immediate8() as u64,
                OpKind::Immediate16 => iced.immediate16() as u64,
                OpKind::Immediate32 => iced.immediate32() as u64,
                OpKind::Immediate64 => iced.immediate64(),
                OpKind::Memory => iced.memory_displacement64(),
                _ => 0,
            };
            if value != 0 && report.is_addr_within_memory_image(&value)? {
                res.push(value);
            }
        }
        Ok(res)
    }
}

// `characteristics`, `confidence`, and `tfidf` (below) are populated
// by `Function::new` for `Debug` print output and downstream tooling
// inspection; no in-crate reader.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Function {
    pub arch: crate::FileArchitecture,
    pub format: crate::FileFormat,
    pub bitness: u32,
    pub offset: u64,
    blocks: HashMap<u64, Vec<Instruction>>,
    pub apirefs: HashMap<u64, (Option<String>, Option<String>)>,
    pub blockrefs: HashMap<u64, Vec<u64>>,
    pub inrefs: Vec<u64>,
    pub outrefs: HashMap<u64, Vec<u64>>,
    pub binweight: u32,
    characteristics: String,
    confidence: f32,
    function_name: String,
    tfidf: f32,
    /// True if this function's offset matches a PE export RVA (i.e. the
    /// function is part of the binary's public surface). Always false for
    /// ELF / raw memory dumps in 0.4.1 — we'd need to consult dynsym
    /// `STB_GLOBAL` symbols there, which is a 0.5.0 item.
    pub is_exported: bool,
    /// (0.4.1 N12) Per-function stack-string references. Each entry is
    /// the VA of an instruction that stores a printable ASCII or UTF-16LE
    /// immediate into a stack slot (the classic `mov [rsp+N], 0x6c6c6568`
    /// "hell" stack-string pattern). Consumers like capa-rs use these for
    /// string-based behavioural rule matching.
    pub stringrefs: Vec<u64>,
}

impl Function {
    pub fn new(disassembly: &DisassemblyResult, function_offset: &u64) -> Result<Function> {
        let f =
            Function {
                arch: disassembly.binary_info.file_architecture,
                format: disassembly.binary_info.file_format,
                bitness: disassembly.binary_info.bitness,
                offset: *function_offset,
                blocks: Function::parse_blocks(
                    disassembly,
                    &disassembly.get_blocks_as_decoded(function_offset)?,
                )?,
                apirefs: disassembly.get_api_refs(function_offset)?,
                blockrefs: disassembly.get_block_refs(function_offset)?,
                inrefs: disassembly.get_in_refs(function_offset)?,
                outrefs: disassembly.get_out_refs(function_offset)?,
                binweight: 0,
                characteristics: if disassembly.candidates.contains_key(function_offset) {
                    disassembly.candidates[function_offset].get_characteristics()?
                } else {
                    "-----------".to_string()
                },
                confidence: if disassembly.candidates.contains_key(function_offset) {
                    disassembly.candidates[function_offset].get_confidence()?
                } else {
                    0.0
                },
                function_name: match disassembly.function_symbols.get(function_offset) {
                    Some(s) => s.clone(),
                    _ => String::new(),
                },
                tfidf: if disassembly.candidates.contains_key(function_offset) {
                    disassembly.candidates[function_offset].get_tfidf()?
                } else {
                    0.0
                },
                is_exported: {
                    let base = disassembly.binary_info.base_addr;
                    disassembly.binary_info.exports.iter().any(|(_n, rva, _f)| {
                        base.checked_add(*rva as u64) == Some(*function_offset)
                    })
                },
                stringrefs: Vec::new(),
            };
        let mut f = f;
        for block in f.blocks.values() {
            // x86 path: per-instruction `get_printable_len` fires on
            // any `mov [mem], imm` where the immediate is printable.
            for ins in block {
                if ins.get_printable_len().unwrap_or(0) > 0 {
                    f.stringrefs.push(ins.offset);
                }
            }
            // (0.6.1) AArch64 path: stack strings on ARM64 are built
            // by a MOVZ/MOVK chain into Wn/Xn followed by a STR to
            // `[sp, #N]` or `[x29, #N]`. Track per-block register-to-
            // value bindings; when a STR fires whose source register
            // holds a printable value, surface the STR's offset as a
            // stringref (mirrors the semantic the x86 path produces
            // for the equivalent immediate-store-to-stack pattern).
            Function::collect_aarch64_stack_strings(block, &mut f.stringrefs);
        }
        f.stringrefs.sort_unstable();
        f.stringrefs.dedup();
        Ok(f)
    }

    /// (0.6.1) Walk a single basic block tracking MOVZ/MOVK chains
    /// into the 32 GPRs, and push the offset of any `STR <reg>, [SP/X29, #N]`
    /// where `<reg>` holds a printable ASCII/UTF-16 value at the time
    /// of the store. Idempotent — the caller dedups `stringrefs`.
    ///
    /// This is intentionally a per-block (not cross-block) tracker:
    /// most compiler-emitted stack strings live entirely inside the
    /// block that does the store, and the dataflow we'd need across
    /// blocks (phi-style merging across branch joins) doesn't pay for
    /// itself for the stack-string use case.
    fn collect_aarch64_stack_strings(block: &[Instruction], stringrefs: &mut Vec<u64>) {
        use crate::disassembler::DecodedInsn;
        use crate::disassembler::aarch64_ops::{MovWideKind, decode_ldr_str_uimm, decode_mov_wide};
        use std::collections::HashMap;

        // reg_num -> current materialised value (low 64 bits)
        let mut reg_val: HashMap<u8, u64> = HashMap::new();

        for ins in block {
            let DecodedInsn::Aarch64(a) = &ins.decoded else {
                return; // non-AArch64 block — bail entirely
            };
            let w = a.opcode;

            // STR <reg>, [SP|X29, #imm12] — if the stored register is
            // tracked AND its value is printable, this is a stack
            // string write. SP and X29 (= R29, the frame pointer) are
            // the only stack-relative bases compilers use.
            if let Some(op) = decode_ldr_str_uimm(w)
                && op.is_store
                && (op.rn == 31 || op.rn == 29)
                && let Some(&value) = reg_val.get(&op.rt)
            {
                let bytes = match op.size_bytes {
                    1 => vec![value as u8],
                    2 => (value as u16).to_le_bytes().to_vec(),
                    4 => (value as u32).to_le_bytes().to_vec(),
                    8 => value.to_le_bytes().to_vec(),
                    _ => Vec::new(),
                };
                let ascii = is_printable_ascii(&bytes).unwrap_or(false);
                let utf16 = bytes.len() >= 4
                    && bytes.len().is_multiple_of(2)
                    && is_printable_utf16le(&bytes).unwrap_or(false);
                if ascii || utf16 {
                    stringrefs.push(ins.offset);
                }
                // STR doesn't write Rt — leave the tracker alone.
                continue;
            }

            // MOVZ / MOVN / MOVK update the per-register tracker.
            // Mirrors the syscall-tracker logic in the walker: MOVZ
            // overwrites, MOVN inverts, MOVK keeps non-targeted slots.
            if let Some((rd, value, kind)) = decode_mov_wide(w) {
                match kind {
                    MovWideKind::Movz | MovWideKind::Movn => {
                        reg_val.insert(rd, value);
                    }
                    MovWideKind::Movk => {
                        // (0.6.1, M2 defensive) `hw` lives at bits 22:21,
                        // so `& 0x3` already constrains it to 0..=3 — the
                        // shift `hw * 16` can be at most 48, well within
                        // u64 range. Belt-and-suspenders: skip the update
                        // if `hw` somehow ends up out of range rather
                        // than risking the shift becoming UB.
                        let hw = (w >> 21) & 0x3;
                        if hw >= 4 {
                            continue;
                        }
                        let slot_mask: u64 = 0xFFFFu64 << (hw * 16);
                        let prev = reg_val.get(&rd).copied().unwrap_or(0);
                        reg_val.insert(rd, (prev & !slot_mask) | (value & slot_mask));
                    }
                }
            }
            // Any other instruction *might* clobber some register;
            // we don't model the full ABI. The trade-off: we may
            // over-track in rare cases, but stale-tracker entries
            // only cause harm if (a) they happen to be printable AND
            // (b) a subsequent STR uses them — both rare enough that
            // a false positive in stringrefs is acceptable here.
        }
    }

    fn parse_blocks(
        disassembly: &DisassemblyResult,
        block_dict: &HashMap<u64, Vec<DecodedInsn>>,
    ) -> Result<HashMap<u64, Vec<Instruction>>> {
        let mut blocks = HashMap::with_capacity(block_dict.len());
        for (offset, block) in block_dict {
            let mut instructions = Vec::with_capacity(block.len());
            for ins in block {
                instructions.push(Instruction::new(
                    disassembly.binary_info.file_architecture,
                    disassembly.binary_info.bitness,
                    ins,
                ));
            }
            blocks.insert(*offset, instructions);
        }
        Ok(blocks)
    }

    pub fn get_blocks(&self) -> Result<&HashMap<u64, Vec<Instruction>>> {
        Ok(&self.blocks)
    }

    pub fn get_instructions(&self) -> Result<Vec<&Instruction>> {
        let mut res = vec![];
        for b in self.blocks.values() {
            for i in b {
                res.push(i);
            }
        }
        Ok(res)
    }

    pub fn get_num_instructions(&self) -> Result<usize> {
        Ok(self.blocks.values().map(Vec::len).sum())
    }

    pub fn get_num_outrefs(&self) -> Result<usize> {
        Ok(self.outrefs.values().map(Vec::len).sum())
    }

    /// (0.4.2) Symbolic function name — populated from Go pclntab, MinGW
    /// DWARF, Rust-demangled ELF symbols, Delphi VMT, or any other
    /// symbol source wired into `function_symbols`. Returns `""` when
    /// no source recovered a name for this offset.
    #[must_use]
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    pub fn is_api_thunk(&self) -> Result<bool> {
        if self.get_num_instructions()? != 1 {
            return Ok(false);
        }
        let first_ins = &self.blocks[&self.offset][0];
        // The thunk shape is the same idea on both architectures —
        // a single instruction that transfers control to an imported
        // symbol — but the mnemonic set differs.
        //
        //   x86:     `jmp <api>` or `call <api>`.
        //   AArch64: `b <api>` (the typical PLT thunk on Linux) or
        //            `bl <api>` (rare — would mean call-then-fall-off,
        //            still flagged because get_api_refs follows both
        //            and the apirefs check below disambiguates).
        //
        // ADRP+LDR+BR multi-insn GOT thunks are >1 instruction so the
        // count guard above already excludes them — they show up as
        // ordinary functions with an imported call inside, which is
        // the correct classification.
        match first_ins.decoded {
            DecodedInsn::X86(_) => {
                if !matches!(first_ins.mnemonic_enum(), Mnemonic::Jmp | Mnemonic::Call) {
                    return Ok(false);
                }
            }
            DecodedInsn::Aarch64(a) => {
                use crate::disassembler::{
                    aarch64_is_direct_call, aarch64_is_unconditional_branch,
                };
                if !(aarch64_is_direct_call(&a.decoded)
                    || aarch64_is_unconditional_branch(&a.decoded))
                {
                    return Ok(false);
                }
            }
        }
        if self.apirefs.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }

    // ---- 0.4.2 N15 — dominator tree + loop-nesting depth ------------------

    /// (0.4.2 N15) Compute the immediate-dominator tree over this function's
    /// CFG. Returns a map from each block VA to its immediate dominator VA.
    /// The entry block (this function's `offset`) is omitted — it has no
    /// dominator.
    #[must_use]
    pub fn dominator_tree(&self) -> HashMap<u64, u64> {
        use std::collections::BTreeSet;
        let entry = self.offset;
        let all_blocks: Vec<u64> = self.blocks.keys().copied().collect();
        if !self.blocks.contains_key(&entry) || all_blocks.len() <= 1 {
            return HashMap::new();
        }

        let mut preds: HashMap<u64, Vec<u64>> = HashMap::with_capacity(all_blocks.len());
        for b in &all_blocks {
            preds.insert(*b, Vec::new());
        }
        for (src, dsts) in &self.blockrefs {
            for d in dsts {
                if let Some(p) = preds.get_mut(d)
                    && !p.contains(src)
                {
                    p.push(*src);
                }
            }
        }

        let all_set: BTreeSet<u64> = all_blocks.iter().copied().collect();
        let mut dom: HashMap<u64, BTreeSet<u64>> = HashMap::with_capacity(all_blocks.len());
        let mut entry_only = BTreeSet::new();
        entry_only.insert(entry);
        dom.insert(entry, entry_only);
        for b in &all_blocks {
            if *b != entry {
                dom.insert(*b, all_set.clone());
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for b in &all_blocks {
                if *b == entry {
                    continue;
                }
                let bp = match preds.get(b) {
                    Some(p) if !p.is_empty() => p,
                    _ => continue,
                };
                let mut new_dom: Option<BTreeSet<u64>> = None;
                for p in bp {
                    if let Some(dp) = dom.get(p) {
                        match new_dom {
                            None => new_dom = Some(dp.clone()),
                            Some(ref mut nd) => {
                                *nd = nd.intersection(dp).copied().collect();
                            }
                        }
                    }
                }
                let mut nd = new_dom.unwrap_or_default();
                nd.insert(*b);
                if dom[b] != nd {
                    dom.insert(*b, nd);
                    changed = true;
                }
            }
        }

        let mut idom = HashMap::with_capacity(all_blocks.len().saturating_sub(1));
        for b in &all_blocks {
            if *b == entry {
                continue;
            }
            if dom[b] == all_set {
                continue;
            }
            let mut best: Option<(u64, usize)> = None;
            for c in &dom[b] {
                if c == b {
                    continue;
                }
                let size = dom.get(c).map_or(0, |s| s.len());
                if best.is_none_or(|(_, s)| size > s) {
                    best = Some((*c, size));
                }
            }
            if let Some((c, _)) = best {
                idom.insert(*b, c);
            }
        }
        idom
    }

    /// (0.4.2 N15) Compute the maximum loop-nesting depth for each block.
    #[must_use]
    pub fn nesting_depth(&self) -> HashMap<u64, u32> {
        use std::collections::HashSet;
        let idom = self.dominator_tree();
        let entry = self.offset;
        let all_blocks: HashSet<u64> = self.blocks.keys().copied().collect();
        let mut depth: HashMap<u64, u32> = all_blocks.iter().map(|b| (*b, 0u32)).collect();

        let dominates = |dominator: u64, block: u64| -> bool {
            if dominator == block {
                return true;
            }
            let mut cur = block;
            for _ in 0..self.blocks.len() {
                let Some(&parent) = idom.get(&cur) else {
                    return dominator == entry && cur == entry;
                };
                if parent == dominator {
                    return true;
                }
                if parent == cur {
                    return false;
                }
                cur = parent;
            }
            false
        };

        let mut back_edges: Vec<(u64, u64)> = Vec::new();
        for (src, dsts) in &self.blockrefs {
            if !all_blocks.contains(src) {
                continue;
            }
            for d in dsts {
                if all_blocks.contains(d) && dominates(*d, *src) {
                    back_edges.push((*src, *d));
                }
            }
        }
        if back_edges.is_empty() {
            return depth;
        }

        let mut preds: HashMap<u64, Vec<u64>> = HashMap::with_capacity(all_blocks.len());
        for b in &all_blocks {
            preds.insert(*b, Vec::new());
        }
        for (src, dsts) in &self.blockrefs {
            for d in dsts {
                if let Some(p) = preds.get_mut(d) {
                    p.push(*src);
                }
            }
        }

        for (s, h) in back_edges {
            let mut loop_blocks: HashSet<u64> = HashSet::new();
            loop_blocks.insert(h);
            if s != h {
                let mut stack = vec![s];
                loop_blocks.insert(s);
                while let Some(b) = stack.pop() {
                    if let Some(bp) = preds.get(&b) {
                        for p in bp {
                            if loop_blocks.insert(*p) {
                                stack.push(*p);
                            }
                        }
                    }
                }
            }
            for b in loop_blocks {
                if let Some(d) = depth.get_mut(&b) {
                    *d += 1;
                }
            }
        }
        depth
    }

    // ---- 0.4.2 N16 — PIC hash + opcode hash -------------------------------

    /// (0.4.2 N16) Position-independent hash of this function's instruction
    /// stream — first 8 bytes of SHA-256 over a canonical structural
    /// signature with displacements / branch targets zeroed.
    ///
    /// Two signatures depending on the variant: x86 uses the iced
    /// structural surface (operand kinds, registers); AArch64 uses
    /// `(opcode_word & 0xFFC003FF)` — the bits with the PC-relative
    /// displacement masked out (12-bit imm12 in bits \[21:10\] for
    /// LDR/STR; 19-bit imm19 for b.cond / cbz / ldr literal; 26-bit
    /// imm26 for unconditional b/bl). The mask we use here zeroes the
    /// largest of those slots without touching the register / opcode
    /// fields — adequate for clustering across relocation.
    #[must_use]
    pub fn pic_hash(&self) -> u64 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut block_offsets: Vec<u64> = self.blocks.keys().copied().collect();
        block_offsets.sort_unstable();
        let mut buf = Vec::with_capacity(32);
        for off in block_offsets {
            let block = &self.blocks[&off];
            for ins in block {
                match ins.decoded {
                    DecodedInsn::X86(x) => {
                        buf.clear();
                        Self::pic_signature_into(&x.iced, &mut buf);
                        hasher.update(&buf);
                    }
                    DecodedInsn::Aarch64(a) => {
                        // Mask bits [25:10] — covers imm26 / imm19 / imm12
                        // slots so PC-relative displacements drop out.
                        let masked = a.opcode & !0x03FF_FC00;
                        hasher.update(masked.to_le_bytes());
                    }
                }
            }
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&out[..8]);
        u64::from_le_bytes(bytes)
    }

    /// (0.4.2 N16) Mnemonic-only hash — broadest clustering granularity.
    /// First 8 bytes of SHA-256 over the function's `Mnemonic` sequence.
    #[must_use]
    pub fn opcode_hash(&self) -> u64 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut block_offsets: Vec<u64> = self.blocks.keys().copied().collect();
        block_offsets.sort_unstable();
        for off in block_offsets {
            let block = &self.blocks[&off];
            for ins in block {
                match ins.decoded {
                    DecodedInsn::X86(x) => {
                        let m = x.iced.mnemonic() as u32;
                        hasher.update(m.to_le_bytes());
                    }
                    DecodedInsn::Aarch64(a) => {
                        // Mnemonic is `#[repr(?)]` without a stable
                        // discriminant guarantee — use the Debug string,
                        // which is the variant name and therefore stable
                        // across disarm64 v0.1.x.
                        let dbg = format!("{:?}", a.decoded.mnemonic);
                        hasher.update(dbg.as_bytes());
                    }
                }
            }
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&out[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Internal — write the PIC signature of one decoded x86 instruction
    /// into `out`. See [`Function::pic_hash`] for the rationale.
    fn pic_signature_into(iced: &iced_x86::Instruction, out: &mut Vec<u8>) {
        out.extend_from_slice(&(iced.code() as u32).to_le_bytes());
        let count = iced.op_count();
        out.push(count as u8);
        for i in 0..count {
            let kind = iced.op_kind(i);
            out.push(kind as u8);
            match kind {
                OpKind::Register => {
                    out.extend_from_slice(&(iced.op_register(i) as u16).to_le_bytes());
                }
                OpKind::Memory => {
                    out.extend_from_slice(&(iced.memory_base() as u16).to_le_bytes());
                    out.extend_from_slice(&(iced.memory_index() as u16).to_le_bytes());
                    out.push(iced.memory_index_scale() as u8);
                }
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {}
                OpKind::Immediate8 => out.push(iced.immediate8()),
                OpKind::Immediate16 => out.extend_from_slice(&iced.immediate16().to_le_bytes()),
                OpKind::Immediate32 => out.extend_from_slice(&iced.immediate32().to_le_bytes()),
                OpKind::Immediate64 => out.extend_from_slice(&iced.immediate64().to_le_bytes()),
                OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => {
                    out.extend_from_slice(&iced.immediate(i).to_le_bytes());
                }
                _ => {}
            }
        }
    }
}

pub fn is_printable_ascii(chars: &[u8]) -> Result<bool> {
    for c in chars {
        if c >= &127 || !b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ ".contains(c){
            return Ok(false)
        }
    }
    Ok(true)
}

pub fn is_printable_utf16le(chars: &[u8]) -> Result<bool> {
    let mut i = 1;
    let mut u = vec![];
    while i < chars.len() {
        if i % 2 != 0 && chars[i] != 0x00 {
            return Ok(false);
        } else if i % 2 == 0 {
            u.push(chars[i]);
        }
        i += 1;
    }
    is_printable_ascii(&u)
}
