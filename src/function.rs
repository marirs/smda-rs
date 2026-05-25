//! Decoded function and instruction types.
//!
//! As of 0.4.0 `Instruction` is *fully zero-copy*: only the fully-decoded
//! `iced_x86::Instruction` (16 bytes, `Copy`) is stored per instruction,
//! plus offset + length. The mnemonic / operands strings are formatted on
//! demand via [`Instruction::format_mnemonic`] / [`Instruction::format_operands`],
//! and the raw bytes are looked up via [`Instruction::bytes_in`] against a
//! `&BinaryInfo`. Pre-0.4.0 each `Instruction` carried owned `String`
//! mnemonic + operands + hex-encoded bytes — a 6–15 MB allocation cost on
//! a 100k-instruction binary that this refactor eliminates.
//!
//! The formatter used by `format_mnemonic` / `format_operands` is
//! configured by [`capstone_compat_formatter`] to byte-match capstone's
//! output, so downstream consumers that pattern-match on the strings
//! (e.g. capa-rs rules) get the same characters they did under capstone.

use crate::{BinaryInfo, DisassemblyReport, DisassemblyResult, FileArchitecture, Result};
use iced_x86::{FlowControl, Formatter, IntelFormatter, Mnemonic, OpKind, Register};
use std::collections::HashMap;

/// Configure an `IntelFormatter` to emit capstone-compatible output:
/// lowercase hex with `0x` prefix, `dword ptr` / `qword ptr` size prefixes,
/// space around `+` / `-` in memory operands, and `, ` between operands.
/// Used internally so the existing string-based heuristics in the analyzer
/// continue to match.
#[must_use]
pub fn capstone_compat_formatter() -> IntelFormatter {
    let mut fmt = IntelFormatter::new();
    let opts = fmt.options_mut();
    // Numeric formatting
    opts.set_hex_prefix("0x");
    opts.set_hex_suffix("");
    opts.set_uppercase_hex(false);
    opts.set_small_hex_numbers_in_decimal(false);
    opts.set_add_leading_zero_to_hex_numbers(false);
    // Spacing
    opts.set_space_after_operand_separator(true);
    opts.set_space_between_memory_add_operators(true);
    opts.set_space_between_memory_mul_operators(false);
    // Registers / mnemonics lowercase
    opts.set_uppercase_mnemonics(false);
    opts.set_uppercase_registers(false);
    opts.set_uppercase_keywords(false);
    opts.set_uppercase_decorators(false);
    opts.set_uppercase_prefixes(false);
    // Memory size prefix ("dword ptr" / "qword ptr")
    opts.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    fmt
}

/// A single decoded x86/x64 instruction.
///
/// 0.4.0 dropped the per-instruction `bytes` / `mnemonic` / `operands`
/// String fields. Formatted strings are produced on demand via
/// [`Instruction::format_mnemonic`] / [`Instruction::format_operands`];
/// raw bytes are looked up via [`Instruction::bytes_in`] against the
/// owning `BinaryInfo`.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub arch: FileArchitecture,
    pub bitness: u32,
    pub offset: u64,
    /// Byte length (1–15).
    pub length: u32,
    /// Fully-decoded iced instruction (16 bytes, `Copy`). The single
    /// source of truth for mnemonic / operand / flow-control queries —
    /// prefer the typed accessors (`mnemonic_enum()`, `op_kind()`, …)
    /// over re-formatting via `format_mnemonic()`.
    pub iced: iced_x86::Instruction,
}

impl Instruction {
    /// Construct from a `DecodedInsn` carrier. Zero-allocation in 0.4.0
    /// (no string formatting at construction time).
    #[must_use]
    pub fn new(arch: FileArchitecture, bitness: u32, ins: &DecodedInsn) -> Self {
        Self {
            arch,
            bitness,
            offset: ins.offset,
            length: ins.length,
            iced: ins.iced,
        }
    }

    /// Format the mnemonic on demand. Allocates a fresh `String` per call —
    /// hot-path consumers that read the mnemonic repeatedly should cache
    /// the result locally or use `mnemonic_enum()` for typed comparisons.
    #[must_use]
    pub fn format_mnemonic(&self) -> String {
        let mut fmt = capstone_compat_formatter();
        let mut out = String::new();
        fmt.format_mnemonic(&self.iced, &mut out);
        out
    }

    /// Format the operands on demand. Returns `None` for zero-operand
    /// instructions (e.g. `ret`). Allocates a fresh `String` per call.
    #[must_use]
    pub fn format_operands(&self) -> Option<String> {
        if self.iced.op_count() == 0 {
            return None;
        }
        let mut fmt = capstone_compat_formatter();
        let mut out = String::new();
        fmt.format_all_operands(&self.iced, &mut out);
        Some(out)
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

    // ---- typed accessors (new in 0.3.0; preferred over string parsing) ----

    #[must_use]
    pub fn mnemonic_enum(&self) -> Mnemonic {
        self.iced.mnemonic()
    }
    #[must_use]
    pub fn code(&self) -> iced_x86::Code {
        self.iced.code()
    }
    #[must_use]
    pub fn op_count(&self) -> u32 {
        self.iced.op_count()
    }
    #[must_use]
    pub fn op_kind(&self, i: u32) -> OpKind {
        self.iced.op_kind(i)
    }
    #[must_use]
    pub fn op_register(&self, i: u32) -> Register {
        self.iced.op_register(i)
    }
    #[must_use]
    pub fn memory_base(&self) -> Register {
        self.iced.memory_base()
    }
    #[must_use]
    pub fn memory_index(&self) -> Register {
        self.iced.memory_index()
    }
    #[must_use]
    pub fn memory_displacement64(&self) -> u64 {
        self.iced.memory_displacement64()
    }
    #[must_use]
    pub fn memory_segment(&self) -> Register {
        self.iced.memory_segment()
    }
    #[must_use]
    pub fn near_branch_target(&self) -> u64 {
        self.iced.near_branch_target()
    }
    #[must_use]
    pub fn flow_control(&self) -> FlowControl {
        self.iced.flow_control()
    }
    #[must_use]
    pub fn is_call(&self) -> bool {
        matches!(
            self.iced.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        )
    }
    #[must_use]
    pub fn is_jmp(&self) -> bool {
        matches!(
            self.iced.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        )
    }
    #[must_use]
    pub fn is_conditional_jmp(&self) -> bool {
        matches!(self.iced.flow_control(), FlowControl::ConditionalBranch)
    }
    #[must_use]
    pub fn is_ret(&self) -> bool {
        matches!(self.iced.flow_control(), FlowControl::Return)
    }

    // ---- algorithms (migrated from capstone-string-parsing to typed) ------

    /// Detects "`mov [stack], <imm>`"-style stack strings. Returns the
    /// printable length of the immediate if it is ASCII / UTF-16 LE, else 0.
    pub fn get_printable_len(&self) -> Result<u64> {
        if self.iced.op_count() != 2 {
            return Ok(0);
        }
        let (chars, ascii_len, utf16_len): (Vec<u8>, u64, u64) = match self.iced.op_kind(1) {
            OpKind::Immediate8 => (vec![self.iced.immediate8()], 1, 0),
            OpKind::Immediate16 => (self.iced.immediate16().to_le_bytes().to_vec(), 2, 1),
            OpKind::Immediate32 => (self.iced.immediate32().to_le_bytes().to_vec(), 4, 2),
            OpKind::Immediate64 => (self.iced.immediate64().to_le_bytes().to_vec(), 8, 4),
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
    pub fn get_data_refs(&self, report: &DisassemblyReport) -> Result<Vec<u64>> {
        if !matches!(
            self.iced.flow_control(),
            FlowControl::Next | FlowControl::Exception
        ) {
            return Ok(vec![]);
        }
        if matches!(
            self.iced.mnemonic(),
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
        for i in 0..self.iced.op_count() {
            let value: u64 = match self.iced.op_kind(i) {
                OpKind::Immediate8 => self.iced.immediate8() as u64,
                OpKind::Immediate16 => self.iced.immediate16() as u64,
                OpKind::Immediate32 => self.iced.immediate32() as u64,
                OpKind::Immediate64 => self.iced.immediate64(),
                // iced returns the RIP-resolved displacement directly.
                OpKind::Memory => self.iced.memory_displacement64(),
                _ => 0,
            };
            if value != 0 && report.is_addr_within_memory_image(&value)? {
                res.push(value);
            }
        }
        Ok(res)
    }
}

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
                    // PE: match against the export-RVA list with image-base
                    // applied. The list is small (typically tens-to-hundreds
                    // of exports per DLL); a linear scan is cheaper than
                    // building a HashSet per Function construction.
                    let base = disassembly.binary_info.base_addr;
                    disassembly.binary_info.exports.iter().any(|(_n, rva, _f)| {
                        base.checked_add(*rva as u64) == Some(*function_offset)
                    })
                },
                stringrefs: Vec::new(),
            };
        // (0.4.1 N12) Walk every instruction in every block and record
        // those whose immediate operand looks like a printable
        // stack-string write. We can't fill this inside the struct
        // initializer because we need to look at the already-constructed
        // `blocks` field.
        let mut f = f;
        for block in f.blocks.values() {
            for ins in block {
                if ins.get_printable_len().unwrap_or(0) > 0 {
                    f.stringrefs.push(ins.offset);
                }
            }
        }
        f.stringrefs.sort_unstable();
        Ok(f)
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
        if !matches!(first_ins.mnemonic_enum(), Mnemonic::Jmp | Mnemonic::Call) {
            return Ok(false);
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
    ///
    /// Uses the iterative dataflow algorithm: O(N²·E) worst case, but
    /// per-function CFGs are small (typically < 100 blocks) so it runs in
    /// microseconds in practice. Mirrors `SmdaFunction.getBlockDominatorTree`
    /// upstream.
    ///
    /// Unreachable blocks (those with no predecessors that aren't the entry)
    /// are omitted from the returned map.
    #[must_use]
    pub fn dominator_tree(&self) -> HashMap<u64, u64> {
        use std::collections::BTreeSet;
        let entry = self.offset;
        let all_blocks: Vec<u64> = self.blocks.keys().copied().collect();
        if !self.blocks.contains_key(&entry) || all_blocks.len() <= 1 {
            return HashMap::new();
        }

        // Predecessor map derived from blockrefs (block -> successors).
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

        // dom(entry) = {entry}; dom(other) = all blocks.
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

        // Iterate to fixed point.
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

        // Extract immediate dominators: idom(B) is the dominator of B closest
        // to B — equivalently the one with the largest dominator set.
        let mut idom = HashMap::with_capacity(all_blocks.len().saturating_sub(1));
        for b in &all_blocks {
            if *b == entry {
                continue;
            }
            // Skip blocks the iteration never reached (no predecessors).
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
    /// Returns a map from block VA to nesting depth. Blocks not in any loop
    /// have depth 0; blocks in N nested loops have depth N. Mirrors
    /// `SmdaFunction.getNestingDepth` upstream.
    ///
    /// A back-edge is an edge `(s, h)` where `h` dominates `s`. The natural
    /// loop of a back-edge is `{h}` plus every block that can reach `s`
    /// without going through `h`. Per-block depth is the count of natural
    /// loops containing it.
    #[must_use]
    pub fn nesting_depth(&self) -> HashMap<u64, u32> {
        use std::collections::HashSet;
        let idom = self.dominator_tree();
        let entry = self.offset;
        let all_blocks: HashSet<u64> = self.blocks.keys().copied().collect();
        let mut depth: HashMap<u64, u32> = all_blocks.iter().map(|b| (*b, 0u32)).collect();

        // Does `dominator` dominate `block`?  Walk idom chain from `block`.
        let dominates = |dominator: u64, block: u64| -> bool {
            if dominator == block {
                return true;
            }
            let mut cur = block;
            // Bounded walk — idom forms a tree so this terminates at entry.
            for _ in 0..self.blocks.len() {
                let Some(&parent) = idom.get(&cur) else {
                    // Reached the entry (no idom recorded) or an unreachable
                    // block. dominator dominates iff dominator == entry.
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

        // Collect back-edges.
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

        // Predecessor map for reverse walks (loop discovery).
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

        // For each back-edge, compute the natural loop and bump every member.
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
    /// signature with displacements / branch targets zeroed. Stable across
    /// relocation, useful for malware-clustering pipelines. Mirrors
    /// `SmdaFunction.getPicHash` upstream.
    ///
    /// Per-instruction signature captures: iced `Code` (the precise
    /// encoding variant), operand kinds, register operands, memory
    /// base/index/scale. Memory displacements, RIP-relative offsets, and
    /// near-branch targets are deliberately omitted (that's the "PIC"
    /// part). Immediate values are kept — they often carry semantic
    /// fingerprints (constants, syscall numbers, string lengths).
    ///
    /// Block iteration order is sorted by VA so the hash is deterministic
    /// across HashMap iteration orders. Returns the first 8 bytes of the
    /// SHA-256 digest interpreted as a little-endian `u64`.
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
                buf.clear();
                Self::pic_signature_into(&ins.iced, &mut buf);
                hasher.update(&buf);
            }
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&out[..8]);
        u64::from_le_bytes(bytes)
    }

    /// (0.4.2 N16) Mnemonic-only hash — broadest clustering granularity.
    /// First 8 bytes of SHA-256 over the function's `Mnemonic` sequence.
    /// Collides on any two instructions with the same mnemonic regardless
    /// of operand kinds. Mirrors `SmdaFunction.getOpcHash` upstream.
    #[must_use]
    pub fn opcode_hash(&self) -> u64 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut block_offsets: Vec<u64> = self.blocks.keys().copied().collect();
        block_offsets.sort_unstable();
        for off in block_offsets {
            let block = &self.blocks[&off];
            for ins in block {
                let m = ins.iced.mnemonic() as u32;
                hasher.update(m.to_le_bytes());
            }
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&out[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Internal — write the PIC signature of one decoded instruction into
    /// `out`. See [`Function::pic_hash`] for the rationale.
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
                    // Displacement intentionally omitted (PIC).
                }
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    // Branch target intentionally omitted (PIC).
                }
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

/// Internal carrier type. The analyzer stashes one per decoded instruction
/// into `FunctionAnalysisState` / `DisassemblyResult`, then `Function::new`
/// transforms them into public `Instruction` values.
///
/// 0.4.0 dropped the per-instruction `bytes: Vec<u8>` field — the bytes
/// are looked up via [`DecodedInsn::bytes_in`] against the owning
/// `BinaryInfo` on demand. For a 100k-instruction binary this avoids
/// ~4 MB of per-instruction `Vec<u8>` allocation.
#[derive(Debug, Clone, Copy)]
pub struct DecodedInsn {
    pub offset: u64,
    pub length: u32,
    pub iced: iced_x86::Instruction,
}

impl DecodedInsn {
    /// Look up the raw instruction bytes in `binary_info`. Zero-copy.
    pub fn bytes_in<'b>(&self, binary_info: &'b BinaryInfo<'_>) -> Result<&'b [u8]> {
        binary_info.bytes_at(self.offset, self.length)
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
