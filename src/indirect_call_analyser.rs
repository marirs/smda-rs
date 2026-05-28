#![allow(clippy::too_many_arguments)]
use crate::{
    Disassembler, FunctionAnalysisState, Result,
    disassembler::{
        DecodedInsn,
        aarch64_ops::{
            MovWideKind, decode_add_sub_imm, decode_adrp, decode_ldr_str_uimm, decode_mov_reg,
            decode_mov_wide,
        },
        capstone_compat_formatter,
    },
    error::Error,
    label_providers::ApiEntry,
};
use iced_x86::{Formatter, Mnemonic};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::LazyLock,
};

static MOV_REG_REG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?P<reg1>[a-z]{3}), (?P<reg2>[a-z]{3})$").unwrap());
static MOV_REG_CONST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?P<reg>[a-z]{3}), (?P<val>0x[0-9a-f]{1,8})$").unwrap());
static MOV_REG_DWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<reg>[a-z]{3}), dword ptr \[(?P<addr>0x[0-9a-f]{1,8})\]$").unwrap()
});
static MOV_REG_QWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<reg>[a-z]{3}), qword ptr \[rip \+ (?P<addr>0x[0-9a-f]{1,8})\]$").unwrap()
});
static LEA_REG_DWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<reg>[a-z]{3}), dword ptr \[(?P<addr>0x[0-9a-f]{1,8})\]$").unwrap()
});

fn op_str_of(ins: &DecodedInsn) -> String {
    // x86 only — the regex-driven `process_block` below depends on the
    // capstone-compatible string layout. AArch64 indirect-call
    // resolution lives in `resolve_register_calls_aarch64` /
    // `process_block_aarch64`, which work on the structurally typed
    // disarm64 opcode stream instead and don't go through this helper.
    let Some(iced) = ins.as_iced() else {
        return String::new();
    };
    if iced.op_count() == 0 {
        return String::new();
    }
    let mut fmt = capstone_compat_formatter();
    let mut out = String::new();
    fmt.format_all_operands(iced, &mut out);
    out
}

#[derive(Debug)]
pub struct IndirectCallAnalyser {}

impl IndirectCallAnalyser {
    pub fn new() -> IndirectCallAnalyser {
        IndirectCallAnalyser {}
    }

    pub fn init(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn resolve_register_calls(
        &self,
        disassembler: &Disassembler,
        analysis_state: &mut FunctionAnalysisState,
        block_depth: i32,
    ) -> Result<(Vec<(u64, ApiEntry)>, Vec<(u64, u64)>)> {
        let mut res = vec![];
        let mut res2 = vec![];
        let calling_addr_vec = analysis_state.call_register_ins.clone();
        for calling_addr in &calling_addr_vec {
            let mut start_block = vec![];
            for ins in self.search_block(analysis_state, calling_addr)? {
                if ins.offset() <= *calling_addr {
                    start_block.push(ins);
                }
            }
            if !start_block.is_empty() {
                // The "register being called" string — operand of the
                // call <reg> instruction. Format from iced.
                let mut s = op_str_of(&start_block[start_block.len() - 1]);
                self.process_block(
                    analysis_state,
                    start_block,
                    &mut HashMap::new(),
                    &mut s,
                    &mut HashSet::new(),
                    block_depth,
                    *calling_addr,
                    disassembler,
                    &mut res,
                    &mut res2,
                )?;
            }
        }
        Ok((res, res2))
    }

    pub fn search_block(
        &self,
        analysis_state: &FunctionAnalysisState,
        address: &u64,
    ) -> Result<Vec<DecodedInsn>> {
        for block in &analysis_state.get_blocks()? {
            for i in block {
                if address == &i.offset() {
                    return Ok(block.clone());
                }
            }
        }
        Ok(vec![])
    }

    pub fn process_block(
        &self,
        analysis_state: &mut FunctionAnalysisState,
        block: Vec<DecodedInsn>,
        registers: &mut HashMap<String, u64>,
        register_name: &mut String,
        // Dedup processed blocks by their start address (lighter + simpler
        // than hashing the Vec<DecodedInsn> contents).
        processed: &mut HashSet<u64>,
        depth: i32,
        current_calling_addr: u64,
        disassembler: &Disassembler,
        api_e: &mut Vec<(u64, ApiEntry)>,
        cand_e: &mut Vec<(u64, u64)>,
    ) -> Result<bool> {
        if block.is_empty() {
            return Ok(false);
        }
        let block_start = block[0].offset();
        if processed.contains(&block_start) {
            return Ok(false);
        }
        processed.insert(block_start);

        let mut abs_value_found = false;
        for ins in block.iter().rev() {
            // x86-only path. AArch64 is handled by the sibling
            // `process_block_aarch64` below. Skip non-x86 carriers
            // so this regex pipeline doesn't waste cycles on them.
            let Some(mnem) = ins.mnemonic_enum_x86() else {
                continue;
            };
            let op_str = op_str_of(ins);
            if matches!(mnem, Mnemonic::Mov) {
                // mov <reg>, <reg>
                for match1 in MOV_REG_REG.captures_iter(&op_str) {
                    if &match1["reg1"].to_string() == register_name {
                        *register_name = match1["reg2"].to_string();
                    }
                }
                // mov <reg>, <const>
                for match2 in MOV_REG_CONST.captures_iter(&op_str) {
                    registers.insert(
                        match2["reg"].to_string(),
                        u64::from_str_radix(&match2["val"][2..], 16)?,
                    );
                    if &match2["reg"].to_string() == register_name {
                        abs_value_found = true;
                    }
                }
                // mov <reg>, dword ptr [<addr>]
                for match3 in MOV_REG_DWORD.captures_iter(&op_str) {
                    let addr = u64::from_str_radix(&match3["addr"][2..], 16)?;
                    let (dll, api) = disassembler.resolve_api(addr, addr)?;
                    if dll.is_some() || api.is_some() {
                        registers.insert(match3["reg"].to_string(), addr);
                        if &match3["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    } else if let Ok(dword) = self.get_dword(addr, disassembler) {
                        registers.insert(match3["reg"].to_string(), dword);
                        if &match3["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
                // mov <reg>, qword ptr [rip + <addr>]
                for match4 in MOV_REG_QWORD.captures_iter(&op_str) {
                    let rip = ins.offset() + ins.length() as u64;
                    if let Ok(dword) = self.get_dword(
                        rip + u64::from_str_radix(&match4["addr"][2..], 16)?,
                        disassembler,
                    ) {
                        registers.insert(match4["reg"].to_string(), rip + dword);
                        if &match4["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
            } else if matches!(mnem, Mnemonic::Lea) {
                // lea <reg>, dword ptr [<addr>]
                for match1 in LEA_REG_DWORD.captures_iter(&op_str) {
                    if let Ok(dword) =
                        self.get_dword(u64::from_str_radix(&match1["addr"][2..], 16)?, disassembler)
                    {
                        registers.insert(match1["reg"].to_string(), dword);
                        if &match1["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
            }

            if abs_value_found {
                analysis_state.set_leaf(false)?;
                if registers.contains_key(register_name) {
                    let candidate = registers[register_name];
                    let (dll, api) = disassembler.resolve_api(candidate, candidate)?;
                    if dll.is_some() || api.is_some() {
                        let mut api_entry = ApiEntry {
                            referencing_addr: HashSet::new(),
                            dll_name: dll,
                            api_name: api,
                        };
                        if disassembler.disassembly.apis.contains_key(&candidate) {
                            api_entry = disassembler.disassembly.apis[&candidate].clone();
                        }
                        if !api_entry.referencing_addr.contains(&current_calling_addr) {
                            api_entry.referencing_addr.insert(current_calling_addr);
                        }
                        api_e.push((candidate, api_entry));
                    } else if disassembler
                        .disassembly
                        .is_addr_within_memory_image(candidate)?
                    {
                        cand_e.push((candidate, current_calling_addr));
                    }
                }
                return Ok(true);
            }
        }

        // Process previous blocks.
        if depth >= 0 {
            // All instruction offsets that already appear in any processed
            // block — used to filter back-references.
            let mut all_processed_offsets: HashSet<u64> = HashSet::new();
            for blk in analysis_state.get_blocks()? {
                if !blk.is_empty() && processed.contains(&blk[0].offset()) {
                    for ins in &blk {
                        all_processed_offsets.insert(ins.offset());
                    }
                }
            }
            let mut refs_in = vec![];
            for (fr, to) in &analysis_state.code_refs {
                if processed.contains(to) && !all_processed_offsets.contains(fr) {
                    refs_in.push(fr);
                }
            }
            let mut bb = vec![];
            for i in refs_in {
                if let Ok(b) = self.search_block(analysis_state, i) {
                    bb.push(b);
                }
            }
            for b in bb {
                if self.process_block(
                    analysis_state,
                    b,
                    registers,
                    register_name,
                    processed,
                    depth - 1,
                    current_calling_addr,
                    disassembler,
                    api_e,
                    cand_e,
                )? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn get_dword(&self, addr: u64, disassembler: &Disassembler) -> Result<u64> {
        if !disassembler.disassembly.is_addr_within_memory_image(addr)? {
            return Err(Error::LogicError(file!(), line!()));
        }
        let extracted_dword: &[u8; 4] = &disassembler.disassembly.get_bytes(addr, 4)?.try_into()?;
        Ok(u32::from_le_bytes(*extracted_dword) as u64)
    }

    /// (0.6.1) AArch64 indirect-call resolver. Mirrors
    /// [`resolve_register_calls`] but operates on the structurally-typed
    /// disarm64 opcode stream instead of regex-matching iced operand
    /// strings. Recognises the dominant ARM64 indirect-call patterns:
    ///
    /// **GOT / PLT thunk** (Linux ELF, Apple Mach-O):
    /// ```text
    /// ADRP X16, got_page
    /// LDR  X16, [X16, #got_offset]   ; load slot → API target
    /// BLR  X16                        ; call resolved API
    /// ```
    /// The resolver computes `got_page + got_offset` and:
    ///   - if the slot itself is in `addr_to_api` / `apis` → API call,
    ///   - otherwise reads 8 bytes at the slot and looks up the
    ///     dereferenced value → fall-through API resolution path,
    ///   - otherwise if the slot is in-image but unresolved →
    ///     in-image function candidate.
    ///
    /// **MOVZ + BLR** (small absolute addresses, less common):
    /// ```text
    /// MOVZ X16, #imm                  ; absolute 16-bit address
    /// BLR  X16
    /// ```
    ///
    /// Multi-block back-walk: when the current block doesn't resolve
    /// the target register, the search walks into predecessor blocks
    /// (via `state.code_refs`) up to `block_depth` levels deep. This
    /// mirrors the x86 `process_block` recursion structure so the
    /// AArch64 path catches GOT thunks whose ADRP/LDR were emitted in
    /// an earlier basic block (common for inlined error-handling paths
    /// and compiler-generated cleanup epilogues).
    pub fn resolve_register_calls_aarch64(
        &self,
        disassembler: &Disassembler,
        analysis_state: &mut FunctionAnalysisState,
        block_depth: i32,
    ) -> Result<(Vec<(u64, ApiEntry)>, Vec<(u64, u64)>)> {
        let mut api_e = vec![];
        let mut cand_e = vec![];

        let calling_addrs = analysis_state.call_register_ins.clone();
        for calling_addr in &calling_addrs {
            let block = self.search_block(analysis_state, calling_addr)?;
            if block.is_empty() {
                continue;
            }

            // The BLR itself must be in the block; locate its index so we
            // back-walk preceding instructions only.
            let Some(blr_idx) = block.iter().position(|i| i.offset() == *calling_addr) else {
                continue;
            };

            // Pull out the BLR's target register (Rn at bits 9:5).
            let DecodedInsn::Aarch64(blr) = block[blr_idx] else {
                continue;
            };
            let mut target_reg = ((blr.opcode >> 5) & 0x1F) as u8;
            let mut ldr_state: Option<(u8, u64)> = None;
            let mut processed: HashSet<u64> = HashSet::new();

            let _ = self.process_block_aarch64(
                block,
                Some(blr_idx),
                &mut target_reg,
                &mut ldr_state,
                &mut processed,
                block_depth,
                *calling_addr,
                disassembler,
                analysis_state,
                &mut api_e,
                &mut cand_e,
            )?;
        }

        Ok((api_e, cand_e))
    }

    /// (0.6.1) Per-block back-walk for the AArch64 indirect-call
    /// resolver. Recursive — when a block doesn't yield a resolved
    /// target it descends into the block's predecessors (limited by
    /// `depth`). `target_reg` and `ldr_state` are passed by `&mut`
    /// across the recursion so a partial decode (e.g. seeing the LDR
    /// but not yet the ADRP) in the current block correctly hands off
    /// to the predecessor.
    ///
    /// `end_idx` bounds the back-walk in the originating block: we
    /// only consider instructions strictly before the BLR. Predecessor
    /// calls pass `None` to walk the entire block.
    fn process_block_aarch64(
        &self,
        block: Vec<DecodedInsn>,
        end_idx: Option<usize>,
        target_reg: &mut u8,
        ldr_state: &mut Option<(u8, u64)>,
        processed: &mut HashSet<u64>,
        depth: i32,
        calling_addr: u64,
        disassembler: &Disassembler,
        analysis_state: &mut FunctionAnalysisState,
        api_e: &mut Vec<(u64, ApiEntry)>,
        cand_e: &mut Vec<(u64, u64)>,
    ) -> Result<bool> {
        if block.is_empty() {
            return Ok(false);
        }
        let block_start = block[0].offset();
        if processed.contains(&block_start) {
            return Ok(false);
        }
        processed.insert(block_start);

        let end = end_idx.unwrap_or(block.len());
        let mut resolved_addr: Option<u64> = None;

        for ins in block[..end].iter().rev() {
            let DecodedInsn::Aarch64(a) = ins else {
                continue;
            };
            let w = a.opcode;

            // MOV xT, xS (alias of ORR xT, XZR, xS) — register rename.
            // Update target_reg and keep walking — the *real* producer
            // is whatever wrote xS.
            if let Some((rd, rm)) = decode_mov_reg(w)
                && rd == *target_reg
            {
                *target_reg = rm;
                continue;
            }

            // MOVZ X<target>, #imm — direct absolute address.
            if let Some((rd, val, kind)) = decode_mov_wide(w)
                && rd == *target_reg
                && kind == MovWideKind::Movz
            {
                resolved_addr = Some(val);
                break;
            }

            // Stage 1: LDR target_reg, [base, #off] — the GOT load.
            if ldr_state.is_none()
                && let Some(op) = decode_ldr_str_uimm(w)
                && op.rt == *target_reg
                && !op.is_store
                && op.size_bytes == 8
            {
                *ldr_state = Some((op.rn, op.offset));
                continue;
            }

            // Stage 2a: ADRP <base>, page — completes ADRP+LDR GOT.
            if let Some((base_reg, off)) = *ldr_state
                && let Some((rd, page_va)) = decode_adrp(w, a.offset)
                && rd == base_reg
            {
                let slot_va = page_va.wrapping_add(off);
                resolved_addr = Some(slot_va);
                break;
            }

            // Stage 2b: ADD base, base, #imm followed earlier by ADRP
            // — the ADRP+ADD+LDR pattern (macOS / PIE thunks). When we
            // see the ADD here, it means the table base was paged
            // through ADRP and then offset by a PAGEOFF — fold the
            // PAGEOFF into ldr_state.offset and keep looking for the
            // ADRP that produced ADD's source register.
            if let Some((base_reg, _)) = *ldr_state
                && let Some((rd, rn, imm, is_sub)) = decode_add_sub_imm(w)
                && !is_sub
                && rd == base_reg
                && rn == base_reg
                && let Some((_, off)) = *ldr_state
            {
                *ldr_state = Some((base_reg, off.wrapping_add(imm)));
                continue;
            }
        }

        if let Some(addr) = resolved_addr {
            // (0.6.1, M3 defensive) Stage-2 ADRP+ADD+LDR accumulates
            // offsets via wrapping_add — adversarial binaries could
            // craft ADD immediates that wrap the slot address out of
            // the mapped image. Bail before any downstream resolution
            // / dereference so a corrupted slot can't leak through
            // resolve_api or feed a phantom candidate.
            if !disassembler.disassembly.is_addr_within_memory_image(addr)? {
                return Ok(false);
            }
            analysis_state.set_leaf(false)?;

            // 1) Slot itself is a known API entry?
            let (dll, api) = disassembler.resolve_api(addr, addr)?;
            if dll.is_some() || api.is_some() {
                let mut entry = ApiEntry {
                    referencing_addr: HashSet::new(),
                    dll_name: dll,
                    api_name: api,
                };
                if let Some(existing) = disassembler.disassembly.apis.get(&addr) {
                    entry = existing.clone();
                }
                entry.referencing_addr.insert(calling_addr);
                api_e.push((addr, entry));
                return Ok(true);
            }

            // 2) Dereference the slot — GOT thunk slots hold the
            //    real API target as a 64-bit absolute.
            if disassembler.disassembly.is_addr_within_memory_image(addr)?
                && let Ok(bytes) = disassembler.disassembly.get_bytes(addr, 8)
                && let Ok(packed) = <&[u8; 8]>::try_from(bytes)
            {
                let target = u64::from_le_bytes(*packed);
                let (dll, api) = disassembler.resolve_api(target, target)?;
                if dll.is_some() || api.is_some() {
                    let mut entry = ApiEntry {
                        referencing_addr: HashSet::new(),
                        dll_name: dll,
                        api_name: api,
                    };
                    if let Some(existing) = disassembler.disassembly.apis.get(&target) {
                        entry = existing.clone();
                    }
                    entry.referencing_addr.insert(calling_addr);
                    api_e.push((target, entry));
                    return Ok(true);
                }
                if disassembler
                    .disassembly
                    .is_addr_within_memory_image(target)?
                {
                    cand_e.push((target, calling_addr));
                    return Ok(true);
                }
            }

            // 3) Fallback: in-image slot, unresolved — emit as candidate.
            if disassembler.disassembly.is_addr_within_memory_image(addr)? {
                cand_e.push((addr, calling_addr));
                return Ok(true);
            }
            return Ok(false);
        }

        // Unresolved in this block — recurse into predecessors.
        if depth >= 0 {
            // Find predecessor blocks via code_refs (from, to) where
            // `to` is inside a processed block and `from` is outside
            // every processed block. Same filtering shape as the x86
            // process_block.
            let mut all_processed_offsets: HashSet<u64> = HashSet::new();
            for blk in analysis_state.get_blocks()? {
                if !blk.is_empty() && processed.contains(&blk[0].offset()) {
                    for ins in &blk {
                        all_processed_offsets.insert(ins.offset());
                    }
                }
            }
            let mut pred_starts = vec![];
            for (fr, to) in &analysis_state.code_refs {
                if processed.contains(to) && !all_processed_offsets.contains(fr) {
                    pred_starts.push(*fr);
                }
            }
            let mut pred_blocks = vec![];
            for fr in pred_starts {
                if let Ok(b) = self.search_block(analysis_state, &fr) {
                    pred_blocks.push(b);
                }
            }
            for b in pred_blocks {
                if self.process_block_aarch64(
                    b,
                    None,
                    target_reg,
                    ldr_state,
                    processed,
                    depth - 1,
                    calling_addr,
                    disassembler,
                    analysis_state,
                    api_e,
                    cand_e,
                )? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
