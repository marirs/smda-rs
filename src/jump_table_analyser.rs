#![allow(clippy::invalid_regex)]
// The jump-table back-walk helpers naturally carry a handful of
// related arguments (BR target reg, BR address, the instruction
// stream, disassembler handle, mutable state, and per-variant
// configuration knobs). Bundling them into a struct would obscure
// the call sites without simplifying anything, so we accept the
// arity here.
#![allow(clippy::too_many_arguments)]
use crate::{
    Disassembler, DisassemblyResult, FunctionAnalysisState, Result,
    disassembler::{
        DecodedInsn,
        aarch64_ops::{
            decode_add_ext_reg, decode_add_sub_imm, decode_adr, decode_adrp, decode_ldr_reg,
            decode_ldr_str_uimm, decode_ldrsw_reg,
        },
        capstone_compat_formatter,
    },
    error::Error,
};
use iced_x86::{Formatter, Mnemonic};
use regex::{Regex, bytes::Regex as BytesRegex};
use std::convert::TryInto;
use std::sync::LazyLock;

static BYTES: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)(\x48|\x4c)\x8d.{5}(.\x63|\x77|.\x89..\x63)").unwrap());
static JMP_TBL_SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)(?P<one>[a-z0-9]{2,4}), (?P<two>([0-9])|(0x[0-9a-f]+))").unwrap()
});
static DIRECT_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)[a-z0-9]{2,3}, dword ptr \[[^ ]+ \+ 0x[0-9a-f]+\]").unwrap()
});
static X86_HANDLER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[a-z0-9]{2,3}, \[rip (\+|\-) 0x[0-9a-f]+\]").unwrap());
static X86_BONUS_OFFSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[a-z0-9]{2,3},.*0x[0-9a-f]+\]").unwrap());

/// Format the operands string for a DecodedInsn using the capstone-compatible
/// formatter — used here so the legacy regex-based heuristics keep matching.
fn op_str_of(ins: &DecodedInsn) -> String {
    // x86 only — the jump-table analyser is regex-driven; on AArch64
    // we return empty so the regex pipeline short-circuits. Full
    // AArch64 jump-table analysis lands in 0.6.1.
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
pub struct JumpTableAnalyser {
    table_offsets: Vec<u64>,
}

impl JumpTableAnalyser {
    pub fn new() -> JumpTableAnalyser {
        JumpTableAnalyser {
            table_offsets: vec![],
        }
    }

    pub fn init(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        self.table_offsets = self.find_jump_tables(disassembly)?;
        Ok(())
    }

    pub fn find_jump_tables(&mut self, disassembly: &DisassemblyResult) -> Result<Vec<u64>> {
        let mut jumptables = vec![];
        for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
            for match_offset in BYTES.find_iter(section_bytes) {
                let ins_offset = section_va + match_offset.start() as u64;
                let Ok(packed) = disassembly.binary_info.bytes_at(ins_offset + 3, 4) else {
                    continue;
                };
                let packed_dword: [u8; 4] = packed.try_into()?;
                let rel_table_offset = u32::from_le_bytes(packed_dword) as u64;
                let Some(table_offset) = ins_offset
                    .checked_add(rel_table_offset)
                    .and_then(|t| t.checked_add(7))
                else {
                    continue;
                };
                if disassembly.is_addr_within_memory_image(table_offset)? {
                    jumptables.push(table_offset);
                }
            }
        }
        Ok(jumptables)
    }

    pub fn get_jump_targets(
        &self,
        jump_instruction: &DecodedInsn,
        jump_instruction_op_str: &str,
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<u64>> {
        // x86-only heuristic — no-op on AArch64 in 0.6.0.
        if jump_instruction.as_iced().is_none() {
            return Ok(vec![]);
        }
        let jump_instruction_address = jump_instruction.offset();
        let mut table_offsets = vec![];
        let backtracked = state.backtrack_instructions(jump_instruction_address, 50)?;
        let backtracked_sequence = ""; // "-".join([mnemonic ...]) — leave as-is for parity
        let mut jumptable_size = self.find_jump_table_size(&backtracked)?;
        if jump_instruction_op_str.starts_with("dword ptr [")
            || jump_instruction_op_str.starts_with("qword ptr [")
        {
            let off_jumptable = disassembler.get_referenced_addr(jump_instruction_op_str)?;
            let _table_offsets = self.resolve_explicit_table(
                jump_instruction_address,
                &disassembler.disassembly,
                state,
                off_jumptable,
                Some(jumptable_size),
            )?;
        } else if backtracked_sequence.starts_with("mov") {
            let off_jumptable =
                self.direct_handler(jump_instruction_op_str, disassembler, state, &backtracked)?;
            table_offsets = self.extract_direct_table_offsets(
                Some(jumptable_size),
                off_jumptable,
                disassembler,
            )?;
        } else if backtracked_sequence.starts_with("add-movsxd") {
            jumptable_size = self.find_jump_table_size(&backtracked)?;
            let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
            // Original: `backtracked[..backtracked.len() - 1][0]` — i.e. the
            // first element of the slice excluding the last. Equivalent to
            // `backtracked[0]` whenever `backtracked.len() >= 2`.
            if backtracked.len() >= 2 && op_str_of(&backtracked[0]).contains("rsi") {
                let alternative_base =
                    self.x64_handler(disassembler, state, &backtracked, Some("rsi".to_string()))?;
                table_offsets = self.extract_relative_table_offsets(
                    Some(jumptable_size),
                    off_jumptable,
                    Some(alternative_base),
                    0,
                    disassembler,
                )?;
            }
        } else if backtracked_sequence.starts_with("lea")
            || backtracked_sequence.starts_with("add-add")
            || backtracked_sequence.starts_with("add-shr")
        {
            jumptable_size = self.find_jump_table_size(&backtracked)?;
            let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
            table_offsets = self.extract_relative_table_offsets(
                Some(jumptable_size),
                off_jumptable,
                None,
                0,
                disassembler,
            )?;
        } else if backtracked_sequence.starts_with("add-mov") {
            jumptable_size = self.find_jump_table_size(&backtracked)?;
            let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
            let bonus = self.get_x64_bonus_offset(disassembler, &backtracked)?;
            table_offsets = self.extract_relative_table_offsets(
                Some(jumptable_size),
                off_jumptable,
                None,
                bonus,
                disassembler,
            )?;
        }
        Ok(table_offsets)
    }

    pub fn find_jump_table_size(&self, backtracked: &[DecodedInsn]) -> Result<usize> {
        let mut jumptable_size = 0;
        if backtracked.is_empty() {
            return Ok(jumptable_size);
        }
        for instr in &backtracked[..backtracked.len() - 1] {
            let Some(mnem) = instr.mnemonic_enum_x86() else {
                continue;
            };
            // skip ret-family
            if matches!(
                mnem,
                Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
            ) {
                break;
            }
            if matches!(mnem, Mnemonic::Cmp) {
                let op_str = op_str_of(instr);
                if JMP_TBL_SIZE.is_match(&op_str) {
                    let c = JMP_TBL_SIZE
                        .captures(&op_str)
                        .ok_or(Error::LogicError(file!(), line!()))?;
                    jumptable_size = usize::from_str_radix(&c["two"], 16)? + 1;
                    break;
                }
            }
        }
        Ok(jumptable_size)
    }

    pub fn resolve_explicit_table(
        &self,
        jump_instruction_address: u64,
        disassembly: &DisassemblyResult,
        state: &mut FunctionAnalysisState,
        jumptable_address: u64,
        jumptable_size: Option<usize>,
    ) -> Result<Vec<u64>> {
        // Hard cap the jumptable size — `jumptable_size` is parsed from a
        // user-controlled operand and could be near `usize::MAX`. The cap
        // bounds the loop independently of `get_bytes` Err'ing on OOB.
        const MAX_JUMPTABLE_ENTRIES: usize = 4096;
        let jumptable_size = jumptable_size.unwrap_or(0xFF).min(MAX_JUMPTABLE_ENTRIES);
        let mut jumptable_addresses = vec![];
        let bitness = disassembly.binary_info.bitness;
        let entry_size: u64 = if bitness == 32 { 4 } else { 8 };
        let mut table_entry = 0;
        if disassembly.is_addr_within_memory_image(jumptable_address)? {
            for i in 0..jumptable_size {
                let Some(rel) = (i as u64).checked_mul(entry_size) else {
                    break;
                };
                let Some(entry_addr) = jumptable_address.checked_add(rel) else {
                    break;
                };
                if bitness == 32 {
                    let packed_dword: &[u8; 4] =
                        disassembly.get_bytes(entry_addr, entry_size)?.try_into()?;
                    table_entry = u32::from_le_bytes(*packed_dword) as u64;
                } else if bitness == 64 {
                    let packed_dword: &[u8; 8] =
                        disassembly.get_bytes(entry_addr, entry_size)?.try_into()?;
                    table_entry = u64::from_le_bytes(*packed_dword);
                }
                if !disassembly.is_addr_within_memory_image(table_entry)? {
                    break;
                }
                state.add_data_ref(jump_instruction_address, entry_addr, entry_size)?;
                jumptable_addresses.push(table_entry);
            }
        }
        Ok(jumptable_addresses)
    }

    pub fn direct_handler(
        &self,
        jump_instruction_op_str: &str,
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        backtracked: &[DecodedInsn],
    ) -> Result<u64> {
        let register = jump_instruction_op_str.to_lowercase();
        let mut off_jumptable = None;
        for instr in backtracked.iter().rev() {
            let Some(mnem) = instr.mnemonic_enum_x86() else {
                continue;
            };
            let op_str = op_str_of(instr);
            if matches!(mnem, Mnemonic::Mov) {
                if DIRECT_HANDLER.is_match(&op_str) {
                    let data_ref_instruction_addr = instr.offset();
                    off_jumptable = Some(disassembler.get_referenced_addr(&op_str)?);
                    state.add_data_ref(
                        data_ref_instruction_addr,
                        *off_jumptable.as_ref().unwrap(),
                        4,
                    )?;
                    break;
                }
            } else if matches!(mnem, Mnemonic::Add) && op_str.starts_with(&register) {
                let data_ref_instruction_addr = instr.offset();
                off_jumptable = Some(disassembler.get_referenced_addr(&op_str)?);
                state.add_data_ref(
                    data_ref_instruction_addr,
                    *off_jumptable.as_ref().unwrap(),
                    4,
                )?;
                break;
            }
        }
        match off_jumptable {
            Some(o) => Ok(o),
            None => Err(Error::LogicError(file!(), line!())),
        }
    }

    pub fn extract_direct_table_offsets(
        &self,
        jumptable_size: Option<usize>,
        off_jumptable: u64,
        disassembler: &Disassembler,
    ) -> Result<Vec<u64>> {
        const MAX_JUMPTABLE_ENTRIES: usize = 4096;
        let mut jump_targets = vec![];
        if let Some(jumptable_size) = jumptable_size
            && off_jumptable != 0
            && disassembler
                .disassembly
                .is_addr_within_memory_image(off_jumptable)?
        {
            let jumptable_size = jumptable_size.min(MAX_JUMPTABLE_ENTRIES);
            for index in 0..jumptable_size {
                let Some(rel) = (index as u64).checked_mul(4) else {
                    break;
                };
                let Some(entry_addr) = off_jumptable.checked_add(rel) else {
                    break;
                };
                let packed_dword: &[u8; 4] = disassembler
                    .disassembly
                    .get_bytes(entry_addr, 4)?
                    .try_into()?;
                let entry = u32::from_le_bytes(*packed_dword) as u64;
                jump_targets.push(entry);
            }
        }
        jump_targets.sort_unstable();
        Ok(jump_targets)
    }

    pub fn x64_handler(
        &self,
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        backtracked: &[DecodedInsn],
        target_register: Option<String>,
    ) -> Result<u64> {
        let mut off_jumptable = None;
        for instr in backtracked.iter().rev() {
            let Some(mnem) = instr.mnemonic_enum_x86() else {
                continue;
            };
            let op_str = op_str_of(instr);
            if matches!(mnem, Mnemonic::Lea) && X86_HANDLER.is_match(&op_str) {
                if let Some(target_register_) = &target_register
                    && !op_str.contains(target_register_)
                {
                    continue;
                }
                let data_ref_instruction_addr = instr.offset();
                let mut offset = disassembler.get_referenced_addr(&op_str)? as i64;
                let rip_sign = if op_str.contains('+') { "+" } else { "-" };
                if rip_sign == "-" {
                    offset *= -1;
                }
                off_jumptable = Some(instr.offset() as i64 + instr.length() as i64 + offset);
                state.add_data_ref(
                    data_ref_instruction_addr,
                    *off_jumptable.as_ref().unwrap() as u64,
                    4,
                )?;
                break;
            }
        }
        match off_jumptable {
            Some(s) => Ok(s as u64),
            None => Err(Error::LogicError(file!(), line!())),
        }
    }

    pub fn extract_relative_table_offsets(
        &self,
        jumptable_size: Option<usize>,
        off_jumptable: u64,
        alternative_base: Option<u64>,
        bonus_offset: u64,
        disassembler: &Disassembler,
    ) -> Result<Vec<u64>> {
        const MAX_JUMPTABLE_ENTRIES: usize = 4096;
        let jumptable_size = jumptable_size.unwrap_or(0xFF).min(MAX_JUMPTABLE_ENTRIES);
        let mut jump_targets = vec![];
        let jump_base = match alternative_base {
            Some(s) => s,
            None => off_jumptable,
        };
        let base_addr = disassembler.disassembly.binary_info.base_addr;
        if jumptable_size != 0
            && off_jumptable != 0
            && disassembler
                .disassembly
                .is_addr_within_memory_image(off_jumptable)?
        {
            // Pre-compute the rebased start outside the loop (it doesn't
            // change between iterations).
            let Some(rebased_start) = off_jumptable
                .checked_add(bonus_offset)
                .and_then(|s| s.checked_sub(base_addr))
            else {
                return Ok(jump_targets);
            };
            for index in 0..jumptable_size {
                let Some(rel) = (index as u64).checked_mul(4) else {
                    break;
                };
                let Some(entry_addr) = rebased_start.checked_add(rel) else {
                    break;
                };
                let packed_dword: &[u8; 4] = disassembler
                    .disassembly
                    .get_bytes(entry_addr, 4)?
                    .try_into()?;
                let entry = u32::from_le_bytes(*packed_dword) as u64;
                let Some(table_offset_check) = off_jumptable.checked_add(rel) else {
                    break;
                };
                if index != 0 && self.table_offsets.contains(&table_offset_check) {
                    break;
                }
                let Some(target_raw) = jump_base.checked_add(entry) else {
                    break;
                };
                if !disassembler
                    .disassembly
                    .is_addr_within_memory_image(target_raw)?
                {
                    break;
                }
                if entry != 0 {
                    let target = target_raw & disassembler.get_bitmask();
                    jump_targets.push(target);
                } else if alternative_base.is_none() {
                    break;
                }
            }
        }
        jump_targets.sort_unstable();
        Ok(jump_targets)
    }

    pub fn get_x64_bonus_offset(
        &self,
        disassembler: &Disassembler,
        backtracked: &[DecodedInsn],
    ) -> Result<u64> {
        let mut bonus_offset = 0;
        for (i, instr) in backtracked[..backtracked.len().saturating_sub(1)]
            .iter()
            .enumerate()
        {
            let op_str = op_str_of(instr);
            if i < 3
                && matches!(instr.mnemonic_enum_x86(), Some(Mnemonic::Mov))
                && X86_BONUS_OFFSET.is_match(&op_str)
            {
                bonus_offset = disassembler.get_referenced_addr(&op_str)?;
                break;
            }
        }
        Ok(bonus_offset)
    }

    /// (0.6.1) AArch64 jump-table target resolver. Best-effort —
    /// recognises the two canonical Clang / GCC switch-statement
    /// lowerings on AArch64 and returns the resolved switch arms;
    /// returns an empty `Vec` for anything else (including unknown
    /// indirect-branch patterns) so the caller treats the `BR`
    /// as a tail-call edge.
    ///
    /// **Variant A — table of i32 offsets** (the common Clang case):
    /// ```text
    /// ADRP   xN, table@PAGE
    /// ADD    xN, xN, table@PAGEOFF
    /// LDRSW  xM, [xN, xIdx, LSL #2]   ; each entry = (target - table_base) as i32
    /// ADD    xT, xN, xM                ; resolve target = table_base + offset
    /// BR     xT
    /// ```
    ///
    /// **Variant B — table of u64 absolute targets** (less common —
    /// GCC, large switches with widely-spaced arms):
    /// ```text
    /// ADRP   xN, table@PAGE
    /// ADD    xN, xN, table@PAGEOFF
    /// LDR    xT, [xN, xIdx, LSL #3]   ; each entry = absolute target VA (u64)
    /// BR     xT
    /// ```
    ///
    /// Table size is auto-bounded: we read entries until one falls
    /// outside the mapped image, or we hit a defensive hard cap
    /// (256 entries) — whichever comes first. The walker doesn't
    /// require the upstream `CMP xIdx, #N` to be visible.
    pub fn get_jump_targets_aarch64(
        &self,
        jump_instruction: &DecodedInsn,
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<u64>> {
        const MAX_JUMPTABLE_ENTRIES: usize = 256;

        // Pull the AArch64-specific decode out — bail cleanly on x86.
        let DecodedInsn::Aarch64(br) = jump_instruction else {
            return Ok(vec![]);
        };
        // The BR's target register — anchor for the back-walk.
        let Some(br_rt) = crate::disassembler::aarch64_ops::decode_branch_reg(br.opcode) else {
            return Ok(vec![]);
        };

        // Back-walk up to 12 instructions — covers both variants
        // including a few register-shuffles in between.
        let br_addr = jump_instruction.offset();
        let back = state.backtrack_instructions(br_addr, 12)?;

        // The back array is most-recent-last (matches the x86 path's
        // convention from `backtrack_instructions`). Convert to a Vec
        // of (raw_word, addr) pairs so we can pattern-match cleanly.
        let stream: Vec<(u32, u64)> = back
            .iter()
            .filter_map(|d| match d {
                DecodedInsn::Aarch64(a) => Some((a.opcode, a.offset)),
                DecodedInsn::X86(_) => None,
            })
            .collect();
        if stream.is_empty() {
            return Ok(vec![]);
        }

        // --- pattern dispatch ----------------------------------------
        //
        // We try variant A first (delta table) because it's by far the
        // more common emit on Clang / GCC. If A's pattern doesn't
        // match exactly, fall through to variant B.

        // Variant A: BR xT preceded by ADD xT, xBase, xDelta where
        // xDelta was loaded by LDRSW xDelta, [xBase, xIdx, LSL #2].
        // The ADD's xBase must match the LDRSW's Rn — i.e. the same
        // table-base register feeds both. Then back-walk for the ADRP
        // + ADD that materialised xBase.
        if let Some(targets) = self.try_variant_a_offsets(
            br_rt,
            br_addr,
            &stream,
            disassembler,
            state,
            MAX_JUMPTABLE_ENTRIES,
        )? {
            return Ok(targets);
        }

        // Variant B: BR xT where xT was loaded by LDR xT, [xBase, xIdx, LSL #3].
        if let Some(targets) = self.try_variant_b_absolutes(
            br_rt,
            br_addr,
            &stream,
            disassembler,
            state,
            MAX_JUMPTABLE_ENTRIES,
        )? {
            return Ok(targets);
        }

        // Variant C (JT8): LDRB + ADD-extended-SXTB+LSL2 + BR.
        if let Some(targets) = self.try_variant_c_byte_offsets(
            br_rt,
            br_addr,
            &stream,
            disassembler,
            state,
            MAX_JUMPTABLE_ENTRIES,
        )? {
            return Ok(targets);
        }

        // Variant D (JT16): LDRH + ADD-extended-SXTH+LSL2 + BR.
        if let Some(targets) = self.try_variant_d_halfword_offsets(
            br_rt,
            br_addr,
            &stream,
            disassembler,
            state,
            MAX_JUMPTABLE_ENTRIES,
        )? {
            return Ok(targets);
        }

        Ok(vec![])
    }

    /// Variant A — table of i32 deltas added to the table base.
    fn try_variant_a_offsets(
        &self,
        br_rt: u8,
        br_addr: u64,
        stream: &[(u32, u64)],
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        max_entries: usize,
    ) -> Result<Option<Vec<u64>>> {
        // 1) Find the ADD xT, xBase, xDelta immediately before BR
        //    where Rd == br_rt. Must produce (Rd, Rn, Rm) — but our
        //    `decode_add_sub_imm` only handles ADD-immediate, not
        //    ADD-extended-register. So we re-decode the register
        //    form here inline.
        //
        //    ADD (shifted register), 64-bit:
        //      1 0001011 shift:2 0 Rm:5 imm6:6 Rn:5 Rd:5
        //      Mask 0xFF20_0000, value 0x8B00_0000.
        let add_xt = stream
            .iter()
            .rev()
            .find(|(w, _)| (w & 0xFF20_0000) == 0x8B00_0000 && (*w & 0x1F) as u8 == br_rt);
        let Some(&(add_w, _add_addr)) = add_xt else {
            return Ok(None);
        };
        let add_rn = ((add_w >> 5) & 0x1F) as u8; // base reg
        let add_rm = ((add_w >> 16) & 0x1F) as u8; // delta reg

        // 2) Back-walk for LDRSW xDelta, [xBase, xIdx, LSL #2] where
        //    Rt == add_rm and Rn == add_rn.
        let ldrsw = stream
            .iter()
            .rev()
            .find_map(|(w, _)| decode_ldrsw_reg(*w).filter(|o| o.rt == add_rm && o.rn == add_rn));
        let Some(ldrsw) = ldrsw else {
            return Ok(None);
        };

        // 3) Find the ADRP that materialised xBase (== ldrsw.rn).
        //    May be followed by an ADD-immediate with the page offset.
        let Some(table_base) = self.resolve_aarch64_table_base(stream, ldrsw.rn, disassembler)
        else {
            return Ok(None);
        };

        // 4) Read the table — each entry is a sign-extended i32 added
        //    to the table base.
        let mut targets = Vec::with_capacity(max_entries);
        for i in 0..max_entries {
            let Some(rel) = (i as u64).checked_mul(4) else {
                break;
            };
            let Some(entry_addr) = table_base.checked_add(rel) else {
                break;
            };
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(entry_addr)?
            {
                break;
            }
            let Ok(bytes) = disassembler.disassembly.get_bytes(entry_addr, 4) else {
                break;
            };
            let packed: [u8; 4] = match bytes.try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let delta = i32::from_le_bytes(packed) as i64;
            // (0.6.1) Bit-pattern reinterpretation: we want
            // `table_base + signed(delta)` modulo 2^64. The `u64 -> i64`
            // cast is a no-op on the bits (Rust documented behaviour);
            // wrapping_add then `as u64` round-trips back to an
            // unsigned VA. Equivalent to `table_base.wrapping_add(delta as u64)`
            // when `delta >= 0`, and correctly handles negative deltas
            // (which can validly point earlier in the section).
            let target = table_base.wrapping_add(delta as u64);
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(target)?
            {
                break;
            }
            state.add_data_ref(br_addr, entry_addr, 4)?;
            targets.push(target);
        }
        if targets.is_empty() {
            return Ok(None);
        }
        targets.sort_unstable();
        targets.dedup();
        Ok(Some(targets))
    }

    /// Variant B — table of u64 absolute targets.
    fn try_variant_b_absolutes(
        &self,
        br_rt: u8,
        br_addr: u64,
        stream: &[(u32, u64)],
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        max_entries: usize,
    ) -> Result<Option<Vec<u64>>> {
        // Find LDR xT, [xBase, xIdx, LSL #3] where Rt == br_rt and
        // size == 8 bytes.
        let ldr = stream.iter().rev().find_map(|(w, _)| {
            decode_ldr_reg(*w).filter(|o| o.rt == br_rt && o.size_bytes == 8 && o.shift == 3)
        });
        let Some(ldr) = ldr else {
            return Ok(None);
        };

        let Some(table_base) = self.resolve_aarch64_table_base(stream, ldr.rn, disassembler) else {
            return Ok(None);
        };

        let mut targets = Vec::with_capacity(max_entries);
        for i in 0..max_entries {
            let Some(rel) = (i as u64).checked_mul(8) else {
                break;
            };
            let Some(entry_addr) = table_base.checked_add(rel) else {
                break;
            };
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(entry_addr)?
            {
                break;
            }
            let Ok(bytes) = disassembler.disassembly.get_bytes(entry_addr, 8) else {
                break;
            };
            let packed: [u8; 8] = match bytes.try_into() {
                Ok(b) => b,
                Err(_) => break,
            };
            let target = u64::from_le_bytes(packed);
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(target)?
            {
                break;
            }
            state.add_data_ref(br_addr, entry_addr, 8)?;
            targets.push(target);
        }
        if targets.is_empty() {
            return Ok(None);
        }
        targets.sort_unstable();
        targets.dedup();
        Ok(Some(targets))
    }

    /// Variant C — JT8 byte-offset table (GCC small-bias switches):
    /// ```text
    /// ADRP/ADD or ADR materialises the anchor in xAnchor
    /// LDRB Wm, [xTableBase, xIdx]
    /// ADD  xT, xAnchor, Wm, SXTB #2
    /// BR   xT
    /// ```
    /// Each table entry is an `i8` (target - anchor) / 4. Resolved
    /// target VA = `anchor + (sign_extend(i8) << 2)`.
    fn try_variant_c_byte_offsets(
        &self,
        br_rt: u8,
        br_addr: u64,
        stream: &[(u32, u64)],
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        max_entries: usize,
    ) -> Result<Option<Vec<u64>>> {
        self.try_variant_byte_or_halfword(
            br_rt,
            br_addr,
            stream,
            disassembler,
            state,
            max_entries,
            /*entry_bytes=*/ 1,
            /*expected_option=*/ 0b100, // SXTB
        )
    }

    /// Variant D — JT16 halfword-offset table:
    /// ```text
    /// LDRH Wm, [xTableBase, xIdx, LSL #1]
    /// ADD  xT, xAnchor, Wm, SXTH #2
    /// BR   xT
    /// ```
    /// Each table entry is an `i16` (target - anchor) / 4.
    fn try_variant_d_halfword_offsets(
        &self,
        br_rt: u8,
        br_addr: u64,
        stream: &[(u32, u64)],
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        max_entries: usize,
    ) -> Result<Option<Vec<u64>>> {
        self.try_variant_byte_or_halfword(
            br_rt,
            br_addr,
            stream,
            disassembler,
            state,
            max_entries,
            /*entry_bytes=*/ 2,
            /*expected_option=*/ 0b101, // SXTH
        )
    }

    /// Shared body for JT8 and JT16 — pattern-matches an extended-ADD
    /// (with the expected SXTB/SXTH option + shift=2) preceded by an
    /// LDRB/LDRH from the table base, with an anchor materialised via
    /// either ADR or the table-base resolver. Reads the table as
    /// sign-extended bytes/halfwords scaled by 4.
    fn try_variant_byte_or_halfword(
        &self,
        br_rt: u8,
        br_addr: u64,
        stream: &[(u32, u64)],
        disassembler: &Disassembler,
        state: &mut FunctionAnalysisState,
        max_entries: usize,
        entry_bytes: u8,
        expected_option: u8,
    ) -> Result<Option<Vec<u64>>> {
        // 1) ADD-extended Rd = br_rt, option == SXTB/SXTH, shift == 2.
        let add_ext = stream.iter().rev().find_map(|(w, addr)| {
            decode_add_ext_reg(*w)
                .filter(|op| {
                    !op.is_sub && op.rd == br_rt && op.option == expected_option && op.shift == 2
                })
                .map(|op| (op, *addr))
        });
        let Some((add_op, _add_addr)) = add_ext else {
            return Ok(None);
        };
        let anchor_reg = add_op.rn;
        let delta_reg = add_op.rm;

        // 2) LDRB / LDRH into delta_reg from [table_base, idx, …].
        let ldr = stream.iter().rev().find_map(|(w, _)| {
            decode_ldr_reg(*w).filter(|op| op.rt == delta_reg && op.size_bytes == entry_bytes)
        });
        let Some(ldr) = ldr else {
            return Ok(None);
        };

        // 3) Resolve table base via the existing helper (ADRP+ADD or ADRP+LDR).
        let Some(table_base) = self.resolve_aarch64_table_base(stream, ldr.rn, disassembler) else {
            return Ok(None);
        };

        // 4) Resolve the anchor. Try (a) ADR producing anchor_reg, then
        //    (b) reuse the table-base resolver if anchor_reg == ldr.rn
        //    (common: anchor and table base are the same register).
        let anchor = stream
            .iter()
            .rev()
            .find_map(|(w, addr)| decode_adr(*w, *addr).filter(|(rd, _)| *rd == anchor_reg))
            .map(|(_, va)| va)
            .or_else(|| {
                if anchor_reg == ldr.rn {
                    Some(table_base)
                } else {
                    self.resolve_aarch64_table_base(stream, anchor_reg, disassembler)
                }
            });
        let Some(anchor) = anchor else {
            return Ok(None);
        };

        // 5) Read the table: each entry is a signed byte/halfword,
        //    sign-extended and scaled by 4.
        let mut targets = Vec::with_capacity(max_entries);
        for i in 0..max_entries {
            let Some(rel) = (i as u64).checked_mul(entry_bytes as u64) else {
                break;
            };
            let Some(entry_addr) = table_base.checked_add(rel) else {
                break;
            };
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(entry_addr)?
            {
                break;
            }
            let Ok(bytes) = disassembler
                .disassembly
                .get_bytes(entry_addr, entry_bytes as u64)
            else {
                break;
            };
            let delta_raw = match entry_bytes {
                1 => bytes[0] as i8 as i64,
                2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
                _ => break,
            };
            // ARM ARM C5.1.3: SXTB/SXTH + LSL #2 means the value
            // contributes `signed << 2` bytes to the destination.
            // Same reinterpretation pattern as variant A above —
            // see comment there. (0.6.1)
            let offset = delta_raw.wrapping_shl(2);
            let target = anchor.wrapping_add(offset as u64);
            if !disassembler
                .disassembly
                .is_addr_within_memory_image(target)?
            {
                break;
            }
            state.add_data_ref(br_addr, entry_addr, entry_bytes as u64)?;
            targets.push(target);
        }
        if targets.is_empty() {
            return Ok(None);
        }
        targets.sort_unstable();
        targets.dedup();
        Ok(Some(targets))
    }

    /// Resolve a register-loaded table base address by back-walking.
    /// Tries the two canonical AArch64 patterns:
    ///
    /// **Direct address (non-PIE)** — page + add:
    /// ```text
    /// ADRP xR, table_page
    /// ADD  xR, xR, #table_pageoff
    /// ```
    /// Returns `table_page + table_pageoff`.
    ///
    /// **GOT-loaded (PIE / position-independent)** — page + load:
    /// ```text
    /// ADRP xR, got_page
    /// LDR  xR, [xR, #got_offset]
    /// ```
    /// Reads 8 bytes at `got_page + got_offset` and returns the
    /// dereferenced table base. Required for most Linux ARM64 release
    /// binaries (built with `-fPIC`/`-fpie`) where the linker resolves
    /// table addresses through the GOT.
    ///
    /// Returns `None` if neither pattern matches the back-walk window.
    fn resolve_aarch64_table_base(
        &self,
        stream: &[(u32, u64)],
        target_reg: u8,
        disassembler: &Disassembler,
    ) -> Option<u64> {
        // --- Pattern 1: ADRP + ADD (direct address) -----------------
        let add = stream.iter().rev().find_map(|(w, addr)| {
            decode_add_sub_imm(*w)
                .filter(|(rd, rn, _, is_sub)| !is_sub && *rd == target_reg && *rn == target_reg)
                .map(|(_, _, imm, _)| (imm, *addr))
        });
        let adrp = stream
            .iter()
            .rev()
            .find_map(|(w, addr)| decode_adrp(*w, *addr).filter(|(rd, _)| *rd == target_reg));

        if let Some((_, page_va)) = adrp {
            if let Some((add_imm, _)) = add {
                return Some(page_va.wrapping_add(add_imm));
            }

            // --- Pattern 2: ADRP + LDR (GOT thunk) ------------------
            // LDR xR, [xR, #imm12] where Rt == Rn == target_reg, then
            // dereference the slot to get the real table base.
            let ldr = stream.iter().rev().find_map(|(w, _)| {
                decode_ldr_str_uimm(*w).filter(|op| {
                    op.rt == target_reg && op.rn == target_reg && !op.is_store && op.size_bytes == 8
                })
            });
            if let Some(op) = ldr {
                let slot_va = page_va.wrapping_add(op.offset);
                // Slot must be in image and dereferenceable to 8 bytes.
                if disassembler
                    .disassembly
                    .is_addr_within_memory_image(slot_va)
                    .unwrap_or(false)
                    && let Ok(bytes) = disassembler.disassembly.get_bytes(slot_va, 8)
                    && let Ok(packed) = <&[u8; 8]>::try_from(bytes)
                {
                    let table_base = u64::from_le_bytes(*packed);
                    if disassembler
                        .disassembly
                        .is_addr_within_memory_image(table_base)
                        .unwrap_or(false)
                    {
                        return Some(table_base);
                    }
                }
            }
        }

        None
    }
}
