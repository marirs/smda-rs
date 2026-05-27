#![allow(clippy::invalid_regex)]
use crate::{
    Disassembler, DisassemblyResult, FunctionAnalysisState, Result,
    disassembler::{DecodedInsn, capstone_compat_formatter},
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
}
