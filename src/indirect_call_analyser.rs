#![allow(clippy::too_many_arguments)]
use crate::{
    Disassembler, FunctionAnalysisState, Result,
    error::Error,
    function::{DecodedInsn, capstone_compat_formatter},
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
    if ins.iced.op_count() == 0 {
        return String::new();
    }
    let mut fmt = capstone_compat_formatter();
    let mut out = String::new();
    fmt.format_all_operands(&ins.iced, &mut out);
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
                if ins.offset <= *calling_addr {
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
                if address == &i.offset {
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
        let block_start = block[0].offset;
        if processed.contains(&block_start) {
            return Ok(false);
        }
        processed.insert(block_start);

        let mut abs_value_found = false;
        for ins in block.iter().rev() {
            let mnem = ins.iced.mnemonic();
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
                    let rip = ins.offset + ins.length as u64;
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
                if !blk.is_empty() && processed.contains(&blk[0].offset) {
                    for ins in &blk {
                        all_processed_offsets.insert(ins.offset);
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
}
