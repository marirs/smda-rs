use crate::{error::Error, function::DecodedInsn, DisassemblyResult, Result};
use iced_x86::{FlowControl, Mnemonic};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug)]
pub struct FunctionAnalysisState {
    pub start_addr: u64,
    pub block_queue: VecDeque<u64>,
    pub(crate) current_block: Vec<DecodedInsn>,
    blocks: Vec<Vec<DecodedInsn>>,
    num_blocks_analyzed: u32,
    pub instructions: Vec<DecodedInsn>,
    pub instruction_start_bytes: HashSet<u64>,
    processed_blocks: HashSet<u64>,
    processed_bytes: HashSet<u64>,
    jump_targets: Vec<u64>,
    pub call_register_ins: Vec<u64>,
    pub block_start: u64,
    data_bytes: Vec<u64>,
    data_refs: Vec<(u64, u64)>,
    pub code_refs: Vec<(u64, u64)>,
    code_refs_from: HashMap<u64, Vec<u64>>,
    code_refs_to: HashMap<u64, Vec<u64>>,
    pub suspicious_ins_count: u32,
    is_jmp: bool,
    is_next_instruction_reachable: bool,
    is_block_ending_instruction: bool,
    is_sanely_ending: bool,
    has_collision: bool,
    pub is_tailcall_function: bool,
    is_leaf_function: bool,
    is_recursive: bool,
    is_thunk_call: bool,
    pub label: String,
}

impl FunctionAnalysisState {
    pub fn new(addr: u64) -> Result<FunctionAnalysisState> {
        Ok(FunctionAnalysisState {
            start_addr: addr,
            block_queue: vec![addr].into_iter().collect(),
            current_block: vec![],
            blocks: vec![],
            num_blocks_analyzed: 0,
            instructions: vec![],
            instruction_start_bytes: HashSet::new(),
            processed_blocks: HashSet::new(),
            processed_bytes: HashSet::new(),
            jump_targets: vec![],
            call_register_ins: vec![],
            block_start: 0xFFFFFFFF,
            data_bytes: vec![],
            data_refs: vec![],
            code_refs: vec![],
            code_refs_from: HashMap::new(),
            code_refs_to: HashMap::new(),
            suspicious_ins_count: 0,
            is_jmp: false,
            is_next_instruction_reachable: true,
            is_block_ending_instruction: false,
            is_sanely_ending: false,
            has_collision: false,
            is_tailcall_function: false,
            is_leaf_function: true,
            is_recursive: false,
            is_thunk_call: false,
            label: String::new(),
        })
    }

    pub fn is_processed_function(&self, disassembly: &DisassemblyResult) -> bool {
        disassembly.code_map.contains_key(&self.start_addr)
    }

    pub fn has_unprocessed_blocks(&self) -> bool {
        let ss: HashSet<u64> = self.block_queue.clone().into_iter().collect();
        ss.difference(&self.processed_blocks).count() > 0
    }

    pub fn choose_next_block(&mut self) -> Result<u64> {
        self.is_block_ending_instruction = false;
        self.block_start = self
            .block_queue
            .pop_back()
            .ok_or(Error::LogicError(file!(), line!()))?;
        self.processed_blocks.insert(self.block_start);
        Ok(self.block_start)
    }

    pub fn set_next_instruction_reachable(&mut self, flag: bool) -> Result<()> {
        self.is_next_instruction_reachable = flag;
        Ok(())
    }

    pub fn set_leaf(&mut self, flag: bool) -> Result<()> {
        self.is_leaf_function = flag;
        Ok(())
    }

    pub fn add_code_ref(&mut self, addr_from: u64, addr_to: u64, by_jump: bool) -> Result<()> {
        self.code_refs.push((addr_from, addr_to));
        self.code_refs_from
            .entry(addr_from)
            .or_default()
            .push(addr_to);
        self.code_refs_to
            .entry(addr_to)
            .or_default()
            .push(addr_from);
        if by_jump {
            self.is_jmp = true;
            self.jump_targets.push(addr_to);
        }
        Ok(())
    }

    pub fn is_processed(&self, addr: &u64) -> Result<bool> {
        Ok(self.processed_bytes.contains(addr))
    }

    pub fn is_block_ending_instruction(&self) -> Result<bool> {
        Ok(self.is_block_ending_instruction)
    }

    pub fn set_recursion(&mut self, flag: bool) -> Result<()> {
        self.is_recursive = flag;
        Ok(())
    }

    pub fn set_sanely_ending(&mut self, flag: bool) -> Result<()> {
        self.is_sanely_ending = flag;
        Ok(())
    }

    pub fn is_first_instruction(&self) -> Result<bool> {
        Ok(self.instructions.is_empty())
    }

    pub fn add_block_to_queue(&mut self, block_start: u64) -> Result<()> {
        if !self.processed_blocks.contains(&block_start) {
            self.block_queue.push_back(block_start);
        }
        Ok(())
    }

    pub fn set_block_ending_instruction(&mut self, flag: bool) -> Result<()> {
        self.is_block_ending_instruction = flag;
        Ok(())
    }

    pub fn backtrack_instructions(
        &self,
        addr_from: u64,
        num_instructions: u32,
    ) -> Result<Vec<DecodedInsn>> {
        let mut backtracked = vec![];
        for instruction in &self.instructions {
            if instruction.offset < addr_from {
                backtracked.push(instruction.clone());
            }
        }
        if backtracked.len() < num_instructions as usize {
            Ok(backtracked)
        } else {
            Ok(backtracked[backtracked.len() - num_instructions as usize..].to_vec())
        }
    }

    pub fn add_data_ref(&mut self, addr_from: u64, addr_to: u64, size: u64) -> Result<()> {
        self.data_refs.push((addr_from, addr_to));
        for i in 0..size {
            self.data_bytes.push(addr_to + i);
        }
        Ok(())
    }

    pub fn end_block(&mut self) -> Result<()> {
        if !self.current_block.is_empty() {
            self.num_blocks_analyzed += 1;
        }
        self.current_block = vec![];
        Ok(())
    }

    pub fn add_instruction(&mut self, ins: DecodedInsn) -> Result<()> {
        let i_address = ins.offset;
        let i_size = ins.length as u64;
        self.instructions.push(ins.clone());
        self.instruction_start_bytes.insert(i_address);
        self.current_block.push(ins);
        for byte in 0..i_size {
            self.processed_bytes.insert(i_address + byte);
        }
        if self.is_next_instruction_reachable {
            self.add_code_ref(i_address, i_address + i_size, self.is_jmp)?;
        }
        self.is_jmp = false;
        Ok(())
    }

    pub fn set_collision(&mut self, flag: bool) -> Result<()> {
        self.has_collision = flag;
        Ok(())
    }

    pub fn finalize_analysis(
        &mut self,
        as_gap: bool,
        disassembly: &mut DisassemblyResult,
    ) -> Result<bool> {
        if as_gap && !self.is_sanely_ending {
            // sane case: stub-jmp that is just a `EB <rel8>` short jump
            if self.instructions.len() == 1
                && matches!(self.instructions[0].iced.mnemonic(), Mnemonic::Jmp)
            {
                let byte = disassembly.get_byte(self.instructions[0].offset)?;
                if byte == 0xEB {
                    return Ok(false);
                }
            }
            // sane case: single-block tailcall (jmp/call as last)
            else if self.num_blocks_analyzed == 1 {
                let last = &self.instructions[self.instructions.len() - 1];
                if matches!(last.iced.mnemonic(), Mnemonic::Jmp | Mnemonic::Call) {
                    // tailcall-like; accept
                } else {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        if self.num_blocks_analyzed > 0 {
            self.finalize_regular_analysis(disassembly)?;
        }
        Ok(true)
    }

    pub fn get_blocks(&self) -> Result<Vec<Vec<DecodedInsn>>> {
        let mut ins = HashMap::new();
        for (cc, i) in self.instructions.iter().enumerate() {
            ins.insert(i.offset, cc);
        }
        let mut potential_starts = self.jump_targets.clone();
        potential_starts.push(self.start_addr);
        potential_starts.sort_unstable();
        let mut blocks = vec![];
        for start in &potential_starts {
            let Some(&start_idx) = ins.get(start) else {
                continue;
            };
            let mut block = vec![];
            for i in start_idx..self.instructions.len() {
                let current = &self.instructions[i];
                block.push(current.clone());

                // If one code reference is to another address than the next
                if self.code_refs_from.contains_key(&current.offset)
                    && !matches!(
                        current.iced.flow_control(),
                        FlowControl::Call | FlowControl::IndirectCall
                    )
                    && i != self.instructions.len() - 1
                {
                    for r in &self.code_refs_from[&current.offset] {
                        if *r != self.instructions[i + 1].offset {
                            break;
                        }
                    }
                }

                if i != self.instructions.len() - 1
                    && self
                        .code_refs_to
                        .contains_key(&self.instructions[i + 1].offset)
                    && (self.code_refs_to[&self.instructions[i + 1].offset].len() > 1
                        || potential_starts.contains(&self.instructions[i + 1].offset))
                {
                    break;
                }

                if is_end_instruction(current.iced.mnemonic(), current.iced.flow_control()) {
                    break;
                }
            }
            if !block.is_empty() {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    pub fn finalize_regular_analysis(&mut self, disassembly: &mut DisassemblyResult) -> Result<()> {
        let mut fn_min: u64 = 0xFFFFFFFFFFFFFFFF;
        for s in &self.instructions {
            if s.offset < fn_min {
                fn_min = s.offset;
            }
        }
        let mut fn_max: u64 = 0;
        for s in &self.instructions {
            if s.offset + s.length as u64 > fn_max {
                fn_max = s.offset + s.length as u64;
            }
        }
        disassembly
            .function_symbols
            .insert(self.start_addr, self.label.clone());
        disassembly
            .function_borders
            .insert(self.start_addr, (fn_min, fn_max));
        for ins in &self.instructions {
            // Note: we no longer store the mnemonic string per instruction
            // (it's available via iced enum). The legacy `instructions`
            // map kept a (mnemonic_str, length) pair; for compatibility we
            // store length-only with an empty string. Real consumers should
            // walk `functions` instead and read the DecodedInsn.iced.
            disassembly
                .instructions
                .insert(ins.offset, (String::new(), ins.length));
            for offset in 0..ins.length {
                disassembly
                    .code_map
                    .insert(ins.offset + offset as u64, ins.offset);
                disassembly
                    .ins2fn
                    .insert(ins.offset + offset as u64, self.start_addr);
            }
        }
        for cref in &self.code_refs {
            disassembly.add_code_refs(cref.0, cref.1)?;
        }
        for dref in &self.data_refs {
            disassembly.add_data_refs(dref.0, dref.1)?;
        }
        for d in &self.data_bytes {
            disassembly.data_map.insert(*d);
        }
        disassembly
            .functions
            .insert(self.start_addr, self.get_blocks()?);
        if self.is_recursive {
            disassembly.recursive_functions.insert(self.start_addr);
        }
        if self.is_leaf_function {
            disassembly.leaf_functions.insert(self.start_addr);
        }
        if self.is_thunk_call {
            disassembly.thunk_functions.insert(self.start_addr);
        }
        Ok(())
    }

    pub fn identify_call_conflicts(
        &self,
        all_refs: &HashMap<u64, u64>,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        let mut conflicts: HashMap<u64, Vec<u64>> = HashMap::new();
        let non_instruction_start_bytes: HashSet<u64> = self
            .processed_bytes
            .difference(&self.instruction_start_bytes)
            .copied()
            .collect();
        let all_refs_set: HashSet<u64> = all_refs.keys().copied().collect();
        let conflict_addrs = all_refs_set.intersection(&non_instruction_start_bytes);
        for candidate_source_ref in conflict_addrs {
            let candidate = all_refs[candidate_source_ref];
            conflicts
                .entry(candidate)
                .or_default()
                .push(*candidate_source_ref);
        }
        Ok(conflicts)
    }

    pub fn revert_analysis(&self) -> Result<()> {
        // TODO: mirror Python `revertAnalysis`
        Ok(())
    }
}

/// Replaces the prior `END_INS` `&[Option<&str>]` constant. Returns true if
/// the instruction is a "block-ending" instruction (return, hlt, int3).
fn is_end_instruction(mnem: Mnemonic, fc: FlowControl) -> bool {
    matches!(fc, FlowControl::Return) || matches!(mnem, Mnemonic::Hlt | Mnemonic::Int3)
}
