use crate::{DisassemblyResult, Result, disassembler::DecodedInsn, error::Error};
use iced_x86::{FlowControl, Mnemonic};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
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
            if instruction.offset() < addr_from {
                backtracked.push(*instruction);
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
        let i_address = ins.offset();
        let i_size = ins.length() as u64;
        self.instructions.push(ins);
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
            // sane case: stub-jmp that is just a `EB <rel8>` short jump.
            let first_is_x86_jmp = self
                .instructions
                .first()
                .and_then(|i| i.mnemonic_enum_x86())
                .is_some_and(|m| matches!(m, Mnemonic::Jmp));
            // 0.6.0: AArch64 analog — a single-instruction stub thunk
            // (`b <import>`) is a legitimate function end too. Detect
            // via the arch-agnostic `is_jump()` (which matches the
            // disarm64 `b` mnemonic on AArch64).
            let first_is_aarch64_b = self
                .instructions
                .first()
                .is_some_and(|i| matches!(i, DecodedInsn::Aarch64(_)) && i.is_jump());
            if self.instructions.len() == 1 && first_is_x86_jmp {
                let byte = disassembly.get_byte(self.instructions[0].offset())?;
                if byte == 0xEB {
                    return Ok(false);
                }
            } else if self.instructions.len() == 1 && first_is_aarch64_b {
                // Accept the AArch64 single-instruction stub as a real
                // function (its body is just the tail-call branch).
            }
            // sane case: single-block tailcall (jmp/call as last)
            else if self.num_blocks_analyzed == 1 {
                let Some(last) = self.instructions.last() else {
                    return Ok(false);
                };
                let is_tailcall_like = match last.mnemonic_enum_x86() {
                    Some(m) => matches!(m, Mnemonic::Jmp | Mnemonic::Call),
                    // AArch64: b / bl are the analogous tail-call forms.
                    // Use the arch-agnostic `is_call` / `is_jump` so we
                    // don't pay for the per-call mnemonic-string alloc.
                    None => last.is_call() || last.is_jump(),
                };
                if !is_tailcall_like {
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
            ins.insert(i.offset(), cc);
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
                block.push(*current);

                // If one code reference is to another address than the next
                let cur_off = current.offset();
                if self.code_refs_from.contains_key(&cur_off)
                    && !current.is_call()
                    && i != self.instructions.len() - 1
                {
                    for r in &self.code_refs_from[&cur_off] {
                        if *r != self.instructions[i + 1].offset() {
                            break;
                        }
                    }
                }

                if i != self.instructions.len() - 1
                    && self
                        .code_refs_to
                        .contains_key(&self.instructions[i + 1].offset())
                    && (self.code_refs_to[&self.instructions[i + 1].offset()].len() > 1
                        || potential_starts.contains(&self.instructions[i + 1].offset()))
                {
                    break;
                }

                if is_end_decoded(current) {
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
            if s.offset() < fn_min {
                fn_min = s.offset();
            }
        }
        let mut fn_max: u64 = 0;
        for s in &self.instructions {
            if s.offset() + s.length() as u64 > fn_max {
                fn_max = s.offset() + s.length() as u64;
            }
        }
        // 0.4.2 (N1): don't overwrite a pre-populated function symbol
        // (e.g. a Go pclntab name) with an empty `label`. The label
        // providers don't actually implement `get_symbol` yet, so
        // `state.label` is almost always empty — a blind insert here
        // would wipe out any name we'd seeded before analysis.
        if !self.label.is_empty() || !disassembly.function_symbols.contains_key(&self.start_addr) {
            disassembly
                .function_symbols
                .insert(self.start_addr, self.label.clone());
        }
        disassembly
            .function_borders
            .insert(self.start_addr, (fn_min, fn_max));
        for ins in &self.instructions {
            // Note: we no longer store the mnemonic string per instruction
            // (it's available via the DecodedInsn typed surface). The
            // legacy `instructions` map kept a (mnemonic_str, length)
            // pair; for compatibility we store length-only with an empty
            // string. Real consumers should walk `functions` instead.
            let ins_off = ins.offset();
            let ins_len = ins.length() as u32;
            disassembly
                .instructions
                .insert(ins_off, (String::new(), ins_len));
            for offset in 0..ins_len {
                disassembly
                    .code_map
                    .insert(ins_off + offset as u64, ins_off);
                disassembly
                    .ins2fn
                    .insert(ins_off + offset as u64, self.start_addr);
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
#[allow(dead_code)]
fn is_end_instruction(mnem: Mnemonic, fc: FlowControl) -> bool {
    matches!(fc, FlowControl::Return) || matches!(mnem, Mnemonic::Hlt | Mnemonic::Int3)
}

/// Arch-agnostic block-ending check used by `get_blocks`. On x86 this
/// is true for `ret` / `hlt` / `int3`; on AArch64 for `ret` (other
/// terminators — `b`, `b.cond`, `cbz`, etc. — are caught upstream via
/// the analyser's branch detection).
fn is_end_decoded(ins: &DecodedInsn) -> bool {
    if let Some(iced) = ins.as_iced() {
        is_end_instruction(iced.mnemonic(), iced.flow_control())
    } else {
        ins.is_return()
    }
}
