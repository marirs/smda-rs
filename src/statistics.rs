use crate::{DisassemblyResult, Result};

#[derive(Debug)]
pub struct DisassemblyStatistics {
    _num_functions: usize,
    _num_recursive_functions: usize,
    _num_leaf_functions: usize,
    _num_basic_blocks: usize,
    _num_instructions: usize,
    _num_api_calls: usize,
    _num_function_calls: usize,
    _num_failed_functions: usize,
}

impl DisassemblyStatistics {
    pub fn new(disassembly_result: &mut DisassemblyResult) -> Result<DisassemblyStatistics> {
        Ok(DisassemblyStatistics {
            _num_functions: disassembly_result.functions.len(),
            _num_recursive_functions: disassembly_result.recursive_functions.len(),
            _num_leaf_functions: disassembly_result.leaf_functions.len(),
            _num_basic_blocks: DisassemblyStatistics::count_blocks(disassembly_result)?,
            _num_instructions: DisassemblyStatistics::count_instructions(disassembly_result)?,
            _num_api_calls: DisassemblyStatistics::count_api_calls(disassembly_result)?,
            _num_function_calls: DisassemblyStatistics::count_function_calls(disassembly_result)?,
            _num_failed_functions: disassembly_result.failed_analysis_addr.len(),
        })
    }

    fn count_blocks(disassembly_result: &DisassemblyResult) -> Result<usize> {
        let mut num_blocks = 0;
        for blocks in disassembly_result.functions.values() {
            num_blocks += blocks.len();
        }
        Ok(num_blocks)
    }

    fn count_api_calls(disassembly_result: &mut DisassemblyResult) -> Result<usize> {
        Ok(disassembly_result.get_all_api_refs()?.len())
    }

    fn count_instructions(disassembly_result: &DisassemblyResult) -> Result<usize> {
        let mut num_ins = 0;
        for function_offset in disassembly_result.functions.keys() {
            for block in &disassembly_result.functions[function_offset] {
                num_ins += block.len();
            }
        }
        Ok(num_ins)
    }

    fn count_function_calls(disassembly_result: &DisassemblyResult) -> Result<usize> {
        let mut num_calls = 0;
        for function_start in disassembly_result.functions.keys() {
            if disassembly_result.code_refs_to.contains_key(function_start) {
                num_calls += disassembly_result.code_refs_to[function_start].len();
            }
        }
        Ok(num_calls)
    }
}
