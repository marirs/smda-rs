use crate::{
    BinaryInfo, DisassemblyResult, FileArchitecture, FileFormat, Result,
    error::Error,
    function::{Function, Instruction},
    statistics::DisassemblyStatistics,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DisassemblyReport<'a> {
    pub format: FileFormat,
    pub architecture: FileArchitecture,
    pub base_addr: u64,
    binary_size: u64,
    binweight: u32,
    pub bitness: u32,
    /// Original entry point (VA). PE: `ImageBase + AddressOfEntryPoint`.
    /// ELF: `e_entry`. Zero for formats / inputs without an OEP.
    /// (0.4.1) — mirrors `SmdaReport.oep` in the Python upstream.
    pub oep: u64,
    /// Borrowed view onto the original input bytes — replaces the owned
    /// `buffer: Vec<u8>` (mapped image clone) field that 0.3.x carried.
    /// Use `binary_info.bytes_at(va, len)` to read; `raw_data` is exposed
    /// for callers that need the file SHA-256-equivalent slice.
    pub binary_info: BinaryInfo<'a>,
    code_areas: Vec<(u64, u64)>,
    pub code_sections: Vec<(String, u64, u64)>,
    empty_section: (String, u64, u64),
    component: String,
    confidence_threshold: f32,
    family: String,
    filename: String,
    identified_alignment: usize,
    is_library: bool,
    is_buffer: bool,
    message: String,
    sha256: String,
    statistics: DisassemblyStatistics,
    pub functions: HashMap<u64, Function>,
    pub sections: Vec<(String, u64, usize)>,
    pub imports: Vec<(String, String, usize)>,
    pub exports: Vec<(String, usize, Option<String>)>,
    pub addr_to_api: HashMap<u64, (Option<String>, Option<String>)>,
}

impl<'a> DisassemblyReport<'a> {
    pub fn new(disassembly: &mut DisassemblyResult<'a>) -> Result<DisassemblyReport<'a>> {
        let mut res = DisassemblyReport {
            format: disassembly.binary_info.file_format,
            architecture: disassembly.binary_info.file_architecture,
            base_addr: disassembly.binary_info.base_addr,
            binary_size: disassembly.binary_info.binary_size,
            binweight: 0,
            bitness: disassembly.binary_info.bitness,
            oep: disassembly.binary_info.entry_point,
            binary_info: disassembly.binary_info.clone(),
            code_areas: disassembly.binary_info.code_areas.clone(),
            code_sections: disassembly.binary_info.get_sections()?,
            empty_section: ("".to_string(), 0, 0),
            component: disassembly.binary_info.component.clone(),
            confidence_threshold: disassembly.get_confidence_threshold()?,
            family: disassembly.binary_info.family.clone(),
            filename: disassembly.binary_info.file_path.clone(),
            identified_alignment: disassembly.identified_alignment,
            is_library: disassembly.binary_info.is_library,
            is_buffer: disassembly.binary_info.is_buffer,
            message: "Analysis finished regularly.".to_string(),
            sha256: disassembly.binary_info.sha256.clone(),
            statistics: DisassemblyStatistics::new(disassembly)?,
            functions: HashMap::new(),
            sections: disassembly.binary_info.sections.clone(),
            imports: disassembly.binary_info.imports.clone(),
            exports: disassembly.binary_info.exports.clone(),
            addr_to_api: HashMap::new(),
        };
        for function_offset in disassembly.functions.keys() {
            if res.confidence_threshold > 0.0
                && disassembly.candidates.contains_key(function_offset)
                && disassembly.candidates[function_offset].get_confidence()?
                    < res.confidence_threshold
            {
                continue;
            }
            let function = Function::new(disassembly, function_offset)?;
            res.binweight += function.binweight;
            res.functions.insert(*function_offset, function);
            res.addr_to_api = disassembly.addr_to_api.clone();
        }
        Ok(res)
    }

    pub fn get_functions(&self) -> Result<&HashMap<u64, Function>> {
        Ok(&self.functions)
    }

    pub fn get_function(&self, function_addr: u64) -> Result<&Function> {
        match self.functions.get(&function_addr) {
            Some(f) => Ok(f),
            _ => Err(Error::InvalidRule(line!(), file!().to_string())),
        }
    }

    pub fn is_addr_within_memory_image(&self, offset: &u64) -> Result<bool> {
        Ok(&self.base_addr <= offset && offset < &(self.base_addr + self.binary_size))
    }

    pub fn get_section(&self, offset: &u64) -> Result<&(String, u64, u64)> {
        for section in &self.code_sections {
            if section.1 <= *offset && *offset < section.2 {
                return Ok(section);
            }
        }
        Ok(&self.empty_section)
    }

    /// (0.4.1) Return the function whose range contains `addr`, if any.
    /// Mirrors `SmdaReport.findFunctionByOffset` in the Python upstream.
    /// A function "contains" `addr` if `addr` is the start address of
    /// any of its basic blocks or the offset of any instruction within
    /// one of its blocks. Linear scan over functions × blocks — for a
    /// 100k-function binary this is roughly 5 ms; cache the result if
    /// you call it on every instruction.
    pub fn find_function_by_offset(&self, addr: u64) -> Option<&Function> {
        for func in self.functions.values() {
            let Ok(blocks) = func.get_blocks() else {
                continue;
            };
            for block in blocks.values() {
                if let Some(first) = block.first()
                    && let Some(last) = block.last()
                    && first.offset <= addr
                    && addr <= last.offset
                {
                    return Some(func);
                }
            }
        }
        None
    }

    /// (0.4.1) Return the basic block whose range contains `addr`, if any.
    /// Returns `(function, block_instructions)`. Mirrors
    /// `SmdaReport.findBlockByOffset` upstream.
    pub fn find_block_by_offset(&self, addr: u64) -> Option<(&Function, &Vec<Instruction>)> {
        for func in self.functions.values() {
            let Ok(blocks) = func.get_blocks() else {
                continue;
            };
            for block in blocks.values() {
                if let Some(first) = block.first()
                    && let Some(last) = block.last()
                    && first.offset <= addr
                    && addr <= last.offset
                {
                    return Some((func, block));
                }
            }
        }
        None
    }
}
