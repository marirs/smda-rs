use crate::{
    error::Error, function::Function, statistics::DisassemblyStatistics, DisassemblyResult,
    FileArchitecture, FileFormat, Result,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct DisassemblyReport {
    pub format: FileFormat,
    pub architecture: FileArchitecture,
    pub base_addr: u64,
    binary_size: u64,
    binweight: u32,
    pub bitness: u32,
    pub buffer: Vec<u8>,
    _code_areas: Vec<(u64, u64)>,
    pub code_sections: Vec<(String, u64, u64)>,
    empty_section: (String, u64, u64),
    _component: String,
    confidence_threshold: f32,
    _family: String,
    _filename: String,
    _identified_alignment: usize,
    _is_library: bool,
    _is_buffer: bool,
    _message: String,
    _sha256: String,
    _statistics: DisassemblyStatistics,
    functions: HashMap<u64, Function>,
    pub sections: Vec<(String, u64, usize)>,
    pub imports: Vec<(String, String, usize)>,
    pub exports: Vec<(String, usize)>,
}

impl DisassemblyReport {
    pub fn new(disassembly: &mut DisassemblyResult) -> Result<DisassemblyReport> {
        let mut res = DisassemblyReport {
            format: disassembly.binary_info.file_format,
            architecture: disassembly.binary_info.file_architecture,
            base_addr: disassembly.binary_info.base_addr,
            binary_size: disassembly.binary_info.binary_size,
            binweight: 0,
            bitness: disassembly.binary_info.bitness,
            buffer: disassembly.binary_info.binary.clone(),
            _code_areas: disassembly.binary_info.code_areas.clone(),
            code_sections: disassembly.binary_info.get_sections()?,
            empty_section: ("".to_string(), 0, 0),
            _component: disassembly.binary_info.component.clone(),
            confidence_threshold: disassembly.get_confidence_threshold()?,
            _family: disassembly.binary_info.family.clone(),
            _filename: disassembly.binary_info.file_path.clone(),
            _identified_alignment: disassembly.identified_alignment,
            _is_library: disassembly.binary_info.is_library,
            _is_buffer: disassembly.binary_info.is_buffer,
            _message: "Analysis finished regularly.".to_string(),
            _sha256: disassembly.binary_info.sha256.clone(),
            _statistics: DisassemblyStatistics::new(disassembly)?,
            functions: HashMap::new(),
            sections: disassembly.binary_info.sections.clone(),
            imports: disassembly.binary_info.imports.clone(),
            exports: disassembly.binary_info.exports.clone(),
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
}
