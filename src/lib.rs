#![allow(dead_code)]
#![allow(clippy::type_complexity)]
#[macro_use]
extern crate maplit;

pub mod elf;
pub mod function;
mod function_analysis_state;
mod function_candidate;
mod function_candidate_manager;
mod indirect_call_analyser;
mod jump_table_analyser;
mod label_provider;
mod label_providers;
mod mnemonic_tf_idf;
mod pe;
pub mod report;
mod statistics;
mod tail_call_analyser;

use function::{DecodedInsn, capstone_compat_formatter};
use function_analysis_state::FunctionAnalysisState;
use function_candidate::FunctionCandidate;
use function_candidate_manager::FunctionCandidateManager;
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Mnemonic};
use indirect_call_analyser::IndirectCallAnalyser;
use jump_table_analyser::JumpTableAnalyser;
use label_provider::LabelProvider;
use mnemonic_tf_idf::MnemonicTfIdf;
use regex::bytes::Regex as BytesRegex;
use report::DisassemblyReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    io::Read,
    sync::LazyLock,
    time::SystemTime,
};
use tail_call_analyser::TailCallAnalyser;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

static BITNESS: LazyLock<BytesRegex> = LazyLock::new(|| BytesRegex::new(r"(?-u)\xE8").unwrap());
static REF_ADDR: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)0x[a-fA-F0-9]+").unwrap());
static RE_NUMBER_HEX_SIGN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?P<sign>[+\-]) (?P<num>0x[a-fA-F0-9]+)").unwrap());

static REGS_32BIT: &[&str] = &["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
static REGS_64BIT: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileFormat {
    ELF,
    PE,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileFormat::ELF => write!(f, "Elf file"),
            FileFormat::PE => write!(f, "PE file"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileArchitecture {
    I386,
    AMD64,
}

impl std::fmt::Display for FileArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileArchitecture::I386 => write!(f, "i386"),
            FileArchitecture::AMD64 => write!(f, "amd64"),
        }
    }
}

#[derive(Debug)]
pub struct BinaryInfo {
    pub file_format: FileFormat,
    pub file_architecture: FileArchitecture,
    pub base_addr: u64,
    pub binary: Vec<u8>,
    pub raw_data: Vec<u8>,
    pub binary_size: u64,
    pub bitness: u32,
    pub code_areas: Vec<(u64, u64)>,
    pub component: String,
    pub family: String,
    pub file_path: String,
    pub is_library: bool,
    pub is_buffer: bool,
    pub sha256: String,
    pub entry_point: u64,
    pub sections: Vec<(String, u64, usize)>,
    pub imports: Vec<(String, String, usize)>,
    pub exports: Vec<(String, usize, Option<String>)>,
}

impl Default for BinaryInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryInfo {
    pub fn new() -> BinaryInfo {
        BinaryInfo {
            file_format: FileFormat::ELF,
            file_architecture: FileArchitecture::I386,
            base_addr: 0,
            binary: vec![],
            raw_data: vec![],
            binary_size: 0,
            bitness: 32,
            code_areas: vec![],
            component: String::new(),
            family: String::new(),
            file_path: String::new(),
            is_library: false,
            is_buffer: false,
            sha256: String::new(),
            entry_point: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
        }
    }

    pub fn init(&mut self, content: &[u8]) -> Result<()> {
        self.raw_data = content.to_vec();
        self.binary_size = content.len() as u64;
        self.sha256 = BinaryInfo::sha256_digest(content);
        Ok(())
    }

    fn sha256_digest(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Returns `(section_name, va_start, va_end)` for each PE section. The
    /// addresses are mapped virtual addresses (i.e. `base_addr +
    /// virtual_address`), matching what `report::get_section` and
    /// `function_candidate_manager::locate_exception_handler_candidates`
    /// expect. Sections whose VA range overflows u64 are skipped.
    ///
    /// (Prior to 0.3.0 this returned file offsets, which silently broke the
    /// `.pdata` exception-handler scan and `report::get_section` lookups.)
    pub fn get_sections(&self) -> Result<Vec<(String, u64, u64)>> {
        match Object::parse(&self.raw_data)? {
            Object::PE(pe) => {
                let mut res = vec![];
                let base = self.base_addr;
                for sect in pe.sections {
                    let name = std::str::from_utf8(&sect.name)?.to_string();
                    let Some(va_start) = base.checked_add(sect.virtual_address as u64) else {
                        continue;
                    };
                    let size = sect.virtual_size.max(sect.size_of_raw_data) as u64;
                    let Some(va_end) = va_start.checked_add(size) else {
                        continue;
                    };
                    res.push((name, va_start, va_end));
                }
                Ok(res)
            }
            _ => Ok(vec![]),
        }
    }

    pub fn get_oep(&self) -> Result<u64> {
        match Object::parse(&self.raw_data)? {
            Object::PE(pe) => Ok(pe.entry as u64),
            _ => Ok(0),
        }
    }
}

#[derive(Debug)]
pub struct DisassemblyResult {
    analysis_start_ts: SystemTime,
    analysis_end_ts: SystemTime,
    analysis_timeout: bool,
    pub binary_info: BinaryInfo,
    identified_alignment: usize,
    pub code_map: HashMap<u64, u64>,
    pub data_map: HashSet<u64>,
    /// Per-function block list. Keyed by function start address; value is a
    /// `Vec<block>`, each block is `Vec<DecodedInsn>` (per-instruction iced
    /// decode + raw bytes — no per-instruction `String` mnemonic/operands).
    pub functions: HashMap<u64, Vec<Vec<DecodedInsn>>>,
    recursive_functions: HashSet<u64>,
    leaf_functions: HashSet<u64>,
    thunk_functions: HashSet<u64>,
    failed_analysis_addr: Vec<u64>,
    function_borders: HashMap<u64, (u64, u64)>,
    instructions: HashMap<u64, (String, u32)>,
    pub ins2fn: HashMap<u64, u64>,
    language: HashMap<i32, Vec<u8>>,
    data_refs_from: HashMap<u64, Vec<u64>>,
    data_refs_to: HashMap<u64, Vec<u64>>,
    pub code_refs_from: HashMap<u64, Vec<u64>>,
    pub code_refs_to: HashMap<u64, Vec<u64>>,
    pub apis: HashMap<u64, label_providers::ApiEntry>,
    pub addr_to_api: HashMap<u64, (Option<String>, Option<String>)>,
    pub function_symbols: HashMap<u64, String>,
    pub candidates: HashMap<u64, FunctionCandidate>,
    confidence_threshold: f32,
    code_areas: Vec<u8>,
}

impl Default for DisassemblyResult {
    fn default() -> Self {
        Self::new()
    }
}

impl DisassemblyResult {
    pub fn new() -> DisassemblyResult {
        DisassemblyResult {
            analysis_start_ts: SystemTime::now(),
            analysis_end_ts: SystemTime::now(),
            analysis_timeout: false,
            binary_info: BinaryInfo::new(),
            identified_alignment: 0,
            code_map: HashMap::new(),
            data_map: HashSet::new(),
            functions: HashMap::new(),
            recursive_functions: HashSet::new(),
            leaf_functions: HashSet::new(),
            thunk_functions: HashSet::new(),
            failed_analysis_addr: vec![],
            function_borders: HashMap::new(),
            instructions: HashMap::new(),
            ins2fn: HashMap::new(),
            language: HashMap::new(),
            data_refs_from: HashMap::new(),
            data_refs_to: HashMap::new(),
            code_refs_from: HashMap::new(),
            code_refs_to: HashMap::new(),
            apis: HashMap::new(),
            addr_to_api: HashMap::new(),
            function_symbols: HashMap::new(),
            candidates: HashMap::new(),
            confidence_threshold: 0.0,
            code_areas: vec![],
        }
    }

    pub fn init(&mut self, bi: BinaryInfo) -> Result<()> {
        self.analysis_start_ts = SystemTime::now();
        self.analysis_end_ts = SystemTime::now();
        self.binary_info = bi;
        Ok(())
    }

    pub fn get_all_api_refs(&mut self) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
        if self.addr_to_api.is_empty() {
            self.init_api_refs()?;
        }
        let mut all_api_refs = HashMap::new();
        let func_addrs: Vec<u64> = self.functions.keys().copied().collect();
        for function_addr in func_addrs {
            for (k, v) in self.get_api_refs(&function_addr)? {
                all_api_refs.insert(k, v);
            }
        }
        Ok(all_api_refs)
    }

    pub fn init_api_refs(&mut self) -> Result<()> {
        for api_offset in self.apis.keys() {
            let api = self.apis[api_offset].clone();
            for reference in api.referencing_addr {
                self.addr_to_api
                    .insert(reference, (api.dll_name.clone(), api.api_name.clone()));
            }
        }

        if self.binary_info.file_format == FileFormat::ELF {
            let elf_apis = elf::extract_elf_dynamic_apis(&self.binary_info.raw_data)?;
            for (addr, (dll, api)) in elf_apis {
                if api.is_some() {
                    let canonical_addr = if addr >= self.binary_info.base_addr {
                        addr
                    } else {
                        self.binary_info.base_addr + addr
                    };
                    self.addr_to_api
                        .insert(canonical_addr, (dll.clone(), api.clone()));
                }
            }
        }
        Ok(())
    }

    pub fn get_api_refs(
        &self,
        func_addr: &u64,
    ) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
        let mut api_refs = HashMap::new();
        let Some(blocks) = self.functions.get(func_addr) else {
            return Ok(api_refs);
        };

        for block in blocks {
            for ins in block {
                let ins_absolute_addr = self.binary_info.base_addr + ins.offset;

                // Direct lookup
                if let Some((dll, api)) = self.addr_to_api.get(&ins_absolute_addr) {
                    api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                    continue;
                }

                // If it's a call, follow the target
                if matches!(ins.iced.flow_control(), FlowControl::Call)
                    && let Some(target_addr) =
                        Self::extract_call_target(ins, self.binary_info.base_addr)
                {
                    if let Some((dll, api)) = self.addr_to_api.get(&target_addr) {
                        api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                        continue;
                    }
                    if let Some(api_entry) = self.apis.get(&target_addr) {
                        api_refs.insert(
                            ins_absolute_addr,
                            (api_entry.dll_name.clone(), api_entry.api_name.clone()),
                        );
                        continue;
                    }
                }
            }
        }

        Ok(api_refs)
    }

    fn extract_call_target(instruction: &DecodedInsn, _base_addr: u64) -> Option<u64> {
        use iced_x86::OpKind;
        if matches!(instruction.iced.flow_control(), FlowControl::Call)
            && instruction.iced.op_count() >= 1
        {
            match instruction.iced.op_kind(0) {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    return Some(instruction.iced.near_branch_target());
                }
                OpKind::Memory => {
                    let target = instruction.iced.memory_displacement64();
                    if target != 0 {
                        return Some(target);
                    }
                }
                _ => {}
            }
        }
        None
    }

    pub fn get_confidence_threshold(&self) -> Result<f32> {
        Ok(self.confidence_threshold)
    }

    pub fn get_byte(&self, addr: u64) -> Result<u8> {
        if self.is_addr_within_memory_image(addr)? {
            // is_addr_within_memory_image guarantees base_addr <= addr in
            // u64 space — do the subtraction in u64 (never in usize after
            // truncation, to stay correct on 32-bit targets).
            let rel = addr - self.binary_info.base_addr;
            let idx = usize::try_from(rel).map_err(|_| Error::NotEnoughBytesError(addr, 1))?;
            return self
                .binary_info
                .binary
                .get(idx)
                .copied()
                .ok_or(Error::NotEnoughBytesError(addr, 1));
        }
        Err(Error::LogicError(file!(), line!()))
    }

    pub fn get_raw_byte(&self, addr: u64) -> Result<u8> {
        let idx = usize::try_from(addr).map_err(|_| Error::NotEnoughBytesError(addr, 1))?;
        self.binary_info
            .binary
            .get(idx)
            .copied()
            .ok_or(Error::NotEnoughBytesError(addr, 1))
    }

    pub fn get_raw_bytes(&self, offset: u64, bytes: u64) -> Result<&[u8]> {
        let end = offset
            .checked_add(bytes)
            .ok_or(Error::NotEnoughBytesError(offset, bytes))?;
        let (start_us, end_us) = (
            usize::try_from(offset).map_err(|_| Error::NotEnoughBytesError(offset, bytes))?,
            usize::try_from(end).map_err(|_| Error::NotEnoughBytesError(offset, bytes))?,
        );
        self.binary_info
            .binary
            .get(start_us..end_us)
            .ok_or(Error::NotEnoughBytesError(offset, bytes))
    }

    pub fn get_bytes(&self, addr: u64, num_bytes: u64) -> Result<&[u8]> {
        if !self.is_addr_within_memory_image(addr)? {
            return Err(Error::NotEnoughBytesError(addr, num_bytes));
        }
        let rel_start = addr - self.binary_info.base_addr;
        let rel_end = rel_start
            .checked_add(num_bytes)
            .ok_or(Error::NotEnoughBytesError(addr, num_bytes))?;
        if rel_end > self.binary_info.binary_size {
            return Err(Error::NotEnoughBytesError(addr, num_bytes));
        }
        let (start_us, end_us) = (
            usize::try_from(rel_start).map_err(|_| Error::NotEnoughBytesError(addr, num_bytes))?,
            usize::try_from(rel_end).map_err(|_| Error::NotEnoughBytesError(addr, num_bytes))?,
        );
        self.binary_info
            .binary
            .get(start_us..end_us)
            .ok_or(Error::NotEnoughBytesError(addr, num_bytes))
    }

    pub fn is_addr_within_memory_image(&self, offset: u64) -> Result<bool> {
        // Use checked_add to avoid overflowing when binary_size is at the
        // top of the address space; an overflow conservatively means
        // "address is not within image".
        let Some(end) = self
            .binary_info
            .base_addr
            .checked_add(self.binary_info.binary_size)
        else {
            return Ok(false);
        };
        Ok(self.binary_info.base_addr <= offset && offset < end)
    }

    pub fn passes_code_filter(&self, address: Option<u64>) -> Result<bool> {
        match address {
            Some(addr) => {
                for (start, end) in &self.binary_info.code_areas {
                    if *start <= addr && *end > addr {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    pub fn dereference_dword(&self, addr: u64) -> Result<u64> {
        if !self.is_addr_within_memory_image(addr)? {
            return Err(Error::DereferenceError(addr));
        }
        let rel_start_addr = addr - self.binary_info.base_addr;
        let rel_end_addr = rel_start_addr
            .checked_add(4)
            .ok_or(Error::DereferenceError(addr))?;
        if rel_end_addr > self.binary_info.binary_size {
            return Err(Error::DereferenceError(addr));
        }
        let (s, e) = (
            usize::try_from(rel_start_addr).map_err(|_| Error::DereferenceError(addr))?,
            usize::try_from(rel_end_addr).map_err(|_| Error::DereferenceError(addr))?,
        );
        let extracted_dword: &[u8; 4] = self
            .binary_info
            .binary
            .get(s..e)
            .ok_or(Error::DereferenceError(addr))?
            .try_into()?;
        Ok(u32::from_le_bytes(*extracted_dword) as u64)
    }

    pub fn dereference_qword(&self, addr: u64) -> Result<u64> {
        if !self.is_addr_within_memory_image(addr)? {
            return Err(Error::DereferenceError(addr));
        }
        let rel_start_addr = addr - self.binary_info.base_addr;
        let rel_end_addr = rel_start_addr
            .checked_add(8)
            .ok_or(Error::DereferenceError(addr))?;
        if rel_end_addr > self.binary_info.binary_size {
            return Err(Error::DereferenceError(addr));
        }
        let (s, e) = (
            usize::try_from(rel_start_addr).map_err(|_| Error::DereferenceError(addr))?,
            usize::try_from(rel_end_addr).map_err(|_| Error::DereferenceError(addr))?,
        );
        let extracted_qword: &[u8; 8] = self
            .binary_info
            .binary
            .get(s..e)
            .ok_or(Error::DereferenceError(addr))?
            .try_into()?;
        Ok(u64::from_le_bytes(*extracted_qword))
    }

    pub fn add_code_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
        self.code_refs_from
            .entry(addr_from)
            .or_default()
            .push(addr_to);
        self.code_refs_to
            .entry(addr_to)
            .or_default()
            .push(addr_from);
        Ok(())
    }

    pub fn add_data_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
        self.data_refs_from
            .entry(addr_from)
            .or_default()
            .push(addr_to);
        self.data_refs_to
            .entry(addr_to)
            .or_default()
            .push(addr_from);
        Ok(())
    }

    /// Per-block view of a function, used by `Function::new` to construct
    /// the public-facing `Instruction`s.
    pub fn get_blocks_as_decoded(
        &self,
        function_addr: &u64,
    ) -> Result<HashMap<u64, Vec<DecodedInsn>>> {
        let mut blocks = HashMap::new();
        let Some(func_blocks) = self.functions.get(function_addr) else {
            return Ok(blocks);
        };
        for block in func_blocks {
            if block.is_empty() {
                continue;
            }
            blocks.insert(block[0].offset, block.clone());
        }
        Ok(blocks)
    }

    pub fn get_block_refs(&self, func_addr: &u64) -> Result<HashMap<u64, Vec<u64>>> {
        let mut block_refs = HashMap::new();
        let mut ins_addrs = HashSet::new();
        let Some(blocks) = self.functions.get(func_addr) else {
            return Ok(block_refs);
        };
        for block in blocks {
            for ins in block {
                ins_addrs.insert(ins.offset);
            }
        }
        for block in blocks {
            if block.is_empty() {
                continue;
            }
            let last_ins_addr = block[block.len() - 1].offset;
            if self.code_refs_from.contains_key(&last_ins_addr) {
                let mut code_refs_from_a = HashSet::new();
                for dd in &self.code_refs_from[&last_ins_addr] {
                    code_refs_from_a.insert(*dd);
                }
                let mut verified_refs = vec![];
                for dd in ins_addrs.intersection(&code_refs_from_a) {
                    verified_refs.push(*dd);
                }
                if !verified_refs.is_empty() {
                    block_refs.insert(block[0].offset, verified_refs);
                }
            }
        }
        Ok(block_refs)
    }

    pub fn get_in_refs(&self, func_addr: &u64) -> Result<Vec<u64>> {
        if self.code_refs_to.contains_key(func_addr) {
            return Ok(self.code_refs_to[func_addr].clone());
        }
        Ok(vec![])
    }

    pub fn get_out_refs(&self, func_addr: &u64) -> Result<HashMap<u64, Vec<u64>>> {
        let mut ins_addrs = HashSet::new();
        let mut code_refs = vec![];
        let mut out_refs: HashMap<u64, u64> = HashMap::new();
        let Some(blocks) = self.functions.get(func_addr) else {
            return Ok(HashMap::new());
        };
        for block in blocks {
            for ins in block {
                let ins_addr = ins.offset;
                ins_addrs.insert(ins_addr);
                if self.code_refs_from.contains_key(&ins_addr) {
                    for to_addr in &self.code_refs_from[&ins_addr] {
                        code_refs.push((ins_addr, to_addr))
                    }
                }
            }
        }
        if ins_addrs.contains(func_addr) {
            ins_addrs.remove(func_addr);
        }
        let max_addr = self.binary_info.base_addr + self.binary_info.binary_size;
        let mut image_refs = vec![];
        for reff in code_refs {
            if &self.binary_info.base_addr <= reff.1 && reff.1 <= &max_addr {
                image_refs.push(reff);
            }
        }
        for reff in image_refs {
            if ins_addrs.contains(reff.1) {
                continue;
            }
            out_refs.entry(reff.0).or_insert(*reff.1);
        }
        let mut res: HashMap<u64, Vec<u64>> = HashMap::new();
        for (src, dst) in &out_refs {
            res.entry(*src).or_default().push(*dst);
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct Disassembler {
    common_start_bytes: HashMap<u32, HashMap<u8, u32>>,
    tailcall_analyzer: TailCallAnalyser,
    indirect_call_analyser: IndirectCallAnalyser,
    jumptable_analyzer: JumpTableAnalyser,
    fc_manager: FunctionCandidateManager,
    tfidf: MnemonicTfIdf,
    pub disassembly: DisassemblyResult,
    label_providers: Vec<LabelProvider>,
}

impl Disassembler {
    pub fn get_bitmask(&self) -> u64 {
        0xFFFFFFFFFFFFFFFF
    }

    pub fn new() -> Result<Disassembler> {
        let mut res = Disassembler {
            common_start_bytes: HashMap::new(),
            tailcall_analyzer: TailCallAnalyser::new(),
            indirect_call_analyser: IndirectCallAnalyser::new(),
            jumptable_analyzer: JumpTableAnalyser::new(),
            fc_manager: FunctionCandidateManager::new(),
            tfidf: MnemonicTfIdf::new(),
            disassembly: DisassemblyResult::new(),
            label_providers: label_providers::init()?,
        };
        res.common_start_bytes.insert(
            32,
            hashmap! {0x55 => 8334,
            0x6a => 758,
            0x56 => 756,
            0x51 => 312,
            0x8d => 566,
            0x83 => 558,
            0x53 => 548},
        );
        res.common_start_bytes.insert(
            64,
            hashmap! {0x48 => 1341,
            0x40 => 349,
            0x4c => 59,
            0x33 => 56,
            0x44 => 18,
            0x45 => 17,
            0xe9 => 16},
        );
        Ok(res)
    }

    pub fn load_file(file_name: &str) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(file_name)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    fn determine_bitness(&mut self) -> Result<u32> {
        let binary = &self.disassembly.binary_info.binary;
        let mut candidate_first_bytes: HashMap<u32, HashMap<u8, u32>> =
            [(32, HashMap::new()), (64, HashMap::new())]
                .iter()
                .cloned()
                .collect();
        for bitness in [32, 64] {
            for call_match in BITNESS.find_iter(binary) {
                if binary.len() - call_match.start() > 5 {
                    let packed_call: &[u8; 4] =
                        &binary[call_match.start() + 1..call_match.start() + 5].try_into()?;
                    let rel_call_offset = i32::from_le_bytes(*packed_call);
                    let call_destination = rel_call_offset
                        .overflowing_add(call_match.start() as i32)
                        .0
                        .overflowing_add(5)
                        .0;
                    if call_destination > 0 && (call_destination as usize) < binary.len() {
                        let first_byte = binary[call_destination as usize];
                        if let Some(s) = candidate_first_bytes.get_mut(&bitness) {
                            *s.entry(first_byte).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        let mut score: HashMap<u32, f32> = [(32, 0.0), (64, 0.0)].iter().cloned().collect();
        for bitness in [32, 64] {
            for candidate_sequence in candidate_first_bytes[&(bitness as u32)].keys() {
                for (common_sequence, sequence_score) in &self.common_start_bytes[&(bitness as u32)]
                {
                    if candidate_sequence == common_sequence {
                        *score
                            .get_mut(&(bitness as u32))
                            .ok_or(Error::LogicError(file!(), line!()))? +=
                            *sequence_score as f32 * 1.0;
                    }
                }
            }
        }
        let total_score = std::cmp::max((score[&32] + score[&64]) as u32, 1);
        *score
            .get_mut(&32)
            .ok_or(Error::LogicError(file!(), line!()))? /= total_score as f32;
        *score
            .get_mut(&64)
            .ok_or(Error::LogicError(file!(), line!()))? /= total_score as f32;
        if score[&32] < score[&64] {
            Ok(64)
        } else {
            Ok(32)
        }
    }

    pub fn disassemble_file(
        file_name: &str,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        data: Option<&Vec<u8>>,
    ) -> Result<DisassemblyReport> {
        let mut disassembler = Disassembler::new()?;
        let file_content = match data {
            Some(d) => d.to_vec(),
            _ => Disassembler::load_file(file_name)?,
        };
        let mut binary_info = BinaryInfo::new();
        binary_info.init(&file_content)?;
        binary_info.file_path = file_name.to_string();
        match Object::parse(&file_content)? {
            Object::Elf(elf) => {
                binary_info.file_format = FileFormat::ELF;
                binary_info.base_addr = elf::get_base_address(&file_content)?;
                binary_info.bitness = elf::get_bitness(&file_content)?;
                binary_info.file_architecture = match binary_info.bitness {
                    64 => FileArchitecture::AMD64,
                    _ => FileArchitecture::I386,
                };
                binary_info.code_areas = elf::get_code_areas(&file_content, &elf)?;
                binary_info.sections = elf
                    .section_headers
                    .iter()
                    .map(|s| {
                        (
                            elf.shdr_strtab
                                .get_at(s.sh_name)
                                .unwrap_or("..")
                                .to_string(),
                            s.sh_addr,
                            s.sh_size as usize,
                        )
                    })
                    .collect();
                binary_info.binary = elf::map_binary(&binary_info.raw_data)?;
                binary_info.binary_size = binary_info.binary.len() as u64;
            }
            Object::PE(pe) => {
                binary_info.file_format = FileFormat::PE;
                binary_info.base_addr = pe::get_base_address(&file_content)?;
                binary_info.bitness = pe::get_bitness(&file_content)?;
                binary_info.file_architecture = match binary_info.bitness {
                    64 => FileArchitecture::AMD64,
                    _ => FileArchitecture::I386,
                };
                binary_info.code_areas = pe::get_code_areas(&file_content, &pe)?;
                binary_info.sections = pe
                    .sections
                    .iter()
                    .map(|s| {
                        (
                            std::str::from_utf8(&s.name).unwrap_or("").to_string(),
                            s.virtual_address as u64,
                            s.virtual_size as usize,
                        )
                    })
                    .collect();
                binary_info.imports = pe
                    .imports
                    .iter()
                    .map(|s| (s.dll.to_string(), s.name.to_string(), s.offset))
                    .collect();
                binary_info.exports = pe
                    .exports
                    .iter()
                    .map(|s| {
                        let forward = match s.reexport {
                            Some(goblin::pe::export::Reexport::DLLName { export: _, lib }) => {
                                Some(lib.to_string())
                            }
                            Some(goblin::pe::export::Reexport::DLLOrdinal { ordinal: _, lib }) => {
                                Some(lib.to_string())
                            }
                            None => None,
                        };
                        (s.name.unwrap_or("").to_string(), s.rva, forward)
                    })
                    .collect();
                binary_info.binary = pe::map_binary(&binary_info.raw_data)?;
                binary_info.binary_size = binary_info.binary.len() as u64;
            }
            _ => return Err(Error::UnsupportedFormatError),
        }
        disassembler.analyse_buffer(binary_info, high_accuracy, resolve_tailcalls)?;
        let report = DisassemblyReport::new(&mut disassembler.disassembly)?;
        Ok(report)
    }

    fn get_symbol_candidates(&self) -> Result<Vec<u64>> {
        let mut symbol_offsets: HashSet<u64> = HashSet::new();
        for provider in &self.label_providers {
            if !provider.is_symbol_provider()? {
                continue;
            }
            for s in (provider.get_functions_symbols()?).keys() {
                symbol_offsets.insert(*s);
            }
        }
        Ok(symbol_offsets.iter().copied().collect())
    }

    pub fn analyse_buffer(
        &mut self,
        bin: BinaryInfo,
        high_accuracy: bool,
        resolve_tailcalls: bool,
    ) -> Result<&DisassemblyResult> {
        self.update_label_providers(&bin)?;
        self.disassembly.init(bin)?;
        if self.disassembly.binary_info.file_format == FileFormat::ELF {
            match elf::extract_elf_dynamic_apis(&self.disassembly.binary_info.raw_data) {
                Ok(elf_apis) => {
                    for (addr, (dll, api)) in elf_apis {
                        let api_entry = label_providers::ApiEntry {
                            referencing_addr: HashSet::new(),
                            dll_name: dll,
                            api_name: api,
                        };
                        self.disassembly.apis.insert(addr, api_entry);
                    }
                    if let Err(e) = self.disassembly.init_api_refs() {
                        eprintln!("Error initializing ELF API references: {e:?}");
                    }
                }
                Err(e) => eprintln!("Error extracting ELF APIs: {e:?}"),
            }
        }

        if ![32u32, 64u32].contains(&self.disassembly.binary_info.bitness) {
            self.disassembly.binary_info.bitness = self.determine_bitness()?;
        }
        self.tailcall_analyzer.init()?;
        self.indirect_call_analyser.init()?;
        self.jumptable_analyzer.init(&self.disassembly)?;
        self.fc_manager.symbol_addresses = self.get_symbol_candidates()?;
        self.fc_manager.init(&self.disassembly)?;
        self.tfidf.init(self.disassembly.binary_info.bitness)?;
        let queue = self.fc_manager.get_queue()?;
        let mut state = None;
        for addr in queue.clone() {
            state = self.analyse_function(addr, false, high_accuracy).ok()
        }
        let queue2 = self.fc_manager.get_queue()?;
        for addr in queue2 {
            if queue.contains(&addr) {
                continue;
            }
            state = self.analyse_function(addr, false, high_accuracy).ok()
        }
        let mut next_gap = 0;
        while let Ok(gap_candidate) = self
            .fc_manager
            .next_gap_candidate(Some(next_gap), &self.disassembly)
        {
            state = self
                .analyse_function(gap_candidate, true, high_accuracy)
                .ok();
            if !self.disassembly.functions.contains_key(&gap_candidate) {
                self.fc_manager.update_analysis_aborted(
                    &gap_candidate,
                    "Gap candidate did not fulfil function criteria.",
                )?;
            }
            next_gap = self.fc_manager.get_next_gap(true, &self.disassembly)?;
        }

        if resolve_tailcalls && let Some(s) = &mut state {
            let tailcalled_functions = TailCallAnalyser::resolve_tailcalls(self, s, high_accuracy)?;
            for addr in tailcalled_functions {
                self.fc_manager
                    .add_tailcall_candidate(&addr, &self.disassembly)?;
            }
        }
        self.disassembly.failed_analysis_addr = self.fc_manager.get_aborted_candidates()?;

        for (addr, candidate) in &mut self.fc_manager.candidates {
            if self.disassembly.functions.contains_key(addr) {
                let function_blocks = self.disassembly.get_blocks_as_decoded(addr)?;
                let function_tfidf = self.tfidf.get_tfidf_from_blocks(&function_blocks)?;
                candidate.set_tfidf(function_tfidf)?;
                candidate.init_confidence()?;
            }
            self.disassembly.candidates.insert(*addr, candidate.clone());
        }
        Ok(&self.disassembly)
    }

    fn get_disasm_window_buffer(&self, addr: u64) -> Vec<u8> {
        if addr < self.disassembly.binary_info.base_addr
            || addr
                >= self.disassembly.binary_info.base_addr
                    + self.disassembly.binary_info.binary.len() as u64
        {
            return vec![];
        }
        let relative_start = (addr - self.disassembly.binary_info.base_addr) as usize;
        let len = self.disassembly.binary_info.binary.len();
        let relative_end = (relative_start + 15).min(len);
        self.disassembly.binary_info.binary[relative_start..relative_end].to_vec()
    }

    fn handle_call_target(
        &self,
        from_addr: u64,
        to_addr: u64,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        if self.disassembly.is_addr_within_memory_image(to_addr)? {
            state.add_code_ref(from_addr, to_addr, false)?;
        }
        if state.start_addr == to_addr {
            state.set_recursion(true)?;
        }
        Ok(())
    }

    fn handle_api_target(
        &mut self,
        from_addr: u64,
        to_addr: u64,
        dereferenced: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        if to_addr != 0 {
            let (dll, api) = self.resolve_api(to_addr, dereferenced)?;
            if dll.is_some() || api.is_some() {
                self.update_api_information(from_addr, dereferenced, &dll, &api)?;
                return Ok((dll, api));
            }
        }
        Ok((None, None))
    }

    fn get_referenced_addr(&self, op_str: &str) -> Result<u64> {
        let referenced_addr = REF_ADDR.find_iter(op_str.as_bytes()).next();
        if let Some(ref_addr) = referenced_addr {
            let z = u64::from_str_radix(std::str::from_utf8(&ref_addr.as_bytes()[2..])?, 16)?;
            return Ok(z);
        }
        Ok(0)
    }

    #[allow(unused_assignments)]
    fn get_referenced_addr_sign(&self, op_str: &str) -> Result<i64> {
        let mut number = 0;
        let number_hex = RE_NUMBER_HEX_SIGN.captures(op_str);
        if let Some(n) = number_hex {
            number = i64::from_str_radix(&n["num"][2..], 16)?;
            if &n["sign"] == "-" {
                number *= -1;
            }
            return Ok(number);
        }
        Ok(0)
    }

    fn resolve_api(
        &self,
        to_address: u64,
        api_address: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        for provider in &self.label_providers {
            if !provider.is_api_provider()? {
                continue;
            }
            let res = provider.get_api(to_address, api_address);
            if let Ok((None, None)) = res {
                continue;
            } else {
                return res;
            }
        }
        Ok((None, None))
    }

    fn is_plt_got_address(&self, addr: u64) -> Result<bool> {
        for (section_name, section_start, section_size) in &self.disassembly.binary_info.sections {
            if section_name.contains(".plt") || section_name.contains(".got") {
                let section_end = section_start + *section_size as u64;
                if addr >= *section_start && addr < section_end {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn analyze_call_instruction(
        &mut self,
        ins: &DecodedInsn,
        op_str: &str,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = ins.offset;
        let i_size = ins.length;
        state.set_leaf(false)?;

        if op_str.starts_with("dword ptr [") {
            if op_str.starts_with("dword ptr [0x") {
                let call_destination = self.get_referenced_addr(op_str)?;
                if let Ok(dereferenced) = self.disassembly.dereference_dword(call_destination) {
                    state.add_code_ref(i_address, dereferenced, false)?;
                    self.handle_call_target(i_address, dereferenced, state)?;
                    self.handle_api_target(i_address, call_destination, dereferenced)?;
                }
            }
        } else if op_str.starts_with("qword ptr [rip") {
            let rip = i_address + i_size as u64;
            let call_destination = ((rip as i64) + self.get_referenced_addr_sign(op_str)?) as u64;
            if let Some((dll, api)) = self.disassembly.addr_to_api.get(&call_destination) {
                let mut api_entry = label_providers::ApiEntry {
                    referencing_addr: HashSet::new(),
                    dll_name: dll.clone(),
                    api_name: api.clone(),
                };
                api_entry.referencing_addr.insert(i_address);
                self.disassembly.apis.insert(call_destination, api_entry);
            }
            state.add_code_ref(i_address, call_destination, false)?;
            if let Ok(dereferenced) = self.disassembly.dereference_qword(call_destination) {
                self.handle_api_target(i_address, call_destination, dereferenced)?;
            }
        } else if op_str.starts_with("0x") {
            let call_destination = self.get_referenced_addr(op_str)?;
            if self.disassembly.binary_info.file_format == FileFormat::ELF
                && let Ok(Some((dll, api))) = self.resolve_elf_thunk(call_destination)
            {
                let mut api_entry = label_providers::ApiEntry {
                    referencing_addr: HashSet::new(),
                    dll_name: dll.clone(),
                    api_name: api.clone(),
                };
                api_entry.referencing_addr.insert(i_address);
                self.disassembly.apis.insert(call_destination, api_entry);
                self.disassembly
                    .addr_to_api
                    .insert(call_destination, (dll.clone(), api.clone()));
            }
            self.handle_call_target(i_address, call_destination, state)?;
            self.handle_api_target(i_address, call_destination, call_destination)?;
        } else if REGS_32BIT.contains(&op_str.to_lowercase().as_str())
            || REGS_64BIT.contains(&op_str.to_lowercase().as_str())
        {
            state.call_register_ins.push(i_address);
        }
        Ok(())
    }

    fn resolve_elf_thunk(
        &self,
        thunk_addr: u64,
    ) -> Result<Option<(Option<String>, Option<String>)>> {
        if !self.disassembly.is_addr_within_memory_image(thunk_addr)? {
            return Ok(None);
        }
        if let Some((dll, api)) = self.disassembly.addr_to_api.get(&thunk_addr) {
            return Ok(Some((dll.clone(), api.clone())));
        }
        let rel_addr = thunk_addr - self.disassembly.binary_info.base_addr;
        if rel_addr + 16 > self.disassembly.binary_info.binary_size {
            return Ok(None);
        }
        let bytes = &self.disassembly.binary_info.binary[rel_addr as usize..rel_addr as usize + 16];
        for i in 0..12 {
            if i + 5 < bytes.len() && bytes[i] == 0xFF && bytes[i + 1] == 0x25 {
                let offset =
                    i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                let rip = thunk_addr + (i as u64) + 6;
                let got_addr = (rip as i64 + offset as i64) as u64;
                if let Some((dll, api)) = self.disassembly.addr_to_api.get(&got_addr) {
                    return Ok(Some((dll.clone(), api.clone())));
                } else {
                    for candidate_addr in self.disassembly.addr_to_api.keys() {
                        let diff = (*candidate_addr).abs_diff(got_addr);
                        if diff <= 8
                            && let Some((dll, api)) =
                                self.disassembly.addr_to_api.get(candidate_addr)
                        {
                            return Ok(Some((dll.clone(), api.clone())));
                        }
                    }
                }
                break;
            }
        }
        Ok(None)
    }

    fn analyze_jmp_instruction(
        &mut self,
        ins: &DecodedInsn,
        op_str: &str,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = ins.offset;
        let i_size = ins.length;

        if op_str.contains(':') {
            // long-jmp
        } else if op_str.starts_with("dword ptr [0x") {
            let jump_destination = self.get_referenced_addr(op_str)?;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_dword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if op_str.starts_with("qword ptr [rip") {
            let rip = i_address + i_size as u64;
            let jump_destination = ((rip as i64) + self.get_referenced_addr_sign(op_str)?) as u64;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_qword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if let Some(stripped) = op_str.strip_prefix("0x") {
            let jump_destination = self.get_referenced_addr(op_str)?;
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                // tailcall?
            } else {
                let addr_to = u64::from_str_radix(stripped, 16)?;
                if !state.is_first_instruction()?
                    && self.disassembly.is_addr_within_memory_image(addr_to)?
                    && self.disassembly.passes_code_filter(Some(addr_to))?
                {
                    state.add_block_to_queue(addr_to)?;
                }
                state.add_code_ref(i_address, addr_to, true)?;
            }
        } else {
            let jumptable_targets = self
                .jumptable_analyzer
                .get_jump_targets(ins, op_str, self, state)?;
            for target in jumptable_targets {
                if self.disassembly.is_addr_within_memory_image(target)? {
                    state.add_block_to_queue(target)?;
                    state.add_code_ref(i_address, target, true)?;
                }
            }
        }
        state.set_next_instruction_reachable(false)?;
        state.set_block_ending_instruction(true)?;
        Ok(tailcall_jumps)
    }

    pub fn analyze_loop_instruction(
        &self,
        ins: &DecodedInsn,
        op_str: &str,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = ins.offset;
        let i_size = ins.length;
        // Use the already-parsed jump_destination rather than re-parsing
        // `op_str[2..]` (which previously panicked on `op_str.len() < 2`
        // or operands that didn't start with `0x`).
        if let Ok(jump_destination) = self.get_referenced_addr(op_str) {
            state.add_code_ref(i_address, jump_destination, true)?;
        }
        state.add_block_to_queue(i_address.wrapping_add(i_size as u64))?;
        state.set_block_ending_instruction(true)?;
        Ok(())
    }

    pub fn analyze_cond_jmp_instruction(
        &self,
        ins: &DecodedInsn,
        op_str: &str,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = ins.offset;
        let i_size = ins.length;
        state.add_block_to_queue(i_address.wrapping_add(i_size as u64))?;
        if let Ok(jump_destination) = self.get_referenced_addr(op_str) {
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                // tailcall?
            } else {
                state.add_block_to_queue(jump_destination)?;
            }
            state.add_code_ref(i_address, jump_destination, true)?;
        }
        state.set_block_ending_instruction(true)?;
        Ok(tailcall_jumps)
    }

    pub fn analyze_end_instruction(&self, state: &mut FunctionAnalysisState) -> Result<()> {
        state.set_sanely_ending(true)?;
        state.set_next_instruction_reachable(false)?;
        state.set_block_ending_instruction(true)?;
        Ok(())
    }

    /// Decode a 15-byte window with iced. Returns owned DecodedInsn values.
    fn decode_window(&self, ip: u64) -> Vec<DecodedInsn> {
        let buf = self.get_disasm_window_buffer(ip);
        if buf.is_empty() {
            return vec![];
        }
        let mut decoder = Decoder::with_ip(
            self.disassembly.binary_info.bitness,
            &buf,
            ip,
            DecoderOptions::NONE,
        );
        let mut out = Vec::with_capacity(4);
        while decoder.can_decode() {
            let pos_before = decoder.position();
            let insn = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            let len = decoder.position() - pos_before;
            let bytes = buf[pos_before..pos_before + len].to_vec();
            out.push(DecodedInsn {
                offset: insn.ip(),
                length: len as u32,
                iced: insn,
                bytes,
            });
        }
        out
    }

    fn analyse_function(
        &mut self,
        start_addr: u64,
        as_gap: bool,
        high_accuracy: bool,
    ) -> Result<FunctionAnalysisState> {
        self.tailcall_analyzer.init()?;
        let mut state = FunctionAnalysisState::new(start_addr)?;
        if state.is_processed_function(&self.disassembly) {
            self.fc_manager.update_analysis_aborted(
                &start_addr,
                &format!(
                    "collision with existing code of function 0x{:08x}",
                    self.disassembly.ins2fn[&start_addr]
                ),
            )?;
            return Err(Error::CollisionError(self.disassembly.ins2fn[&start_addr]));
        }
        let mut fmt = capstone_compat_formatter();

        while state.has_unprocessed_blocks() {
            state.choose_next_block()?;
            let mut cache_pos: usize = 0;
            let start_block = state.block_start;
            let mut cache = self.decode_window(start_block);
            let mut previous_address: Option<u64> = None;
            let mut previous_mnemonic_str: Option<String> = None;
            let mut previous_op_str: Option<String> = None;

            loop {
                let mut exit_flag = false;
                for ins in &cache {
                    let i_address = ins.offset;
                    let i_size = ins.length;
                    let mnemonic_enum = ins.iced.mnemonic();
                    let mut mnemonic_str = String::new();
                    fmt.format_mnemonic(&ins.iced, &mut mnemonic_str);
                    let op_str = if ins.iced.op_count() == 0 {
                        String::new()
                    } else {
                        let mut s = String::new();
                        fmt.format_all_operands(&ins.iced, &mut s);
                        s
                    };

                    cache_pos += i_size as usize;
                    state.set_next_instruction_reachable(true)?;

                    if ins.bytes == b"\x00\x00" {
                        state.suspicious_ins_count += 1;
                        if state.suspicious_ins_count > 1 {
                            self.fc_manager.update_analysis_aborted(
                                &start_addr,
                                &format!("too many suspicious instructions 0x{i_address:08x}"),
                            )?;
                            return Ok(state);
                        }
                    }

                    let fc = ins.iced.flow_control();
                    if matches!(fc, FlowControl::Call | FlowControl::IndirectCall) {
                        self.analyze_call_instruction(ins, &op_str, &mut state)?;
                    } else if matches!(
                        fc,
                        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
                    ) {
                        let jumps = self.analyze_jmp_instruction(ins, &op_str, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if matches!(
                        mnemonic_enum,
                        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne
                    ) {
                        self.analyze_loop_instruction(ins, &op_str, &mut state)?;
                    } else if matches!(fc, FlowControl::ConditionalBranch) {
                        let jumps = self.analyze_cond_jmp_instruction(ins, &op_str, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if matches!(fc, FlowControl::Return) {
                        self.analyze_end_instruction(&mut state)?;
                        if previous_address.is_some()
                            && previous_address != Some(0)
                            && previous_mnemonic_str.as_deref() == Some("push")
                            && let Some(prev_op) = previous_op_str.as_ref()
                        {
                            let push_ret_destination = self.get_referenced_addr(prev_op)?;
                            if self
                                .disassembly
                                .is_addr_within_memory_image(push_ret_destination)?
                            {
                                state.add_block_to_queue(push_ret_destination)?;
                                state.add_code_ref(i_address, push_ret_destination, true)?;
                            }
                        }
                    } else if matches!(mnemonic_enum, Mnemonic::Int3 | Mnemonic::Hlt) {
                        self.analyze_end_instruction(&mut state)?;
                    } else if let Some(prev) = previous_address
                        && prev != 0
                        && i_address != start_addr
                        && previous_mnemonic_str.as_deref() == Some("call")
                    {
                        let instruction_sequence = self.decode_window(i_address);
                        let is_align = self
                            .fc_manager
                            .is_alignment_sequence(&instruction_sequence)?;
                        let is_cand = self.fc_manager.is_function_candidate(i_address)?;
                        if is_align || is_cand {
                            state.set_block_ending_instruction(true)?;
                            state.end_block()?;
                            state.set_sanely_ending(true)?;
                            if is_align {
                                let next_aligned_address = prev + (16 - prev % 16);
                                self.fc_manager.add_candidate(
                                    next_aligned_address,
                                    true,
                                    None,
                                    &self.disassembly,
                                )?;
                            }
                            exit_flag = true;
                            break;
                        }
                    }

                    previous_address = Some(i_address);
                    previous_mnemonic_str = Some(mnemonic_str.clone());
                    previous_op_str = Some(op_str.clone());
                    if !self.disassembly.code_map.contains_key(&i_address)
                        && !self.disassembly.data_map.contains(&i_address)
                        && !state.is_processed(&i_address)?
                    {
                        state.add_instruction(ins.clone())?;
                    } else if self.disassembly.code_map.contains_key(&i_address) {
                        state.set_block_ending_instruction(true)?;
                        state.set_collision(true)?;
                    } else {
                        state.set_block_ending_instruction(true)?;
                    }
                    if state.is_block_ending_instruction()? {
                        state.end_block()?;
                        exit_flag = true;
                        break;
                    }
                }
                if !exit_flag {
                    cache = self.decode_window(state.block_start + cache_pos as u64);
                    if cache.is_empty() {
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
        }
        state.label = self.resolve_symbol(state.start_addr)?;
        if let Ok(_analysis_result) = state.finalize_analysis(as_gap, &mut self.disassembly) {
            let (api_e, cand_e) = self
                .indirect_call_analyser
                .resolve_register_calls(self, &mut state, 4)?;
            for a in api_e {
                match self.disassembly.apis.get_mut(&a.0) {
                    Some(s) => {
                        s.referencing_addr.extend(a.1.referencing_addr.clone());
                    }
                    None => {
                        self.disassembly.apis.insert(a.0, a.1);
                    }
                }
            }
            for a in cand_e {
                self.fc_manager
                    .add_candidate(a.0, false, Some(a.1), &self.disassembly)?;
            }
            TailCallAnalyser::finalize_function(self, &state)?;
        }
        self.fc_manager.update_analysis_finished(&start_addr)?;
        if high_accuracy {
            self.fc_manager.update_candidates(&state)?;
        }
        Ok(state)
    }

    fn update_api_information(
        &mut self,
        from_addr: u64,
        to_addr: u64,
        dll: &Option<String>,
        api: &Option<String>,
    ) -> Result<()> {
        let mut api_entry = label_providers::ApiEntry {
            referencing_addr: HashSet::new(),
            dll_name: dll.clone(),
            api_name: api.clone(),
        };
        if self.disassembly.apis.contains_key(&to_addr) {
            api_entry = self.disassembly.apis[&to_addr].clone();
        }
        if !api_entry.referencing_addr.contains(&from_addr) {
            api_entry.referencing_addr.insert(from_addr);
        }
        self.disassembly.apis.insert(to_addr, api_entry);
        Ok(())
    }

    pub fn resolve_symbol(&self, address: u64) -> Result<String> {
        for provider in &self.label_providers {
            if !provider.is_symbol_provider()? {
                continue;
            }
            if let Ok(result) = provider.get_symbol(address) {
                return Ok(result);
            }
        }
        Ok(String::new())
    }

    fn update_label_providers(&mut self, bi: &BinaryInfo) -> Result<()> {
        for provider in &mut self.label_providers {
            provider.update(bi)?;
        }
        Ok(())
    }
}
