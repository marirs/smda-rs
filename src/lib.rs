#![allow(dead_code)]
#![allow(clippy::type_complexity)]
#[macro_use]
extern crate maplit;
#[macro_use]
extern crate lazy_static;

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

use capstone::prelude::*;
use data_encoding::HEXUPPER;
use function_analysis_state::FunctionAnalysisState;
use function_candidate::FunctionCandidate;
use function_candidate_manager::FunctionCandidateManager;
use goblin::Object;
use indirect_call_analyser::IndirectCallAnalyser;
use jump_table_analyser::JumpTableAnalyser;
use label_provider::LabelProvider;
use mnemonic_tf_idf::MnemonicTfIdf;
use regex::bytes::Regex as BytesRegex;
use report::DisassemblyReport;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    io::Read,
    time::SystemTime,
};
use tail_call_analyser::TailCallAnalyser;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

lazy_static! {
    static ref BITNESS: BytesRegex = BytesRegex::new(r"(?-u)\xE8").unwrap();
    static ref REF_ADDR: BytesRegex = BytesRegex::new(r"(?-u)0x[a-fA-F0-9]+").unwrap();
    static ref RE_NUMBER_HEX_SIGN: regex::Regex = regex::Regex::new(r"(?P<sign>[+\-]) (?P<num>0x[a-fA-F0-9]+)").unwrap();
}

static CALL_INS: &[Option<&str>] = &[Some("call"), Some("ncall")];
static CJMP_INS: &[Option<&str>] = &[
    Some("je"),
    Some("jne"),
    Some("js"),
    Some("jns"),
    Some("jp"),
    Some("jnp"),
    Some("jo"),
    Some("jno"),
    Some("jl"),
    Some("jle"),
    Some("jg"),
    Some("jge"),
    Some("jb"),
    Some("jbe"),
    Some("ja"),
    Some("jae"),
    Some("jcxz"),
    Some("jecxz"),
    Some("jrcxz"),
];
static LOOP_INS: &[Option<&str>] = &[Some("loop"), Some("loopne"), Some("loope")];
static JMP_INS: &[Option<&str>] = &[Some("jmp"), Some("ljmp")];
static RET_INS: &[Option<&str>] = &[Some("ret"), Some("retn"), Some("retf"), Some("iret")];
static END_INS: &[Option<&str>] = &[
    Some("ret"),
    Some("retn"),
    Some("retf"),
    Some("iret"),
    Some("int3"),
    Some("hlt"),
];
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
    file_format: FileFormat,
    file_architecture: FileArchitecture,
    base_addr: u64,
    binary: Vec<u8>,
    raw_data: Vec<u8>,
    binary_size: u64,
    bitness: u32,
    code_areas: Vec<(u64, u64)>,
    component: String,
    family: String,
    file_path: String,
    is_library: bool,
    is_buffer: bool,
    sha256: String,
    entry_point: u64,
    sections: Vec<(String, u64, usize)>,
    imports: Vec<(String, String, usize)>,
    exports: Vec<(String, usize, Option<String>)>,
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
            component: String::from(""),
            family: String::from(""),
            file_path: String::from(""),
            is_library: false,
            is_buffer: false,
            sha256: String::from(""),
            entry_point: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
        }
    }

    pub fn init(&mut self, content: &[u8]) -> Result<()> {
        //        self.binary = content.to_vec();
        self.raw_data = content.to_vec();
        self.binary_size = content.len() as u64;
        self.sha256 = BinaryInfo::sha256_digest(content)?;
        Ok(())
    }

    fn sha256_digest(content: &[u8]) -> Result<String> {
        let mut context = Context::new(&SHA256);
        context.update(content);
        Ok(HEXUPPER.encode(context.finish().as_ref()))
    }

    pub fn get_sections(&self) -> Result<Vec<(String, u64, u64)>> {
        match Object::parse(&self.raw_data)? {
            Object::PE(pe) => {
                let mut res = vec![];
                for sect in pe.sections {
                    res.push((
                        std::str::from_utf8(&sect.name)?.to_string(),
                        sect.pointer_to_raw_data as u64,
                        (sect.pointer_to_raw_data + sect.size_of_raw_data) as u64,
                    ));
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
    binary_info: BinaryInfo,
    identified_alignment: usize,
    code_map: HashMap<u64, u64>,
    data_map: HashSet<u64>,
    //    errors:
    functions: HashMap<u64, Vec<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>>>,
    recursive_functions: HashSet<u64>,
    leaf_functions: HashSet<u64>,
    thunk_functions: HashSet<u64>,
    failed_analysis_addr: Vec<u64>,
    function_borders: HashMap<u64, (u64, u64)>,
    instructions: HashMap<u64, (String, u32)>,
    ins2fn: HashMap<u64, u64>,
    language: HashMap<i32, Vec<u8>>,
    data_refs_from: HashMap<u64, Vec<u64>>,
    data_refs_to: HashMap<u64, Vec<u64>>,
    code_refs_from: HashMap<u64, Vec<u64>>,
    code_refs_to: HashMap<u64, Vec<u64>>,
    apis: HashMap<u64, label_providers::ApiEntry>,
    addr_to_api: HashMap<u64, (Option<String>, Option<String>)>,
    function_symbols: HashMap<u64, String>,
    candidates: HashMap<u64, FunctionCandidate>,
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
        for function_addr in self.functions.keys() {
            for (k, v) in self.get_api_refs(function_addr)? {
                all_api_refs.insert(k, v);
            }
        }
        Ok(all_api_refs)
    }


    fn init_api_refs(&mut self) -> Result<()> {
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
                if let Some(_) = &api {
                    let canonical_addr = if addr >= self.binary_info.base_addr {
                        addr
                    } else {
                        self.binary_info.base_addr + addr
                    };

                    self.addr_to_api.insert(canonical_addr, (dll.clone(), api.clone()));
                }
            }
        }

        Ok(())
    }

    pub fn get_api_refs(&self, func_addr: &u64) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
        let mut api_refs = HashMap::new();

        for block in &self.functions[func_addr] {
            for ins in block {
                let ins_absolute_addr = self.binary_info.base_addr + ins.0;

                // METHOD 1: Direct search in addr_to_api
                if let Some((dll, api)) = self.addr_to_api.get(&ins_absolute_addr) {
                    println!("DEBUG: Found direct API for ins {}: {:?}:{:?}", ins_absolute_addr, dll, api);
                    api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                    continue;
                }

                // METHOD 2: for jumps, check if it's a jump or call
                if let Some(ref mnemonic) = ins.2 {
                    if mnemonic == "call" {
                        if let Some(target_addr) = self.extract_call_target(ins, self.binary_info.base_addr) {

                            // SEARCH IN addr_to_api
                            if let Some((dll, api)) = self.addr_to_api.get(&target_addr) {
                                // println!("DEBUG: Found target API {} -> {:?}:{:?}", target_addr, dll, api);
                                api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                                continue;
                            }

                            // SEARCH IN self.apis
                            if let Some(api_entry) = self.apis.get(&target_addr) {
                                // println!("DEBUG: Found API via thunk {} -> {:?}", target_addr, api_entry.api_name);
                                api_refs.insert(ins_absolute_addr, (api_entry.dll_name.clone(), api_entry.api_name.clone()));
                                continue;
                            }
                        }
                    }
                }
            }
        }

        Ok(api_refs)
    }

    fn extract_call_target(&self, instruction: &(u64, u32, Option<String>, Option<String>, Vec<u8>), base_addr: u64) -> Option<u64> {
        let (ins_addr, ins_size, mnemonic, op_str, _ins_bytes) = instruction;

        if let Some(mnem) = mnemonic {
            if mnem != "call" {
                return None;
            }
        } else {
            return None;
        }

        if let Some(operands) = op_str {
            // DIRECT CALL - call 0x12345
            if operands.starts_with("0x") {
                if let Ok(addr) = u64::from_str_radix(&operands[2..], 16) {
                    // println!("DEBUG: Direct call target: {}", addr);
                    return Some(addr);
                }
            }

            // DWORD-PTR - call dword ptr [0x12345]
            if operands.starts_with("dword ptr [0x") {
                let start = "dword ptr [0x".len();
                if let Some(end) = operands.find(']') {
                    if let Ok(addr) = u64::from_str_radix(&operands[start..end], 16) {
                        return Some(addr);
                    }
                }
            }

            // QWORD-PTR RIP-relative - call qword ptr [rip + 0x12345]
            if operands.starts_with("qword ptr [rip") {
                if let Some(plus_pos) = operands.find(" + 0x") {
                    let start = plus_pos + 5; // " + 0x".len()
                    if let Some(end) = operands[start..].find(']') {
                        if let Ok(offset) = u64::from_str_radix(&operands[start..start+end], 16) {
                            let rip = base_addr + ins_addr + *ins_size as u64;
                            let target = rip + offset;
                            return Some(target);
                        }
                    }
                } else if let Some(minus_pos) = operands.find(" - 0x") {
                    let start = minus_pos + 5; // " - 0x".len()
                    if let Some(end) = operands[start..].find(']') {
                        if let Ok(offset) = u64::from_str_radix(&operands[start..start+end], 16) {
                            let rip = base_addr + ins_addr + *ins_size as u64;
                            let target = rip - offset;
                            return Some(target);
                        }
                    }
                }
            }
        }

        None
    }

    pub fn get_confidence_threshold(&self) -> Result<f32> {
        Ok(self.confidence_threshold)
    }

    pub fn get_byte(&self, addr: u64) -> Result<u8> {
        if self.is_addr_within_memory_image(addr)? {
            return Ok(self.binary_info.binary[addr as usize - self.binary_info.base_addr as usize]);
        }
        Err(Error::LogicError(file!(), line!()))
    }

    pub fn get_raw_byte(&self, addr: u64) -> Result<u8> {
        Ok(self.binary_info.binary[addr as usize])
    }

    pub fn get_raw_bytes(&self, offset: u64, bytes: u64) -> Result<&[u8]> {
        Ok(&self.binary_info.binary[offset as usize..(offset + bytes) as usize])
    }

    pub fn get_bytes(&self, addr: u64, num_bytes: u64) -> Result<&[u8]> {
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            return Ok(&self.binary_info.binary
                [rel_start_addr as usize..(rel_start_addr + num_bytes) as usize]);
        }
        Err(Error::NotEnoughBytesError(addr, num_bytes))
    }

    pub fn is_addr_within_memory_image(&self, offset: u64) -> Result<bool> {
        let res = self.binary_info.base_addr <= offset
            && offset < self.binary_info.base_addr + self.binary_info.binary_size;
        Ok(res)
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
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            let rel_end_addr = rel_start_addr + 4;
            let extracted_dword: &[u8; 4] = &self.binary_info.binary
                [rel_start_addr as usize..rel_end_addr as usize]
                .try_into()?;
            return Ok(u32::from_le_bytes(*extracted_dword) as u64);
        }
        Err(Error::DereferenceError(addr))
    }

    pub fn dereference_qword(&self, addr: u64) -> Result<u64> {
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            let rel_end_addr = rel_start_addr + 8;
            if rel_end_addr > self.binary_info.binary_size {
                return Err(Error::DereferenceError(addr));
            }
            let extracted_dword: &[u8; 8] = &self.binary_info.binary
                [rel_start_addr as usize..rel_end_addr as usize]
                .try_into()?;
            return Ok(u64::from_le_bytes(*extracted_dword));
        }
        Err(Error::DereferenceError(addr))
    }

    pub fn add_code_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
        let mut refs_from = match self.code_refs_from.remove(&addr_from) {
            Some(v) => v,
            _ => vec![],
        };
        refs_from.push(addr_to);
        self.code_refs_from.insert(addr_from, refs_from);
        let mut refs_to = match self.code_refs_to.remove(&addr_to) {
            Some(v) => v,
            _ => vec![],
        };
        refs_to.push(addr_from);
        self.code_refs_to.insert(addr_to, refs_to.clone());
        Ok(())
    }

    pub fn add_data_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
        let mut refs_from = match self.data_refs_from.remove(&addr_from) {
            Some(v) => v,
            _ => vec![],
        };
        refs_from.push(addr_to);
        self.data_refs_from.insert(addr_from, refs_from);
        let mut refs_to = match self.data_refs_to.remove(&addr_to) {
            Some(v) => v,
            _ => vec![],
        };
        refs_to.push(addr_from);
        self.data_refs_to.insert(addr_to, refs_to.clone());
        Ok(())
    }

    pub fn get_blocks_as_dict(
        &self,
        function_addr: &u64,
    ) -> Result<HashMap<u64, Vec<(u64, String, String, Option<String>)>>> {
        let mut blocks = HashMap::new();
        for block in &self.functions[function_addr] {
            let mut instructions = vec![];
            for ins in block {
                instructions.push(self.transform_instruction(ins)?);
                blocks.insert(instructions[0].0, instructions.clone());
            }
        }
        Ok(blocks)
    }

    pub fn transform_instruction(
        &self,
        ins_tuple: &(u64, u32, Option<String>, Option<String>, Vec<u8>),
    ) -> Result<(u64, String, String, Option<String>)> {
        let (ins_addr, _, ins_mnem, ins_ops, ins_raw_bytes) = ins_tuple;
        Ok((
            *ins_addr,
            hex::encode(ins_raw_bytes),
            ins_mnem.as_ref().unwrap().to_string(),
            ins_ops.clone(),
        ))
    }

    pub fn get_block_refs(&self, func_addr: &u64) -> Result<HashMap<u64, Vec<u64>>> {
        let mut block_refs = HashMap::new();
        let mut ins_addrs = HashSet::new();
        for block in &self.functions[func_addr] {
            for ins in block {
                ins_addrs.insert(ins.0);
            }
        }
        for block in &self.functions[func_addr] {
            let last_ins_addr = block[block.len() - 1].0;
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
                    block_refs.insert(block[0].0, verified_refs);
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
        let mut out_refs = HashMap::new();
        for block in &self.functions[func_addr] {
            for ins in block {
                let ins_addr = ins.0;
                ins_addrs.insert(ins_addr);
                if self.code_refs_from.contains_key(&ins_addr) {
                    for to_addr in &self.code_refs_from[&ins_addr] {
                        code_refs.push((ins_addr, to_addr))
                    }
                }
            }
        }
        //# function may be recursive
        if ins_addrs.contains(func_addr) {
            ins_addrs.remove(func_addr);
        }
        //# reduce outrefs to addresses within the memory image
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
            out_refs.entry(reff.0).or_insert(reff.1);
        }
        let mut res: HashMap<u64, Vec<u64>> = HashMap::new();
        for (src, dst) in &out_refs {
            match res.get_mut(src) {
                Some(s) => {
                    s.push(**dst);
                }
                _ => {
                    res.insert(*src, vec![**dst]);
                }
            }
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
    disassembly: DisassemblyResult,
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
                            if let Some(ss) = s.get_mut(&first_byte) {
                                *ss += 1;
                            } else {
                                s.insert(first_byte, 1);
                            }
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
        //let file_content = Disassembler::load_file(file_name)?;
        let mut binary_info = BinaryInfo::new();
        binary_info.init(&file_content)?;
        binary_info.file_path = file_name.to_string();
        match Object::parse(&file_content)? {
            Object::Elf(elf) => {
                // println!("Parsing ELF file: {}", file_name);
                binary_info.file_format = FileFormat::ELF;
                binary_info.base_addr = elf::get_base_address(&file_content)?;
                binary_info.bitness = elf::get_bitness(&file_content)?;
                binary_info.file_architecture = match binary_info.bitness {
                    64 => FileArchitecture::AMD64,
                    32 => FileArchitecture::I386,
                    _ => FileArchitecture::I386,  // fallback
                };
                binary_info.code_areas = elf::get_code_areas(&file_content, &elf)?;
                binary_info.sections = elf
                    .section_headers
                    .iter()
                    .map(|s| {
                        (
                            if let Some(ss) = elf.shdr_strtab.get_at(s.sh_name) {
                                ss.to_string()
                            } else {
                                "..".to_string()
                            },
                            s.sh_addr,
                            s.sh_size as usize,
                        )
                    })
                    .collect();
                // binary_info.imports = elf
                //     .imports
                //     .iter()
                //     .map(|s| (s.dll.to_string(), s.name.to_string(), s.offset))
                //     .collect();
                // binary_info.exports = elf
                //     .exports
                //     .iter()
                //     .map(|s| (s.name.unwrap_or("").to_string(), s.offset))
                //     .collect();

                binary_info.binary = elf::map_binary(&binary_info.raw_data)?;
                binary_info.binary_size = binary_info.binary.len() as u64;
            }
            Object::PE(pe) => {
                binary_info.file_format = FileFormat::PE;
                binary_info.base_addr = pe::get_base_address(&file_content)?;
                binary_info.bitness = pe::get_bitness(&file_content)?;
                binary_info.code_areas = pe::get_code_areas(&file_content, &pe)?;
                binary_info.sections = pe
                    .sections
                    .iter()
                    .map(|s| {
                        (
                            std::str::from_utf8(&s.name).unwrap().to_string(),
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
            // for (s, _a) in provider.get_functions_symbols()? {
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
        //LOGGER.debug("Analyzing buffer with %d bytes @0x%08x",
        // binary_info.binary_size, binary_info.base_addr)
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
                        eprintln!("Error initializing ELF API references: {:?}", e);
                    }

                }
                Err(e) => {
                    eprintln!("Error extracting ELF APIs: {:?}", e);
                }
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
            state = match self.analyse_function(addr, false, high_accuracy) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        }
        //LOGGER.debug("Finished heuristical analysis, functions: %d", len(self.disassembly.functions))
        let queue2 = self.fc_manager.get_queue()?;
        for addr in queue2 {
            if queue.contains(&addr) {
                continue;
            }
            state = match self.analyse_function(addr, false, high_accuracy) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        }
        //# second pass, analyze remaining gaps for additional
        //# candidates in an iterative way
        let mut next_gap = 0;
        while let Ok(gap_candidate) = self
            .fc_manager
            .next_gap_candidate(Some(next_gap), &self.disassembly)
        {
            //LOGGER.debug("based on gap, performing function analysis of 0x%08x", gap_candidate)
            state = match self.analyse_function(gap_candidate, true, high_accuracy) {
                Ok(s) => {
                    if let Ok(_function_blocks) = s.get_blocks() {
                        //LOGGER.debug("+ got some blocks here -> 0x%08x", gap_candidate)
                    }
                    Some(s)
                }
                Err(_) => None,
            };
            if self.disassembly.functions.contains_key(&gap_candidate) {
                //LOGGER.debug("+++ YAY, is now a function! -> 0x%08x - 0x%08x", fn_min, fn_max)
                //start looking directly after our new function
            } else {
                self.fc_manager.update_analysis_aborted(
                    &gap_candidate,
                    "Gap candidate did not fulfil function criteria.",
                )?;
            }
            next_gap = self.fc_manager.get_next_gap(true, &self.disassembly)?;
        }
        //LOGGER.debug("Finished gap analysis, functions: %d", len(self.disassembly.functions))

        //# third pass, fix potential tailcall functions that were identified during analysis
        if resolve_tailcalls {
            if let Some(s) = &mut state {
                let tailcalled_functions =
                    TailCallAnalyser::resolve_tailcalls(self, s, high_accuracy)?;
                for addr in tailcalled_functions {
                    self.fc_manager
                        .add_tailcall_candidate(&addr, &self.disassembly)?;
                }
            }
            //LOGGER.debug("Finished tailcall analysis, functions.")
        }
        self.disassembly.failed_analysis_addr = self.fc_manager.get_aborted_candidates()?;

        //# package up and finish
        for (addr, candidate) in &mut self.fc_manager.candidates {
            if self.disassembly.functions.contains_key(addr) {
                let function_blocks = self.disassembly.get_blocks_as_dict(addr)?;
                let function_tfidf = self.tfidf.get_tfidf_from_blocks(&function_blocks)?;
                candidate.set_tfidf(function_tfidf)?;
                candidate.init_confidence()?;
            }
            self.disassembly.candidates.insert(*addr, candidate.clone());
        }
        Ok(&self.disassembly)
    }

    fn get_disasm_window_buffer(&self, addr: u64) -> Vec<u8> {
        if (addr < self.disassembly.binary_info.base_addr)
            || (addr
            >= self.disassembly.binary_info.base_addr
            + self.disassembly.binary_info.binary.len() as u64)
        {
            return vec![];
        }
        let relative_start = addr - self.disassembly.binary_info.base_addr;
        let relative_end = relative_start + 15;
        if relative_end >= self.disassembly.binary_info.binary.len() as u64 {
            return self.disassembly.binary_info.binary[relative_start as usize..].to_vec();
        }
        self.disassembly.binary_info.binary[relative_start as usize..relative_end as usize].to_vec()
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
            } else if !self.disassembly.is_addr_within_memory_image(to_addr)? {
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
        // for referenced_addr in re.find_iter(op_str.as_bytes()) {
        //     let z =
        //         u64::from_str_radix(std::str::from_utf8(&referenced_addr.as_bytes()[2..])?, 16)?;
        //     return Ok(z);
        // }
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
        // Check if address is in .plt or .got section
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
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = i.address();
        let i_size = i.bytes().len();
        let i_op_str = i.op_str();
        state.set_leaf(false)?;

        match i_op_str {
            Some(op_str) => {
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

                    // Search API in add_to_api
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
                    if self.disassembly.binary_info.file_format == FileFormat::ELF {
                        if let Ok(api_info) = self.resolve_elf_thunk(call_destination) {
                            if let Some((dll, api)) = api_info {
                                let mut api_entry = label_providers::ApiEntry {
                                    referencing_addr: HashSet::new(),
                                    dll_name: dll.clone(),
                                    api_name: api.clone(),
                                };
                                api_entry.referencing_addr.insert(i_address);
                                self.disassembly.apis.insert(call_destination, api_entry);
                                self.disassembly.addr_to_api.insert(call_destination, (dll.clone(), api.clone()));
                            }
                        }
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
            _ => Ok(()),
        }
    }

    fn resolve_elf_thunk(&self, thunk_addr: u64) -> Result<Option<(Option<String>, Option<String>)>> {
        if !self.disassembly.is_addr_within_memory_image(thunk_addr)? {
            return Ok(None);
        }

        // first check if we already have this address mapped
        if let Some((dll, api)) = self.disassembly.addr_to_api.get(&thunk_addr) {
            return Ok(Some((dll.clone(), api.clone())));
        }

        let rel_addr = thunk_addr - self.disassembly.binary_info.base_addr;
        if rel_addr + 16 > self.disassembly.binary_info.binary_size {
            return Ok(None);
        }

        let bytes = &self.disassembly.binary_info.binary[rel_addr as usize..rel_addr as usize + 16];


        // search for the pattern FF 25 ?? ?? ?? ??
        for i in 0..12 {
            if i + 5 < bytes.len() && bytes[i] == 0xFF && bytes[i + 1] == 0x25 {
                let offset = i32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                let rip = thunk_addr + (i as u64) + 6;
                let got_addr = (rip as i64 + offset as i64) as u64;

                if let Some((dll, api)) = self.disassembly.addr_to_api.get(&got_addr) {
                    return Ok(Some((dll.clone(), api.clone())));
                } else {
                    for candidate_addr in self.disassembly.addr_to_api.keys() {
                        let diff = if *candidate_addr > got_addr {
                            *candidate_addr - got_addr
                        } else {
                            got_addr - *candidate_addr
                        };

                        if diff <= 8 {
                            if let Some((dll, api)) = self.disassembly.addr_to_api.get(candidate_addr) {
                                return Ok(Some((dll.clone(), api.clone())));
                            }
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
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = i.op_str().unwrap_or("");
        //case = "FALLTHROUGH"
        if i_op_str.contains(':') {
            //case = "LONG-JMP"
        } else if i_op_str.starts_with("dword ptr [0x") {
            //case = "DWORD-PTR"
            //Handles mostly jmp-to-api, stubs or tailcalls, all
            // should be handled sanely this way.
            let jump_destination = self.get_referenced_addr(i_op_str)?;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_dword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if i_op_str.starts_with("qword ptr [rip") {
            //case = "QWORD-PTR, RIP-relative"
            //Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            let rip = i_address + i_size as u64;
            //let jump_destination = rip + self.get_referenced_addr(i_op_str)?;
            let jump_destination = ((rip as i64) + self.get_referenced_addr_sign(i_op_str)?) as u64;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_qword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if i_op_str.starts_with("0x") {
            let jump_destination = self.get_referenced_addr(i_op_str)?;
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                // case = "TAILCALL!"
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                // case = "TAILCALL?"
            } else {
                let addr_to =
                    u64::from_str_radix(std::str::from_utf8(&i_op_str.as_bytes()[2..])?, 16)?;
                if state.is_first_instruction()? {
                    // case = "STUB-TAILCALL!"
                } else {
                    // case = "OFFSET-QUEUE"
                    if self.disassembly.is_addr_within_memory_image(addr_to)?
                        && self.disassembly.passes_code_filter(Some(addr_to))?
                    {
                        state.add_block_to_queue(addr_to)?;
                    }
                    // if self.disassembly.is_addr_within_memory_image(addr_to)? {
                    //     if self.disassembly.passes_code_filter(Some(addr_to))? {
                    //         state.add_block_to_queue(addr_to)?;
                    //     }
                    // }
                }
                state.add_code_ref(i_address, addr_to, true)?;
            }
        } else {
            let jumptable_targets = self.jumptable_analyzer.get_jump_targets(i, self, state)?;
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
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = i.op_str().unwrap_or("");
        if let Ok(_jump_destination) = self.get_referenced_addr(i_op_str) {
            state.add_code_ref(i_address, u64::from_str_radix(&i_op_str[2..], 16)?, true)?;
        }
        //# loops have two exits and should thus be handled as block ending instruction
        state.add_block_to_queue(i_address + i_size as u64)?;
        state.set_block_ending_instruction(true)?;
        Ok(())
    }

    pub fn analyze_cond_jmp_instruction(
        &self,
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = i.op_str().unwrap_or("");
        state.add_block_to_queue(i_address + i_size as u64)?;
        if let Ok(jump_destination) = self.get_referenced_addr(i_op_str) {
            //# case = "FALLTHROUGH"
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                //# case = "TAILCALL!"
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                //# it's tough to decide whether this should be disassembled here or not. topic of "code-sharing functions".
                //# case = "TAILCALL?"
            } else {
                //# case = "OFFSET-QUEUE"
                state.add_block_to_queue(u64::from_str_radix(&i_op_str[2..], 16)?)?;
            }
            state.add_code_ref(i_address, u64::from_str_radix(&i_op_str[2..], 16)?, true)?;
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
        let capstone = Capstone::new()
            .x86()
            .mode(if self.fc_manager.bitness == 32 {
                arch::x86::ArchMode::Mode32
            } else {
                arch::x86::ArchMode::Mode64
            })
            .syntax(arch::x86::ArchSyntax::Intel)
            //            .detail(true)
            .build()
            .map_err(Error::CapstoneError)?;
        while state.has_unprocessed_blocks() {
            state.choose_next_block()?;
            let mut cache_pos = 0;
            let start_block = state.block_start;
            let mut cache = capstone
                .disasm_all(
                    &self.get_disasm_window_buffer(state.block_start),
                    start_block,
                )
                .map_err(Error::CapstoneError)?;
            let mut previous_address: Option<u64> = None;
            let mut previous_mnemonic: Option<String> = None;
            let mut previous_op_str: Option<String> = None;
            loop {
                let mut exit_flag = false;
                for i in cache.as_ref() {
                    let i_address = i.address();
                    let i_size = i.bytes().len();
                    let i_mnemonic = i.mnemonic();
                    let i_op_str = i.op_str(); //strip
                    let i_relative_address = i_address - self.disassembly.binary_info.base_addr;
                    let i_bytes = &self.disassembly.binary_info.binary
                        [i_relative_address as usize..i_relative_address as usize + i_size]
                        .to_vec();
                    //LOGGER.debug("  analyzeFunction() now processing instruction @0x%08x: %s", i_address, i_mnemonic + " " + i_op_str)
                    cache_pos += i_size;
                    state.set_next_instruction_reachable(true)?;
                    if i_bytes == b"\x00\x00" {
                        state.suspicious_ins_count += 1;
                        if state.suspicious_ins_count > 1 {
                            self.fc_manager.update_analysis_aborted(
                                &start_addr,
                                &format!("too many suspicious instructions 0x{:08x}", i_address),
                            )?;
                            return Ok(state);
                        }
                    }
                    if CALL_INS.contains(&i_mnemonic) {
                        self.analyze_call_instruction(i, &mut state)?;
                    } else if JMP_INS.contains(&i_mnemonic) {
                        let jumps = self.analyze_jmp_instruction(i, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if LOOP_INS.contains(&i_mnemonic) {
                        self.analyze_loop_instruction(i, &mut state)?;
                    } else if CJMP_INS.contains(&i_mnemonic) {
                        let jumps = self.analyze_cond_jmp_instruction(i, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if i_mnemonic.as_ref().unwrap().starts_with('j') {
                        //LOGGER.error("unsupported jump @0x%08x (0x%08x): %s %s", i_address, start_addr, i_mnemonic, i_op_str)
                    } else if RET_INS.contains(&i_mnemonic) {
                        self.analyze_end_instruction(&mut state)?;
                        if previous_address.is_some()
                            && previous_address != Some(0)
                            && previous_mnemonic == Some("push".to_string())
                        {
                            let push_ret_destination =
                                self.get_referenced_addr(previous_op_str.as_ref().unwrap())?;
                            if self
                                .disassembly
                                .is_addr_within_memory_image(push_ret_destination)?
                            {
                                state.add_block_to_queue(push_ret_destination)?;
                                state.add_code_ref(i_address, push_ret_destination, true)?;
                            }
                        }
                    } else if [Some("int3"), Some("hlt")].contains(&i_mnemonic) {
                        self.analyze_end_instruction(&mut state)?;
                    } else if previous_address.is_some()
                        && previous_address != Some(0)
                        && i_address != start_addr
                        && previous_mnemonic == Some("call".to_string())
                    {
                        let instruction_sequence = capstone
                            .disasm_all(&self.get_disasm_window_buffer(i_address), i_address)
                            .map_err(Error::CapstoneError)?;
                        if self
                            .fc_manager
                            .is_alignment_sequence(&instruction_sequence)?
                            || self.fc_manager.is_function_candidate(i_address)?
                        {
                            state.set_block_ending_instruction(true)?;
                            state.end_block()?;
                            state.set_sanely_ending(true)?;
                            if self
                                .fc_manager
                                .is_alignment_sequence(&instruction_sequence)?
                            {
                                let next_aligned_address = previous_address.as_ref().unwrap()
                                    + (16 - previous_address.as_ref().unwrap() % 16);
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
                    previous_mnemonic = Some(i_mnemonic.as_ref().unwrap().to_string());
                    previous_op_str = Some(i_op_str.as_ref().unwrap().to_string());
                    if !self.disassembly.code_map.contains_key(&i_address)
                        && !self.disassembly.data_map.contains(&i_address)
                        && !state.is_processed(&i_address)?
                    {
                        state.add_instruction(
                            i_address,
                            i_size,
                            i_mnemonic.map(|m| m.to_string()),
                            i_op_str.map(|m| m.to_string()),
                            i_bytes.to_vec(),
                        )?;
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
                    cache = capstone
                        .disasm_all(
                            &self.get_disasm_window_buffer(state.block_start + cache_pos as u64),
                            state.block_start + cache_pos as u64,
                        )
                        .map_err(Error::CapstoneError)?;
                    if cache.len() == 0 {
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
            if !state.is_block_ending_instruction()? {
                //LOGGER.debug("No block submitted, last instruction:
                // 0x%08x -> 0x%08x %s || %s", start_addr, i_address, i_mnemonic + " " + i_op_str, self.fc_manager.getFunctionCandidate(start_addr))
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
            // self.tailcall_analyzer.finalize_function(&state)?;
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
        Ok(String::from(""))
        //        Err(Error::LogicError(file!(), line!()))
    }

    fn update_label_providers(&mut self, bi: &BinaryInfo) -> Result<()> {
        for provider in &mut self.label_providers {
            provider.update(bi)?;
        }
        Ok(())
    }
}
