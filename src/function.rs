//! Decoded function and instruction types.
//!
//! `Instruction` keeps the legacy String fields (`mnemonic`, `operands`,
//! `bytes` as hex) for backward compatibility with capa-rs — but ALSO
//! exposes the fully-decoded `iced_x86::Instruction` (16 bytes, `Copy`) so
//! new consumers can use typed mnemonic / operand / flow-control access
//! without paying the string-parsing tax.
//!
//! For 0.3.0 the strings are formatted by iced configured to byte-match
//! capstone's output (`0x` hex prefix, lowercase, space around `+` in
//! memory ops, `dword ptr` / `qword ptr` size prefixes). This lets the
//! analyzer's existing string-based heuristics continue to work unchanged.

use crate::{DisassemblyReport, DisassemblyResult, FileArchitecture, Result};
use iced_x86::{FlowControl, Formatter, IntelFormatter, Mnemonic, OpKind, Register};
use std::collections::HashMap;

/// Configure an `IntelFormatter` to emit capstone-compatible output:
/// lowercase hex with `0x` prefix, `dword ptr` / `qword ptr` size prefixes,
/// space around `+` / `-` in memory operands, and `, ` between operands.
/// Used internally so the existing string-based heuristics in the analyzer
/// continue to match.
#[must_use]
pub fn capstone_compat_formatter() -> IntelFormatter {
    let mut fmt = IntelFormatter::new();
    let opts = fmt.options_mut();
    // Numeric formatting
    opts.set_hex_prefix("0x");
    opts.set_hex_suffix("");
    opts.set_uppercase_hex(false);
    opts.set_small_hex_numbers_in_decimal(false);
    opts.set_add_leading_zero_to_hex_numbers(false);
    // Spacing
    opts.set_space_after_operand_separator(true);
    opts.set_space_between_memory_add_operators(true);
    opts.set_space_between_memory_mul_operators(false);
    // Registers / mnemonics lowercase
    opts.set_uppercase_mnemonics(false);
    opts.set_uppercase_registers(false);
    opts.set_uppercase_keywords(false);
    opts.set_uppercase_decorators(false);
    opts.set_uppercase_prefixes(false);
    // Memory size prefix ("dword ptr" / "qword ptr")
    opts.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    fmt
}

/// A single decoded x86/x64 instruction.
///
/// Legacy capstone-shaped fields (`mnemonic`, `operands`, `bytes`) are kept
/// for backward compatibility with capa-rs; new consumers should prefer the
/// typed iced accessors (`mnemonic()`, `op_kind()`, `flow_control()`, …).
#[derive(Debug, Clone)]
pub struct Instruction {
    pub arch: FileArchitecture,
    pub bitness: u32,
    pub offset: u64,
    /// Byte length (1–15).
    pub length: u32,
    /// Hex-encoded raw bytes (preserved for capa-rs compatibility).
    pub bytes: String,
    /// Capstone-compatible lowercase mnemonic ("mov", "call", "jmp", …).
    pub mnemonic: String,
    /// Capstone-compatible Intel operands string ("eax, 0x10",
    /// "dword ptr [rip + 0x100]", …) or `None` if no operands.
    pub operands: Option<String>,
    /// Fully-decoded iced instruction (16 bytes, `Copy`). New consumers
    /// should prefer this — it gives typed `Mnemonic` / `OpKind` / `Register`
    /// / `FlowControl` enum access without re-parsing the strings above.
    pub iced: iced_x86::Instruction,
}

impl Instruction {
    /// Construct from a `DecodedInsn` carrier.
    #[must_use]
    pub fn new(arch: FileArchitecture, bitness: u32, ins: &DecodedInsn) -> Self {
        let mut fmt = capstone_compat_formatter();
        let mut mnemonic = String::new();
        fmt.format_mnemonic(&ins.iced, &mut mnemonic);
        let operands = if ins.iced.op_count() == 0 {
            None
        } else {
            let mut out = String::new();
            fmt.format_all_operands(&ins.iced, &mut out);
            Some(out)
        };
        Self {
            arch,
            bitness,
            offset: ins.offset,
            length: ins.length,
            bytes: hex::encode(&ins.bytes),
            mnemonic,
            operands,
            iced: ins.iced,
        }
    }

    // ---- typed accessors (new in 0.3.0; preferred over string parsing) ----

    #[must_use]
    pub fn mnemonic_enum(&self) -> Mnemonic {
        self.iced.mnemonic()
    }
    #[must_use]
    pub fn code(&self) -> iced_x86::Code {
        self.iced.code()
    }
    #[must_use]
    pub fn op_count(&self) -> u32 {
        self.iced.op_count()
    }
    #[must_use]
    pub fn op_kind(&self, i: u32) -> OpKind {
        self.iced.op_kind(i)
    }
    #[must_use]
    pub fn op_register(&self, i: u32) -> Register {
        self.iced.op_register(i)
    }
    #[must_use]
    pub fn memory_base(&self) -> Register {
        self.iced.memory_base()
    }
    #[must_use]
    pub fn memory_index(&self) -> Register {
        self.iced.memory_index()
    }
    #[must_use]
    pub fn memory_displacement64(&self) -> u64 {
        self.iced.memory_displacement64()
    }
    #[must_use]
    pub fn memory_segment(&self) -> Register {
        self.iced.memory_segment()
    }
    #[must_use]
    pub fn near_branch_target(&self) -> u64 {
        self.iced.near_branch_target()
    }
    #[must_use]
    pub fn flow_control(&self) -> FlowControl {
        self.iced.flow_control()
    }
    #[must_use]
    pub fn is_call(&self) -> bool {
        matches!(
            self.iced.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        )
    }
    #[must_use]
    pub fn is_jmp(&self) -> bool {
        matches!(
            self.iced.flow_control(),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        )
    }
    #[must_use]
    pub fn is_conditional_jmp(&self) -> bool {
        matches!(self.iced.flow_control(), FlowControl::ConditionalBranch)
    }
    #[must_use]
    pub fn is_ret(&self) -> bool {
        matches!(self.iced.flow_control(), FlowControl::Return)
    }

    // ---- algorithms (migrated from capstone-string-parsing to typed) ------

    /// Detects "`mov [stack], <imm>`"-style stack strings. Returns the
    /// printable length of the immediate if it is ASCII / UTF-16 LE, else 0.
    pub fn get_printable_len(&self) -> Result<u64> {
        if self.iced.op_count() != 2 {
            return Ok(0);
        }
        let (chars, ascii_len, utf16_len): (Vec<u8>, u64, u64) = match self.iced.op_kind(1) {
            OpKind::Immediate8 => (vec![self.iced.immediate8()], 1, 0),
            OpKind::Immediate16 => (self.iced.immediate16().to_le_bytes().to_vec(), 2, 1),
            OpKind::Immediate32 => (self.iced.immediate32().to_le_bytes().to_vec(), 4, 2),
            OpKind::Immediate64 => (self.iced.immediate64().to_le_bytes().to_vec(), 8, 4),
            _ => return Ok(0),
        };
        if is_printable_ascii(&chars)? {
            return Ok(ascii_len);
        }
        if utf16_len > 0 && is_printable_utf16le(&chars)? {
            return Ok(utf16_len);
        }
        Ok(0)
    }

    /// Returns the absolute addresses referenced by immediate or memory
    /// operands, filtered to addresses inside the mapped image. Skips
    /// control-flow / compare / test instructions.
    pub fn get_data_refs(&self, report: &DisassemblyReport) -> Result<Vec<u64>> {
        if !matches!(
            self.iced.flow_control(),
            FlowControl::Next | FlowControl::Exception
        ) {
            return Ok(vec![]);
        }
        if matches!(
            self.iced.mnemonic(),
            Mnemonic::Cmp
                | Mnemonic::Cmpsb
                | Mnemonic::Cmpsw
                | Mnemonic::Cmpsd
                | Mnemonic::Cmpsq
                | Mnemonic::Test
        ) {
            return Ok(vec![]);
        }
        let mut res = Vec::new();
        for i in 0..self.iced.op_count() {
            let value: u64 = match self.iced.op_kind(i) {
                OpKind::Immediate8 => self.iced.immediate8() as u64,
                OpKind::Immediate16 => self.iced.immediate16() as u64,
                OpKind::Immediate32 => self.iced.immediate32() as u64,
                OpKind::Immediate64 => self.iced.immediate64(),
                // iced returns the RIP-resolved displacement directly.
                OpKind::Memory => self.iced.memory_displacement64(),
                _ => 0,
            };
            if value != 0 && report.is_addr_within_memory_image(&value)? {
                res.push(value);
            }
        }
        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub arch: crate::FileArchitecture,
    pub format: crate::FileFormat,
    pub bitness: u32,
    pub offset: u64,
    blocks: HashMap<u64, Vec<Instruction>>,
    pub apirefs: HashMap<u64, (Option<String>, Option<String>)>,
    pub blockrefs: HashMap<u64, Vec<u64>>,
    pub inrefs: Vec<u64>,
    pub outrefs: HashMap<u64, Vec<u64>>,
    pub binweight: u32,
    characteristics: String,
    confidence: f32,
    function_name: String,
    tfidf: f32,
}

impl Function {
    pub fn new(disassembly: &DisassemblyResult, function_offset: &u64) -> Result<Function> {
        let f = Function {
            arch: disassembly.binary_info.file_architecture,
            format: disassembly.binary_info.file_format,
            bitness: disassembly.binary_info.bitness,
            offset: *function_offset,
            blocks: Function::parse_blocks(
                disassembly,
                &disassembly.get_blocks_as_decoded(function_offset)?,
            )?,
            apirefs: disassembly.get_api_refs(function_offset)?,
            blockrefs: disassembly.get_block_refs(function_offset)?,
            inrefs: disassembly.get_in_refs(function_offset)?,
            outrefs: disassembly.get_out_refs(function_offset)?,
            binweight: 0,
            characteristics: if disassembly.candidates.contains_key(function_offset) {
                disassembly.candidates[function_offset].get_characteristics()?
            } else {
                "-----------".to_string()
            },
            confidence: if disassembly.candidates.contains_key(function_offset) {
                disassembly.candidates[function_offset].get_confidence()?
            } else {
                0.0
            },
            function_name: match disassembly.function_symbols.get(function_offset) {
                Some(s) => s.clone(),
                _ => String::new(),
            },
            tfidf: if disassembly.candidates.contains_key(function_offset) {
                disassembly.candidates[function_offset].get_tfidf()?
            } else {
                0.0
            },
        };
        Ok(f)
    }

    fn parse_blocks(
        disassembly: &DisassemblyResult,
        block_dict: &HashMap<u64, Vec<DecodedInsn>>,
    ) -> Result<HashMap<u64, Vec<Instruction>>> {
        let mut blocks = HashMap::with_capacity(block_dict.len());
        for (offset, block) in block_dict {
            let mut instructions = Vec::with_capacity(block.len());
            for ins in block {
                instructions.push(Instruction::new(
                    disassembly.binary_info.file_architecture,
                    disassembly.binary_info.bitness,
                    ins,
                ));
            }
            blocks.insert(*offset, instructions);
        }
        Ok(blocks)
    }

    pub fn get_blocks(&self) -> Result<&HashMap<u64, Vec<Instruction>>> {
        Ok(&self.blocks)
    }

    pub fn get_instructions(&self) -> Result<Vec<&Instruction>> {
        let mut res = vec![];
        for b in self.blocks.values() {
            for i in b {
                res.push(i);
            }
        }
        Ok(res)
    }

    pub fn get_num_instructions(&self) -> Result<usize> {
        Ok(self.blocks.values().map(Vec::len).sum())
    }

    pub fn get_num_outrefs(&self) -> Result<usize> {
        Ok(self.outrefs.values().map(Vec::len).sum())
    }

    pub fn is_api_thunk(&self) -> Result<bool> {
        if self.get_num_instructions()? != 1 {
            return Ok(false);
        }
        let first_ins = &self.blocks[&self.offset][0];
        if !matches!(first_ins.mnemonic_enum(), Mnemonic::Jmp | Mnemonic::Call) {
            return Ok(false);
        }
        if self.apirefs.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Internal carrier type. The analyzer stashes one per decoded instruction
/// into `FunctionAnalysisState` / `DisassemblyResult`, then `Function::new`
/// transforms them into public `Instruction` values (which also format the
/// capstone-compatible string fields).
///
/// Bytes are owned (max 15 bytes per x86/x64 insn — trivial cost, and
/// avoids self-referential-struct headaches with the analyzer state).
#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub offset: u64,
    pub length: u32,
    pub iced: iced_x86::Instruction,
    pub bytes: Vec<u8>,
}

pub fn is_printable_ascii(chars: &[u8]) -> Result<bool> {
    for c in chars {
        if c >= &127 || !b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ ".contains(c){
            return Ok(false)
        }
    }
    Ok(true)
}

pub fn is_printable_utf16le(chars: &[u8]) -> Result<bool> {
    let mut i = 1;
    let mut u = vec![];
    while i < chars.len() {
        if i % 2 != 0 && chars[i] != 0x00 {
            return Ok(false);
        } else if i % 2 == 0 {
            u.push(chars[i]);
        }
        i += 1;
    }
    is_printable_ascii(&u)
}
