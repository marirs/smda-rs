#![allow(dead_code)]
#![allow(clippy::type_complexity)]
#[macro_use]
extern crate maplit;

mod delphi;
mod demangle;
pub mod disassembler;
mod dwarf;
pub mod elf;
pub mod function;
mod function_analysis_state;
mod function_candidate;
mod function_candidate_manager;
mod indirect_call_analyser;
mod jump_table_analyser;
mod label_provider;
mod label_providers;
pub mod macho;
mod mnemonic_tf_idf;
mod pclntab;
mod pe;
pub mod report;
mod statistics;
mod tail_call_analyser;
pub mod xmetadata;

use disassembler::{Aarch64Decoder, DecodedInsn, X86Decoder, capstone_compat_formatter};
use function_analysis_state::FunctionAnalysisState;
use function_candidate::FunctionCandidate;
use function_candidate_manager::FunctionCandidateManager;
use goblin::Object;
use iced_x86::{FlowControl, Formatter, Mnemonic};
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

/// (0.5.0) Disassembler configuration — replaces the positional
/// `(path, high_accuracy, resolve_tailcalls)` + `parse_with_timeout`
/// sibling that 0.4.x used. Construct via [`SmdaConfig::new`] +
/// chained builder methods.
///
/// `#[non_exhaustive]` — future knobs add as new builder methods
/// without forcing a major bump.
///
/// ```
/// use smda::SmdaConfig;
/// use std::time::Duration;
///
/// let cfg = SmdaConfig::new()
///     .path("/tmp/sample.bin")
///     .high_accuracy(true)
///     .resolve_tailcalls(true)
///     .timeout(Duration::from_secs(30));
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SmdaConfig {
    /// Optional path label embedded in `BinaryInfo.file_path` — purely
    /// cosmetic, no I/O is performed against it.
    pub path: Option<String>,
    /// Run the slower, higher-accuracy heuristics. Trades analysis
    /// time for fewer missed function starts. Defaults to `false`.
    pub high_accuracy: bool,
    /// Promote unresolved tail-call targets to full functions in a
    /// post-pass. Defaults to `false`.
    pub resolve_tailcalls: bool,
    /// Optional wall-clock budget for the whole analysis. Returns
    /// `Error::AnalysisTimeout` if exceeded mid-flight. `None` =
    /// unbounded. Useful for batch-processing untrusted samples.
    pub timeout: Option<std::time::Duration>,
    /// 0.6.0 — which slice to pick when the input is a fat Mach-O
    /// (universal binary carrying multiple architectures). Defaults
    /// to [`MachoArchPreference::HostNative`] — the slice matching
    /// the host architecture is preferred, falling back to other
    /// slices if the native one isn't present.
    ///
    /// Override when:
    /// - You're always analysing modern Mac malware → `Aarch64First`.
    /// - You're processing older campaigns that targeted Intel Macs
    ///   from a host where you don't care → `X86_64First`.
    /// - You're on an unusual host (e.g. Linux on a non-x86 server
    ///   analysing Apple-silicon malware) and want explicit control.
    pub macho_arch_preference: MachoArchPreference,
}

/// 0.6.0 — fat Mach-O slice preference. See
/// [`SmdaConfig::macho_arch_preference`].
///
/// Thin (single-arch) Mach-O binaries ignore this — there's only one
/// slice to pick. ELF and PE never carry multiple architectures, so
/// this is a Mach-O-only knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MachoArchPreference {
    /// Prefer the slice matching the host architecture
    /// (`std::env::consts::ARCH`). Apple-silicon → ARM64 first,
    /// Intel/AMD Linux/Windows → x86_64 first. Falls back to the
    /// other available slices. Default — matches the "I'm analysing
    /// on this machine" intuition for most users.
    #[default]
    HostNative,
    /// Prefer ARM64, then x86_64, then x86. Right call when
    /// analysing modern Mac malware regardless of analyst host
    /// (Apple-silicon dominates deployed Mac targets in 2024+).
    Aarch64First,
    /// Prefer x86_64, then ARM64, then x86. Right call for older
    /// campaigns or legacy Mac samples.
    X86_64First,
    /// Prefer x86 (32-bit Intel), then x86_64, then ARM64. Niche —
    /// only useful for archaic Mac binaries.
    X86First,
}

impl SmdaConfig {
    /// Empty config — equivalent to the 0.4.x defaults
    /// (`high_accuracy=false`, `resolve_tailcalls=false`, no timeout).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cosmetic file-path label.
    #[must_use]
    pub fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into());
        self
    }

    /// Enable / disable the slower high-accuracy heuristics.
    #[must_use]
    pub fn high_accuracy(mut self, b: bool) -> Self {
        self.high_accuracy = b;
        self
    }

    /// Enable / disable tail-call resolution post-pass.
    #[must_use]
    pub fn resolve_tailcalls(mut self, b: bool) -> Self {
        self.resolve_tailcalls = b;
        self
    }

    /// Set a wall-clock analysis budget. Pass `None` (or omit) for
    /// unbounded.
    #[must_use]
    pub fn timeout(mut self, t: std::time::Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// 0.6.0 — override the fat-Mach-O slice preference. See
    /// [`MachoArchPreference`]. No effect on thin Mach-O, ELF, or PE.
    #[must_use]
    pub fn macho_arch_preference(mut self, p: MachoArchPreference) -> Self {
        self.macho_arch_preference = p;
        self
    }
}

/// Recognised executable file formats.
///
/// Marked `#[non_exhaustive]` in 0.5.0 — future variants land without
/// a major bump. Downstream `match` statements must include a wildcard
/// arm.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileFormat {
    ELF,
    PE,
    /// 0.5.0 — Mach-O (Intel x86 / x86_64).
    MachO,
    /// 0.5.0 — raw memory dump / shellcode (no file-format wrapper).
    /// Set by `Disassembler::parse_buffer`; pre-0.5.0 this surfaced as
    /// `FileFormat::ELF` with `is_buffer = true`.
    Buffer,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileFormat::ELF => write!(f, "Elf file"),
            FileFormat::PE => write!(f, "PE file"),
            FileFormat::MachO => write!(f, "Mach-O file"),
            FileFormat::Buffer => write!(f, "Raw buffer"),
        }
    }
}

/// CPU architectures recognised by the disassembler.
///
/// Marked `#[non_exhaustive]` in 0.5.0 — future variants land without
/// a major bump.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileArchitecture {
    I386,
    AMD64,
    /// 0.6.0 — ARM 64-bit (AArch64). Decoded via the `disarm64` backend.
    /// In 0.6.0 only the linear decode + report surface is populated;
    /// the x86-only heuristics (jump tables, indirect calls, tail
    /// calls, function-candidate alignment, exit-syscall recognition)
    /// are no-ops on this variant. Full analyser support arrives in
    /// 0.6.1.
    Aarch64,
}

impl std::fmt::Display for FileArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileArchitecture::I386 => write!(f, "i386"),
            FileArchitecture::AMD64 => write!(f, "amd64"),
            FileArchitecture::Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// One contiguous mapping between a VA range and a slice of the input file.
///
/// Replaces the per-binary `Vec<u8>` "mapped image" of 0.3.x — instead of
/// reorganising bytes into a virtual-address layout we record where each
/// section lives in both spaces and slice into the borrowed input on
/// demand. For raw memory dumps the section table collapses to a single
/// entry; for PE/ELF there's one entry per loaded section.
///
/// `file_size <= va_end - va_start`: the remainder is the BSS-style gap
/// between the on-disk bytes and the in-memory size. Reads into that gap
/// return `Err(NotEnoughBytesError)` so callers can decide whether to
/// treat them as zero or skip.
#[derive(Debug, Clone, Copy)]
pub struct SectionMap {
    pub va_start: u64,
    pub va_end: u64,
    pub file_offset: usize,
    pub file_size: usize,
}

/// All binary-level metadata threaded through the analyser. Borrowed
/// against the input bytes for `'a`.
///
/// Marked `#[non_exhaustive]` in 0.5.0 — adding fields is no longer
/// breaking. Construct via `BinaryInfo::from_buffer` or
/// `BinaryInfo::empty`; struct-literal construction is no longer
/// supported by downstream crates.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BinaryInfo<'a> {
    pub file_format: FileFormat,
    pub file_architecture: FileArchitecture,
    pub base_addr: u64,
    /// The original input bytes — borrowed, not owned. Goblin parses
    /// from this directly when needed.
    pub raw_data: &'a [u8],
    /// Section table describing where bytes live in both file and VA
    /// space. Sorted by `va_start`.
    pub section_maps: Vec<SectionMap>,
    /// Total VA range covered by the mapping (`max va_end - base_addr`).
    /// Note: this is the *virtual* footprint, not `raw_data.len()`.
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

impl<'a> BinaryInfo<'a> {
    /// Empty placeholder, primarily used to satisfy the
    /// `DisassemblyResult::new()` initial-construction pattern before a
    /// real binary is loaded. Carries no borrowed data.
    pub fn empty() -> BinaryInfo<'static> {
        BinaryInfo {
            file_format: FileFormat::ELF,
            file_architecture: FileArchitecture::I386,
            base_addr: 0,
            raw_data: &[],
            section_maps: vec![],
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

    /// Build a `BinaryInfo<'a>` borrowing `content`. Computes the SHA-256
    /// of the raw input and leaves the section table empty — the caller
    /// (the disassembler) is responsible for populating `section_maps`
    /// and the format-specific metadata.
    pub fn from_buffer(content: &'a [u8]) -> Result<BinaryInfo<'a>> {
        Ok(BinaryInfo {
            file_format: FileFormat::ELF,
            file_architecture: FileArchitecture::I386,
            base_addr: 0,
            raw_data: content,
            section_maps: vec![],
            binary_size: 0,
            bitness: 32,
            code_areas: vec![],
            component: String::new(),
            family: String::new(),
            file_path: String::new(),
            is_library: false,
            is_buffer: false,
            sha256: BinaryInfo::sha256_digest(content),
            entry_point: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
        })
    }

    fn sha256_digest(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Locate `va` in the section table and return the section + the
    /// offset within it. Linear search over typically <10 entries; faster
    /// than binary search for small tables thanks to branch prediction.
    fn locate(&self, va: u64) -> Option<(&SectionMap, usize)> {
        for sect in &self.section_maps {
            if sect.va_start <= va && va < sect.va_end {
                let offset_in_section = (va - sect.va_start) as usize;
                return Some((sect, offset_in_section));
            }
        }
        None
    }

    /// Read `len` bytes starting at virtual address `va`. Returns a
    /// borrowed slice into `raw_data` — zero allocation.
    ///
    /// Returns `Err(NotEnoughBytesError)` if `va` is not within any
    /// section, if the read would cross a section boundary, or if it
    /// would extend past the on-disk bytes into a BSS-style gap.
    pub fn bytes_at(&self, va: u64, len: u32) -> Result<&[u8]> {
        let (sect, offset_in_section) = self
            .locate(va)
            .ok_or(Error::NotEnoughBytesError(va, len as u64))?;
        let end_offset = offset_in_section
            .checked_add(len as usize)
            .ok_or(Error::NotEnoughBytesError(va, len as u64))?;
        // Reads that would extend past the on-disk part of the section
        // (into a BSS gap or past the section end) are errors. Callers
        // that want zero-fill semantics can handle the Err.
        if end_offset > sect.file_size {
            return Err(Error::NotEnoughBytesError(va, len as u64));
        }
        let file_start = sect
            .file_offset
            .checked_add(offset_in_section)
            .ok_or(Error::NotEnoughBytesError(va, len as u64))?;
        let file_end = sect
            .file_offset
            .checked_add(end_offset)
            .ok_or(Error::NotEnoughBytesError(va, len as u64))?;
        self.raw_data
            .get(file_start..file_end)
            .ok_or(Error::NotEnoughBytesError(va, len as u64))
    }

    /// Best-effort variant of `bytes_at` that returns up to `max_len`
    /// bytes (fewer if a section boundary or EOF intervenes). Used by
    /// the iced decoder's lookahead window where a short read is
    /// acceptable (iced will decode whatever fits).
    pub fn bytes_at_best_effort(&self, va: u64, max_len: u32) -> Result<&[u8]> {
        let (sect, offset_in_section) = self
            .locate(va)
            .ok_or(Error::NotEnoughBytesError(va, max_len as u64))?;
        let available = sect.file_size.saturating_sub(offset_in_section);
        if available == 0 {
            return Err(Error::NotEnoughBytesError(va, max_len as u64));
        }
        let take = (max_len as usize).min(available);
        let file_start = sect
            .file_offset
            .checked_add(offset_in_section)
            .ok_or(Error::NotEnoughBytesError(va, max_len as u64))?;
        let file_end = file_start
            .checked_add(take)
            .ok_or(Error::NotEnoughBytesError(va, max_len as u64))?;
        self.raw_data
            .get(file_start..file_end)
            .ok_or(Error::NotEnoughBytesError(va, max_len as u64))
    }

    /// Convenience: highest VA covered by any section (exclusive). Set
    /// at construction; recomputed by callers as sections are added.
    pub fn compute_binary_size(&self) -> u64 {
        self.section_maps
            .iter()
            .map(|s| s.va_end.saturating_sub(self.base_addr))
            .max()
            .unwrap_or(0)
    }

    /// Yield `(va_start, &[u8])` for each section. Used by candidate
    /// scanners that need to find byte patterns and translate match
    /// positions back to virtual addresses. The byte slice is a direct
    /// borrow into `raw_data` — zero allocation.
    pub fn section_slices(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.section_maps.iter().filter_map(|s| {
            let end = s.file_offset.checked_add(s.file_size)?;
            let bytes = self.raw_data.get(s.file_offset..end)?;
            Some((s.va_start, bytes))
        })
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
        match Object::parse(self.raw_data)? {
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

    /// Original entry-point virtual address.
    ///
    /// PE: `OptionalHeader.AddressOfEntryPoint + ImageBase`.
    /// ELF: `e_entry`. Returns 0 if the format has no concept of an entry
    /// point or none is set.
    pub fn get_oep(&self) -> Result<u64> {
        match Object::parse(self.raw_data)? {
            Object::PE(pe) => Ok((pe.entry as u64).saturating_add(self.base_addr)),
            Object::Elf(elf) => Ok(elf.header.e_entry),
            _ => Ok(0),
        }
    }
}

#[derive(Debug)]
pub struct DisassemblyResult<'a> {
    analysis_start_ts: SystemTime,
    analysis_end_ts: SystemTime,
    analysis_timeout: bool,
    pub binary_info: BinaryInfo<'a>,
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

impl<'a> DisassemblyResult<'a> {
    /// Construct a fresh `DisassemblyResult` borrowing `binary_info`'s
    /// underlying input bytes for the lifetime `'a`.
    pub fn new(binary_info: BinaryInfo<'a>) -> DisassemblyResult<'a> {
        DisassemblyResult {
            analysis_start_ts: SystemTime::now(),
            analysis_end_ts: SystemTime::now(),
            analysis_timeout: false,
            binary_info,
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

    pub fn init(&mut self, bi: BinaryInfo<'a>) -> Result<()> {
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
            let elf_apis = elf::extract_elf_dynamic_apis(self.binary_info.raw_data)?;
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
                let ins_absolute_addr = self.binary_info.base_addr + ins.offset();

                // Direct lookup
                if let Some((dll, api)) = self.addr_to_api.get(&ins_absolute_addr) {
                    api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                    continue;
                }

                // If it's a call, follow the target
                if matches!(ins.flow_control_x86(), Some(FlowControl::Call))
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

                // (0.6.1) AArch64 branch follow: thunks use a direct
                // `b <import>` (single-instruction function) and direct
                // calls use `bl <import>` — both have a PC-relative
                // immediate target resolvable via the disarm64 helper.
                // Mirror the x86 call-follow above so single-`b` API
                // thunks get classified by `is_api_thunk` and ordinary
                // `bl` API calls populate `apirefs` for capa
                // consumption.
                if let DecodedInsn::Aarch64(a) = ins {
                    use disassembler::{
                        aarch64_branch_target_raw, aarch64_is_direct_call,
                        aarch64_is_unconditional_branch,
                    };
                    if (aarch64_is_direct_call(&a.decoded)
                        || aarch64_is_unconditional_branch(&a.decoded))
                        && let Some(target_va) =
                            aarch64_branch_target_raw(&a.decoded, a.opcode, a.offset)
                    {
                        if let Some((dll, api)) = self.addr_to_api.get(&target_va) {
                            api_refs.insert(ins_absolute_addr, (dll.clone(), api.clone()));
                            continue;
                        }
                        if let Some(api_entry) = self.apis.get(&target_va) {
                            api_refs.insert(
                                ins_absolute_addr,
                                (api_entry.dll_name.clone(), api_entry.api_name.clone()),
                            );
                            continue;
                        }
                    }
                }
            }
        }

        Ok(api_refs)
    }

    fn extract_call_target(instruction: &DecodedInsn, _base_addr: u64) -> Option<u64> {
        use iced_x86::OpKind;
        // x86 only: AArch64 bl/blr resolution lands in 0.6.1.
        let iced = instruction.as_iced()?;
        if matches!(iced.flow_control(), FlowControl::Call) && iced.op_count() >= 1 {
            match iced.op_kind(0) {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    return Some(iced.near_branch_target());
                }
                OpKind::Memory => {
                    let target = iced.memory_displacement64();
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

    /// Read one byte at virtual address `addr`.
    pub fn get_byte(&self, addr: u64) -> Result<u8> {
        let slice = self.binary_info.bytes_at(addr, 1)?;
        slice
            .first()
            .copied()
            .ok_or(Error::NotEnoughBytesError(addr, 1))
    }

    /// Read one byte at a base-relative offset (i.e. `base_addr + offset`).
    /// Pre-0.4.0 this indexed directly into the mapped image; in the
    /// section-map model we translate to VA-space and go through `bytes_at`.
    pub fn get_raw_byte(&self, offset: u64) -> Result<u8> {
        let va = self
            .binary_info
            .base_addr
            .checked_add(offset)
            .ok_or(Error::NotEnoughBytesError(offset, 1))?;
        self.get_byte(va)
    }

    /// Read `bytes` bytes at a base-relative offset.
    pub fn get_raw_bytes(&self, offset: u64, bytes: u64) -> Result<&[u8]> {
        let va = self
            .binary_info
            .base_addr
            .checked_add(offset)
            .ok_or(Error::NotEnoughBytesError(offset, bytes))?;
        let len = u32::try_from(bytes).map_err(|_| Error::NotEnoughBytesError(offset, bytes))?;
        self.binary_info.bytes_at(va, len)
    }

    /// Read `num_bytes` bytes at virtual address `addr`.
    pub fn get_bytes(&self, addr: u64, num_bytes: u64) -> Result<&[u8]> {
        let len =
            u32::try_from(num_bytes).map_err(|_| Error::NotEnoughBytesError(addr, num_bytes))?;
        self.binary_info.bytes_at(addr, len)
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
        let slice = self
            .binary_info
            .bytes_at(addr, 4)
            .map_err(|_| Error::DereferenceError(addr))?;
        let arr: &[u8; 4] = slice
            .try_into()
            .map_err(|_| Error::DereferenceError(addr))?;
        Ok(u32::from_le_bytes(*arr) as u64)
    }

    pub fn dereference_qword(&self, addr: u64) -> Result<u64> {
        let slice = self
            .binary_info
            .bytes_at(addr, 8)
            .map_err(|_| Error::DereferenceError(addr))?;
        let arr: &[u8; 8] = slice
            .try_into()
            .map_err(|_| Error::DereferenceError(addr))?;
        Ok(u64::from_le_bytes(*arr))
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
            blocks.insert(block[0].offset(), block.clone());
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
                ins_addrs.insert(ins.offset());
            }
        }
        for block in blocks {
            if block.is_empty() {
                continue;
            }
            let last_ins_addr = block[block.len() - 1].offset();
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
                    block_refs.insert(block[0].offset(), verified_refs);
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
                let ins_addr = ins.offset();
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

pub struct Disassembler<'a> {
    common_start_bytes: HashMap<u32, HashMap<u8, u32>>,
    tailcall_analyzer: TailCallAnalyser,
    indirect_call_analyser: IndirectCallAnalyser,
    jumptable_analyzer: JumpTableAnalyser,
    fc_manager: FunctionCandidateManager,
    tfidf: MnemonicTfIdf,
    pub disassembly: DisassemblyResult<'a>,
    label_providers: Vec<LabelProvider>,
    /// (0.6.0) Per-arch decoder backend. Picked in `with_binary` based
    /// on `binary_info.file_architecture`. `Box<dyn Decoder>` because
    /// the analyser doesn't statically know which backend it will get,
    /// and the trait object cost is negligible vs the per-instruction
    /// decode work.
    decoder: Box<dyn disassembler::Decoder>,
    /// (0.4.1 N14) Optional per-disassembly wall-clock budget.
    analysis_timeout: Option<std::time::Duration>,
    analysis_started: Option<std::time::Instant>,
}

impl std::fmt::Debug for Disassembler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Disassembler")
            .field("disassembly", &self.disassembly)
            .field("analysis_timeout", &self.analysis_timeout)
            .finish_non_exhaustive()
    }
}

impl<'a> Disassembler<'a> {
    pub fn get_bitmask(&self) -> u64 {
        0xFFFFFFFFFFFFFFFF
    }

    /// Constructor used internally by `parse` / `disassemble_file` after
    /// the `BinaryInfo` has been populated. Public callers should use
    /// `Disassembler::parse(&buf, ...)` instead.
    fn with_binary(binary_info: BinaryInfo<'a>) -> Result<Disassembler<'a>> {
        let decoder: Box<dyn disassembler::Decoder> = match binary_info.file_architecture {
            FileArchitecture::Aarch64 => Box::new(Aarch64Decoder::new()),
            // I386 / AMD64 (and anything else x86-shaped) → iced.
            _ => Box::new(X86Decoder::new(binary_info.bitness.max(32))),
        };
        let mut res = Disassembler {
            common_start_bytes: HashMap::new(),
            tailcall_analyzer: TailCallAnalyser::new(),
            indirect_call_analyser: IndirectCallAnalyser::new(),
            jumptable_analyzer: JumpTableAnalyser::new(),
            fc_manager: FunctionCandidateManager::new(),
            tfidf: MnemonicTfIdf::new(),
            disassembly: DisassemblyResult::new(binary_info),
            label_providers: label_providers::init()?,
            decoder,
            analysis_timeout: None,
            analysis_started: None,
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
        // 0.6.0 — minimal AArch64 prologue start-byte table. ARM64
        // instructions are little-endian 4-byte words; the FIRST byte
        // of `stp x29, x30, [sp, #-N]!` (the canonical Apple-silicon /
        // Linux ARM64 prologue) is 0xfd — the low byte of the encoded
        // word. Sized similarly to the x86 weights so the vote
        // converges. AArch64 prologue detection lands more fully in
        // 0.6.1; this table exists so `determine_bitness` doesn't
        // erroneously vote 32 on an ARM64 binary that somehow falls
        // through the file-format routing.
        res.common_start_bytes.insert(
            128, // sentinel key — AArch64 is always 64-bit but we use a
            // distinct key so the iter doesn't collide with the x86
            // 64-bit table.
            hashmap! {0xfd => 1000, 0xff => 500},
        );
        res.common_start_bytes.insert(
            64,
            // 0xF3 added in 0.4.1 — `endbr64` (`F3 0F 1E FA`) is now the
            // first byte of practically every function in modern Linux
            // ELFs built with `-fcf-protection`. The weight (1200) is
            // sized so the new heuristic dominates only on samples that
            // are actually CET-enabled; on older binaries the 0x48 / 0x40
            // / 0x4c weights still drive the bitness vote.
            hashmap! {0x48 => 1341,
            0x40 => 349,
            0x4c => 59,
            0x33 => 56,
            0x44 => 18,
            0x45 => 17,
            0xe9 => 16,
            0xf3 => 1200},
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
        // 0.6.0: AArch64 is always 64-bit and the E8-call scan below is
        // x86-specific. Short-circuit before walking the input bytes.
        if matches!(
            self.disassembly.binary_info.file_architecture,
            FileArchitecture::Aarch64
        ) {
            return Ok(64);
        }
        // Scan the raw input bytes for E8 call patterns. In 0.3.x this
        // walked the mapped image; the raw input version is equivalent
        // for bitness detection — we only need the relative-offset
        // statistics, not the absolute targets.
        let raw = self.disassembly.binary_info.raw_data;
        let mut candidate_first_bytes: HashMap<u32, HashMap<u8, u32>> =
            [(32, HashMap::new()), (64, HashMap::new())]
                .iter()
                .cloned()
                .collect();
        for bitness in [32, 64] {
            for call_match in BITNESS.find_iter(raw) {
                if raw.len() - call_match.start() > 5 {
                    let packed_call: &[u8; 4] =
                        &raw[call_match.start() + 1..call_match.start() + 5].try_into()?;
                    let rel_call_offset = i32::from_le_bytes(*packed_call);
                    let call_destination = rel_call_offset
                        .overflowing_add(call_match.start() as i32)
                        .0
                        .overflowing_add(5)
                        .0;
                    if call_destination > 0 && (call_destination as usize) < raw.len() {
                        let first_byte = raw[call_destination as usize];
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

    // `disassemble_file` was removed in 0.4.0. The 0.3.x signature
    // returned an owned `DisassemblyReport` that cloned the mapped image
    // into the report; the zero-copy refactor makes that pattern
    // impossible to express in safe Rust without either leaking memory
    // or using a self-referential helper crate (yoke / ouroboros).
    //
    // Callers should load the file themselves and pass the buffer to
    // `parse(&buf, Some(path), …)`:
    //
    // ```no_run
    // let buf = std::fs::read("Sample.exe")?;
    // let report = smda::Disassembler::parse(&buf, Some("Sample.exe"), false, false)?;
    // // `buf` must outlive `report`
    // ```

    /// (0.5.0) Zero-copy disassembly entry point. The returned
    /// `DisassemblyReport` borrows from `raw` for the lifetime `'b`;
    /// no copies of the input bytes are made.
    ///
    /// Pre-0.5.0 this took positional `(path, high_accuracy,
    /// resolve_tailcalls)` and an optional `parse_with_timeout` sibling.
    /// 0.5.0 collapses all knobs into [`SmdaConfig`] so future analysis
    /// options land without API breaks.
    ///
    /// ```no_run
    /// use smda::{Disassembler, SmdaConfig};
    /// let buf = std::fs::read("Sample.exe").unwrap();
    /// let cfg = SmdaConfig::new().path("Sample.exe");
    /// let report = Disassembler::parse(&buf, &cfg).unwrap();
    /// ```
    pub fn parse<'b>(raw: &'b [u8], config: &SmdaConfig) -> Result<DisassemblyReport<'b>> {
        Self::parse_inner(
            raw,
            config.path.as_deref(),
            config.high_accuracy,
            config.resolve_tailcalls,
            config.timeout,
            config.macho_arch_preference,
        )
    }

    /// (0.4.2 N11; 0.5.0) Raw-buffer entry point — bypass PE / ELF / MachO
    /// header parsing. Use this for shellcode, unpacked modules, memory
    /// dumps, or any byte blob without a recognised executable header.
    ///
    /// The whole buffer is treated as one section mapped at `base_addr`,
    /// with no imports / exports / code-area subdivision. The returned
    /// report has `binary_info.is_buffer = true` and
    /// `file_format = FileFormat::Buffer`.
    ///
    /// `bitness` must be 32 or 64. `base_addr` is the virtual address the
    /// buffer maps to — defaults are sensible at 0 if the caller has no
    /// preference. Mirrors `disassembleBuffer` in the Python upstream.
    pub fn parse_buffer<'b>(
        raw: &'b [u8],
        base_addr: u64,
        bitness: u32,
        config: &SmdaConfig,
    ) -> Result<DisassemblyReport<'b>> {
        Self::parse_buffer_inner(
            raw,
            base_addr,
            bitness,
            config.high_accuracy,
            config.resolve_tailcalls,
            config.timeout,
        )
    }

    fn parse_buffer_inner<'b>(
        raw: &'b [u8],
        base_addr: u64,
        bitness: u32,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<DisassemblyReport<'b>> {
        if !matches!(bitness, 32 | 64) {
            return Err(Error::MalformedInputError(
                "parse_buffer: bitness must be 32 or 64",
                bitness as u64,
                0,
            ));
        }
        let len = raw.len();
        let va_end = base_addr
            .checked_add(len as u64)
            .ok_or(Error::IntegerOverflow(
                "parse_buffer: base_addr + len",
                base_addr,
                len as u64,
            ))?;
        let mut binary_info = BinaryInfo::from_buffer(raw)?;
        binary_info.is_buffer = true;
        binary_info.file_format = FileFormat::Buffer;
        binary_info.base_addr = base_addr;
        binary_info.bitness = bitness;
        binary_info.entry_point = base_addr;
        binary_info.file_architecture = match bitness {
            64 => FileArchitecture::AMD64,
            _ => FileArchitecture::I386,
        };
        binary_info.code_areas = vec![(base_addr, va_end)];
        binary_info.sections = vec![("raw".to_string(), base_addr, len)];
        binary_info.section_maps = vec![SectionMap {
            va_start: base_addr,
            va_end,
            file_offset: 0,
            file_size: len,
        }];
        binary_info.binary_size = binary_info.compute_binary_size();
        let mut disassembler = Disassembler::with_binary(binary_info)?;
        disassembler.analysis_timeout = timeout;
        disassembler.analysis_started = Some(std::time::Instant::now());
        disassembler.analyse_buffer(high_accuracy, resolve_tailcalls)?;
        DisassemblyReport::new(&mut disassembler.disassembly)
    }

    fn parse_inner<'b>(
        raw: &'b [u8],
        path: Option<&str>,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        timeout: Option<std::time::Duration>,
        macho_arch_preference: MachoArchPreference,
    ) -> Result<DisassemblyReport<'b>> {
        let mut binary_info = BinaryInfo::from_buffer(raw)?;
        if let Some(p) = path {
            binary_info.file_path = p.to_string();
        }
        match Object::parse(raw)? {
            Object::Elf(elf) => {
                binary_info.file_format = FileFormat::ELF;
                binary_info.base_addr = elf::get_base_address(raw)?;
                binary_info.bitness = elf::get_bitness(raw)?;
                binary_info.entry_point = elf.header.e_entry;
                // 0.6.0: EM_AARCH64 == 183 → AArch64 (64-bit fixed).
                binary_info.file_architecture =
                    if elf.header.e_machine == goblin::elf::header::EM_AARCH64 {
                        binary_info.bitness = 64;
                        FileArchitecture::Aarch64
                    } else if binary_info.bitness == 64 {
                        FileArchitecture::AMD64
                    } else {
                        FileArchitecture::I386
                    };
                binary_info.code_areas = elf::get_code_areas(raw, &elf)?;
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
                binary_info.section_maps = elf::map_binary(raw, binary_info.base_addr)?;
            }
            Object::PE(pe) => {
                binary_info.file_format = FileFormat::PE;
                binary_info.base_addr = pe::get_base_address(raw)?;
                // 0.6.0: IMAGE_FILE_MACHINE_ARM64 == 0xAA64. `pe::get_bitness`
                // would error on ARM64; recognise the machine field here
                // and bypass the x86 bitness probe.
                if pe.header.coff_header.machine == 0xAA64 {
                    binary_info.bitness = 64;
                    binary_info.file_architecture = FileArchitecture::Aarch64;
                } else {
                    binary_info.bitness = pe::get_bitness(raw)?;
                    binary_info.file_architecture = match binary_info.bitness {
                        64 => FileArchitecture::AMD64,
                        _ => FileArchitecture::I386,
                    };
                }
                // PE entry is an RVA — add image base to get the VA.
                binary_info.entry_point = binary_info.base_addr.saturating_add(pe.entry as u64);
                binary_info.code_areas = pe::get_code_areas(raw, &pe)?;
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
                binary_info.section_maps = pe::map_binary(raw, binary_info.base_addr)?;
            }
            Object::Mach(_) => {
                // 0.5.0: Mach-O loader for Intel; 0.6.0 adds AArch64 via
                // `macho::extract_macho` which returns either an Intel or
                // ARM64 MachO slice. Routing by cputype follows.
                let mach = macho::extract_macho(raw, macho_arch_preference)?;
                binary_info.file_format = FileFormat::MachO;
                binary_info.base_addr = macho::get_base_address(&mach);
                binary_info.bitness = macho::get_bitness(&mach);
                binary_info.file_architecture = if macho::is_arm64(&mach) {
                    binary_info.bitness = 64;
                    FileArchitecture::Aarch64
                } else if binary_info.bitness == 64 {
                    FileArchitecture::AMD64
                } else {
                    FileArchitecture::I386
                };
                binary_info.entry_point = macho::get_entry_point(&mach, binary_info.base_addr);
                binary_info.code_areas = macho::get_code_areas(&mach);
                binary_info.sections = macho::get_sections(&mach);
                binary_info.imports = macho::get_imports(&mach);
                binary_info.exports = macho::get_exports(&mach);
                binary_info.section_maps =
                    macho::map_binary(raw, binary_info.base_addr, macho_arch_preference)?;
            }
            _ => return Err(Error::UnsupportedFormatError),
        }
        binary_info.binary_size = binary_info.compute_binary_size();
        let mut disassembler = Disassembler::with_binary(binary_info)?;
        disassembler.analysis_timeout = timeout;
        disassembler.analysis_started = Some(std::time::Instant::now());

        // 0.4.2 (N1): Go pclntab parse — recover function names from the
        // runtime's PC-line-table blob, if present. Names are seeded into
        // `function_symbols` so the analyser picks them up and the report
        // surfaces them. Addresses are also pulled into the candidate
        // scanner via `get_symbol_candidates`.
        {
            let bi = &disassembler.disassembly.binary_info;
            // For v1.18 / v1.20 we need the .text section VA as the textStart
            // fallback. Pick the first executable section.
            let text_va = bi
                .sections
                .iter()
                .find(|(n, _, _)| n == ".text" || n == ".init" || n == "__text")
                .map(|(_, va, _)| *va)
                .unwrap_or(bi.base_addr);
            let go = pclntab::parse(bi.raw_data, text_va);
            if !go.func_names.is_empty() {
                for (addr, name) in go.func_names {
                    disassembler.disassembly.function_symbols.insert(addr, name);
                }
            }
        }

        // 0.4.2 (MinGW DWARF): for PE binaries, walk .debug_info /
        // .debug_str if present and recover function names from
        // DW_TAG_subprogram DIEs. MinGW-GCC writes these by default;
        // MSVC does not (it uses PDB sidecars). Silent no-op when no
        // DWARF sections are present.
        if disassembler.disassembly.binary_info.file_format == FileFormat::PE {
            let raw = disassembler.disassembly.binary_info.raw_data;
            let base = disassembler.disassembly.binary_info.base_addr;
            let dwarf_syms = dwarf::parse_pe(raw, base);
            for (addr, name) in dwarf_syms {
                // Don't overwrite a Go pclntab name (Go binaries are very
                // unlikely to also carry DWARF, but defensive).
                disassembler
                    .disassembly
                    .function_symbols
                    .entry(addr)
                    .or_insert(name);
            }
        }

        // 0.4.2: Delphi VMT scanner — detects Delphi-compiled binaries by
        // their self-reference vmtSelfPtr pattern, recovers class names
        // from each VMT's Pascal short string, and seeds the user
        // virtual method table as `ClassName::vmt_<idx>` symbols. PE
        // and ELF both. Silent no-op on non-Delphi binaries.
        {
            let delphi_methods = delphi::parse(&disassembler.disassembly.binary_info);
            for (addr, name) in delphi_methods {
                disassembler
                    .disassembly
                    .function_symbols
                    .entry(addr)
                    .or_insert(name);
            }
        }

        disassembler.analyse_buffer(high_accuracy, resolve_tailcalls)?;
        DisassemblyReport::new(&mut disassembler.disassembly)
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
        // 0.4.2: pre-populated function_symbols (Go pclntab, MinGW DWARF,
        // Delphi VMT) are authoritative function-start hints — make sure
        // their addresses are picked up as candidates.
        for s in self.disassembly.function_symbols.keys() {
            symbol_offsets.insert(*s);
        }
        // 0.4.1 (M4): seed candidates from the PE export directory. The
        // export RVAs sit on BinaryInfo.exports — they were collected at
        // load time but pre-0.4.1 only surfaced in the public report.
        // For PE samples (especially stripped DLLs) the export table is
        // often the only reliable list of public-facing function entries.
        //
        // 0.6.0: same seeding extended to Mach-O so AArch64 binaries
        // (and Intel Mach-O) get function-candidate coverage from
        // their export tables. Without this, ARM64 binaries return
        // zero functions because the x86 prologue-scan analysers are
        // gated off and AArch64 has no equivalent yet (lands in 0.6.1).
        let base_addr = self.disassembly.binary_info.base_addr;
        let format = self.disassembly.binary_info.file_format;
        if format == FileFormat::PE || format == FileFormat::MachO {
            for (_name, rva, _forward) in &self.disassembly.binary_info.exports {
                if *rva == 0 {
                    continue;
                }
                // Mach-O exports already store absolute VAs (set in
                // macho::get_exports), so adding base_addr would
                // double-count. PE stores RVAs relative to image
                // base. Branch on format to handle each correctly.
                let va = match format {
                    FileFormat::MachO => *rva as u64,
                    FileFormat::PE => match base_addr.checked_add(*rva as u64) {
                        Some(v) => v,
                        None => continue,
                    },
                    _ => continue,
                };
                symbol_offsets.insert(va);
            }
        }
        // 0.6.0: seed the entry point as a candidate too. The entry
        // is always a real function start; seeding it directly gives
        // arch-agnostic minimum coverage (one function guaranteed)
        // even on binaries where every other seeding heuristic fails.
        if self.disassembly.binary_info.entry_point != 0 {
            symbol_offsets.insert(self.disassembly.binary_info.entry_point);
        }
        Ok(symbol_offsets.iter().copied().collect())
    }

    /// Run analysis on the already-loaded `binary_info` (set via
    /// `with_binary`). Pre-0.4.0 this took an owned `BinaryInfo`
    /// argument; the new API splits construction (`with_binary`) from
    /// analysis to make the lifetime threading explicit.
    pub fn analyse_buffer(
        &mut self,
        high_accuracy: bool,
        resolve_tailcalls: bool,
    ) -> Result<&DisassemblyResult<'a>> {
        // The binary_info is already in self.disassembly (set by with_binary).
        // Just kick off the analysis.
        self.update_label_providers_from_disassembly()?;
        if self.disassembly.binary_info.file_format == FileFormat::ELF {
            match elf::extract_elf_dynamic_apis(self.disassembly.binary_info.raw_data) {
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
        // Best-effort 15-byte read at the candidate VA — returns Err if
        // the address isn't in any section. Empty Vec keeps the caller's
        // "no decode possible" path working.
        match self.disassembly.binary_info.bytes_at_best_effort(addr, 15) {
            Ok(s) => s.to_vec(),
            Err(_) => vec![],
        }
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
        let i_address = ins.offset();
        let i_size = ins.length() as u32;
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
        // Read up to 16 bytes at the thunk VA — best-effort so a short
        // section near EOF still gets scanned for what it has.
        let Ok(bytes) = self
            .disassembly
            .binary_info
            .bytes_at_best_effort(thunk_addr, 16)
        else {
            return Ok(None);
        };
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
        let i_address = ins.offset();
        let i_size = ins.length() as u32;

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
        let i_address = ins.offset();
        let i_size = ins.length() as u32;
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
        let i_address = ins.offset();
        let i_size = ins.length() as u32;
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

    /// Decode a small window through the per-arch [`disassembler::Decoder`]
    /// backend. Returns owned `DecodedInsn` values. For x86 this walks
    /// up to 15 bytes of variable-width decodes; for AArch64 it pulls
    /// 4-byte fixed words.
    fn decode_window(&self, ip: u64) -> Vec<DecodedInsn> {
        let buf = self.get_disasm_window_buffer(ip);
        if buf.is_empty() {
            return vec![];
        }
        let mut out = Vec::with_capacity(4);
        let mut cursor = 0usize;
        while cursor < buf.len() {
            let address = ip.wrapping_add(cursor as u64);
            match self.decoder.decode_at(&buf, cursor, address) {
                Some((insn, consumed)) => {
                    out.push(insn);
                    cursor = cursor.saturating_add(consumed);
                    if consumed == 0 {
                        break;
                    }
                }
                None => break,
            }
        }
        out
    }

    /// (0.4.1 N14) Check the per-disassembly wall-clock budget. Returns
    /// `Err(AnalysisTimeout)` if the budget is exceeded, `Ok(())` if the
    /// timeout is unset or not yet hit.
    #[inline]
    fn check_timeout(&self) -> Result<()> {
        if let (Some(budget), Some(start)) = (self.analysis_timeout, self.analysis_started)
            && start.elapsed() > budget
        {
            return Err(Error::AnalysisTimeout(budget));
        }
        Ok(())
    }

    /// (0.6.0) AArch64-specific function analyser. Linear walker
    /// modelled after the x86 [`Self::analyse_function`] pass, but
    /// dispatching on disarm64's `Mnemonic` + the direct-branch
    /// target resolver in [`disassembler::aarch64_branch_target_raw`].
    ///
    /// Per-instruction control-flow taxonomy (ARM ARM §C6.2):
    /// - `ret` / `eret` / `retaa` / `retab` / `drps`        — function end
    /// - `bl <imm>`  (BL, BRANCH_IMM)                       — direct call:
    ///   record the target as a function candidate so transitive call
    ///   targets become functions on the next analysis pass; continue
    ///   walking past the call (standard ABI: call returns to PC+4).
    /// - `blr <reg>` (BLR, BRANCH_REG)                      — indirect
    ///   call; track on `state.call_register_ins` for the indirect-call
    ///   analyser (which only inspects x86 today, so this is a stub).
    ///   Continue walking past it.
    /// - `b <imm>`   (B,  BRANCH_IMM)                       — uncond
    ///   direct jump. If the target is a known function start or a
    ///   pending candidate, treat as tail call → function end. Else
    ///   add the target to the block worklist and end the block.
    /// - `br <reg>`  (BR, BRANCH_REG)                       — indirect
    ///   jump (tail-call or jump-table). End the block. Without
    ///   register tracking we can't follow it.
    /// - `b.cond` / `cbz` / `cbnz` / `tbz` / `tbnz`         — conditional
    ///   branch. Queue both the target and the fallthrough; end block.
    /// - everything else                                    — pure
    ///   straight-line code, continue.
    ///
    /// The MVP doesn't model PAC indirect calls (`blraa` / `blrab`),
    /// jump tables, exit syscalls (`svc #0` with `x8 = 93/94`), stack-
    /// string detection, or fancy tail-call deduplication; all deferred
    /// to 0.6.1. Even so, a linear walk from each seeded candidate
    /// fans out via `bl` transitive propagation and turns the
    /// historical 0-function output on AArch64 binaries into the
    /// expected dozens-to-thousands.
    fn analyse_function_aarch64(
        &mut self,
        start_addr: u64,
        as_gap: bool,
        high_accuracy: bool,
    ) -> Result<FunctionAnalysisState> {
        use disassembler::{
            aarch64_branch_target_raw, aarch64_is_conditional_branch, aarch64_is_direct_call,
            aarch64_is_indirect_branch, aarch64_is_indirect_call, aarch64_is_return,
            aarch64_is_svc, aarch64_is_trap, aarch64_is_unconditional_branch,
            aarch64_ops::{MovWideKind, decode_mov_wide},
        };
        self.check_timeout()?;
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

        while state.has_unprocessed_blocks() {
            state.choose_next_block()?;
            let start_block = state.block_start;
            let mut cache_pos: usize = 0;
            let mut cache = self.decode_window(start_block);
            // (0.6.1) AArch64 exit-syscall trackers. Two platforms,
            // two ABIs:
            //
            //   Linux:  syscall number in x8,  entry via `svc #0`
            //           — exit=93, exit_group=94.
            //   macOS:  syscall number in x16, entry via `svc #0x80`
            //           — _exit=1, exit_with_payload=472.
            //
            // We track the most recently MOVZ-loaded value for each
            // register separately and key off the SVC's imm16 to pick
            // the right convention. Reset per-block so a syscall in
            // one block doesn't taint another.
            let mut last_x8_imm: Option<u64> = None;
            let mut last_x16_imm: Option<u64> = None;

            loop {
                let mut exit_flag = false;
                for ins in &cache {
                    let i_address = ins.offset();
                    let i_size = ins.length() as u32;
                    cache_pos += i_size as usize;
                    state.set_next_instruction_reachable(true)?;

                    // Pull the disarm64 Opcode + raw word out of the
                    // enum. Anything that isn't AArch64 here would be
                    // a logic bug — this method is dispatched on
                    // FileArchitecture::Aarch64.
                    let (opcode, raw) = match ins {
                        DecodedInsn::Aarch64(a) => (a.decoded, a.opcode),
                        DecodedInsn::X86(_) => {
                            // Defensive: skip — shouldn't happen.
                            continue;
                        }
                    };

                    if aarch64_is_return(&opcode) {
                        self.analyze_end_instruction(&mut state)?;
                    } else if aarch64_is_direct_call(&opcode) {
                        // `bl <imm26>` — direct PC-relative call. Resolve
                        // the target and add it as a function candidate;
                        // the second `get_queue` pass picks it up.
                        state.set_leaf(false)?;
                        if let Some(target) = aarch64_branch_target_raw(&opcode, raw, i_address)
                            && self.disassembly.is_addr_within_memory_image(target)?
                        {
                            state.add_code_ref(i_address, target, false)?;
                            if state.start_addr == target {
                                state.set_recursion(true)?;
                            }
                            // Seed as a reference candidate so the
                            // outer analysis-loop picks the target up
                            // as a new function on its next pass.
                            self.fc_manager.add_reference_candidate(
                                target,
                                i_address,
                                &self.disassembly,
                            )?;
                        }
                        // BL doesn't end the block — the ABI says control
                        // returns to PC+4. Fall through.
                    } else if aarch64_is_indirect_call(&opcode) {
                        // Indirect call via register: `blr <reg>` or any
                        // PAC variant (`blraa`/`blraaz`/`blrab`/`blrabz`).
                        // Track for the indirect-call analyser (x86-only
                        // today; included here for forward compatibility).
                        state.set_leaf(false)?;
                        state.call_register_ins.push(i_address);
                        // Falls through — `blr*` returns to PC+4.
                    } else if aarch64_is_unconditional_branch(&opcode) {
                        // `b <imm26>` — direct unconditional jump. If
                        // the destination is a known/expected function,
                        // treat as a tail call → function end. Otherwise
                        // queue the target as another block of the same
                        // function and end the current block.
                        if let Some(target) = aarch64_branch_target_raw(&opcode, raw, i_address)
                            && self.disassembly.is_addr_within_memory_image(target)?
                        {
                            // Only seed cross-references for targets we
                            // can actually reach — otherwise we pollute
                            // ins2fn / code_refs with phantom edges to
                            // unmapped addresses.
                            state.add_code_ref(i_address, target, true)?;
                            // (0.6.1) Feed direct `b` jumps into the
                            // tail-call analyser so off-function targets
                            // get promoted to candidates by
                            // `TailCallAnalyser::finalize_function`.
                            self.tailcall_analyzer.add_jump(i_address, target)?;
                            let is_known_function =
                                self.disassembly.functions.contains_key(&target);
                            let is_candidate = self
                                .fc_manager
                                .get_function_start_candidates()?
                                .contains(&target);
                            if is_known_function {
                                state.set_sanely_ending(true)?;
                            } else if !is_candidate {
                                if !state.is_first_instruction()? {
                                    // Intra-function `b` — same-fn block.
                                    state.add_block_to_queue(target)?;
                                } else if target != i_address {
                                    // Single-instruction stub thunk
                                    // (`b <api>` as the whole function).
                                    // Seed the target as a candidate so
                                    // the resolver picks it up. Skip the
                                    // degenerate `b .` self-jump (infinite
                                    // loop sentinel / debugger trap) to
                                    // avoid re-queueing the current
                                    // function as a candidate of itself.
                                    self.fc_manager.add_reference_candidate(
                                        target,
                                        i_address,
                                        &self.disassembly,
                                    )?;
                                }
                            }
                            // else: target is already a pending candidate
                            // — treat the `b` as a tail call and let the
                            // candidate analyser walk it separately.
                        }
                        state.set_next_instruction_reachable(false)?;
                        state.set_block_ending_instruction(true)?;
                    } else if aarch64_is_indirect_branch(&opcode) {
                        // Indirect jump: `br <reg>` or any PAC variant
                        // (`braa`/`braaz`/`brab`/`brabz`). Best-effort
                        // jump-table resolution first (handles the
                        // canonical Clang / GCC switch lowerings); if
                        // the back-walk doesn't match, the BR ends the
                        // block as a tail-call edge.
                        let targets = self
                            .jumptable_analyzer
                            .get_jump_targets_aarch64(ins, self, &mut state)
                            .unwrap_or_default();
                        for target in targets {
                            // is_addr_within_memory_image was already
                            // checked inside the resolver; defensive
                            // re-check just keeps the walker's contract
                            // unchanged.
                            if self.disassembly.is_addr_within_memory_image(target)? {
                                state.add_code_ref(i_address, target, true)?;
                                state.add_block_to_queue(target)?;
                            }
                        }
                        state.set_next_instruction_reachable(false)?;
                        state.set_sanely_ending(true)?;
                        state.set_block_ending_instruction(true)?;
                    } else if aarch64_is_trap(&opcode) {
                        // `udf` / `brk` / `hlt` — unconditional trap.
                        // Compilers emit these after noreturn calls
                        // (`abort`, `__stack_chk_fail`) or as bounds-
                        // check poison. Whatever follows in the byte
                        // stream is typically a constant-pool word or
                        // padding, not real code. End the block and
                        // mark it sane.
                        state.set_next_instruction_reachable(false)?;
                        state.set_sanely_ending(true)?;
                        state.set_block_ending_instruction(true)?;
                    } else if aarch64_is_svc(&opcode) && {
                        // svc #imm16: imm16 lives at bits 20:5 of the
                        // 32-bit encoding. 0x00 → Linux entry, 0x80 →
                        // macOS BSD/Mach entry.
                        let svc_imm = ((raw >> 5) & 0xFFFF) as u16;
                        match svc_imm {
                            //   mov w8, #93  ; svc #0  → exit
                            //   mov w8, #94  ; svc #0  → exit_group
                            0x00 => matches!(last_x8_imm, Some(93 | 94)),
                            //   mov x16, #1   ; svc #0x80  → _exit (BSD)
                            //   mov x16, #472 ; svc #0x80  → exit_with_payload
                            0x80 => matches!(last_x16_imm, Some(1 | 472)),
                            _ => false,
                        }
                    } {
                        // Recognised exit syscall — end the function.
                        // The kernel doesn't return for these. Non-exit
                        // syscalls fall through to the next instruction
                        // (correct behaviour: most syscalls return to
                        // user space).
                        state.set_next_instruction_reachable(false)?;
                        state.set_sanely_ending(true)?;
                        state.set_block_ending_instruction(true)?;
                    } else if aarch64_is_conditional_branch(&opcode) {
                        // `b.cond` / `cbz` / `cbnz` / `tbz` / `tbnz`.
                        // Two-way fork: queue both the taken target
                        // and the fallthrough.
                        let fall_through = i_address.wrapping_add(i_size as u64);
                        state.add_block_to_queue(fall_through)?;
                        if let Some(target) = aarch64_branch_target_raw(&opcode, raw, i_address)
                            && self.disassembly.is_addr_within_memory_image(target)?
                        {
                            // Only seed cross-references for targets we
                            // can actually reach — out-of-image branches
                            // (corrupted imm19/imm14 from data-in-code
                            // or partial decode) would pollute ins2fn.
                            let is_known_function =
                                self.disassembly.functions.contains_key(&target);
                            let is_candidate = self
                                .fc_manager
                                .get_function_start_candidates()?
                                .contains(&target);
                            if is_known_function {
                                state.set_sanely_ending(true)?;
                            } else if !is_candidate {
                                state.add_block_to_queue(target)?;
                            }
                            // else: target is already a candidate — treat
                            // the conditional branch as a tail call and
                            // skip queueing it as another block of *this*
                            // function.
                            state.add_code_ref(i_address, target, true)?;
                            // (0.6.1) Feed conditional-branch jumps
                            // into the tail-call analyser too — Rust
                            // and Go in particular generate conditional
                            // tail calls from `if x { panic() }` lowering.
                            self.tailcall_analyzer.add_jump(i_address, target)?;
                        }
                        state.set_block_ending_instruction(true)?;
                    }

                    // (0.6.1) Exit-syscall tracker update for x8 (Linux
                    // ABI) and x16 (macOS BSD/Mach ABI). We model the
                    // full MOV-wide family:
                    //
                    //   MOVZ Rd, #imm, LSL #(hw*16)
                    //     → tracker = imm << (hw*16) (zeroes other slots)
                    //   MOVN Rd, #imm, LSL #(hw*16)
                    //     → tracker = !(imm << (hw*16))
                    //   MOVK Rd, #imm, LSL #(hw*16)
                    //     → tracker[slot hw] = imm (keep other slots)
                    //
                    // Any other instruction writing the register clears
                    // the tracker — the syscall recogniser then needs
                    // a fresh MOV-wide before the next SVC.
                    let update =
                        |tracker: &mut Option<u64>, value: u64, kind: MovWideKind, hw_raw: u32| {
                            match kind {
                                MovWideKind::Movz | MovWideKind::Movn => *tracker = Some(value),
                                MovWideKind::Movk => {
                                    // value already has the LSL applied; we need to
                                    // mask out the 16-bit slot at `hw` in the
                                    // existing tracker value (or 0) and OR in the
                                    // new bits.
                                    //
                                    // (0.6.1, M2) `hw_raw` is already masked with
                                    // 0x3 at the call site below (bits 22:21 — 2
                                    // bits, range 0..=3). The shift `hw * 16` is
                                    // therefore provably 0/16/32/48, well within
                                    // u64. Redundant `& 0x3` kept defensively.
                                    let hw = hw_raw & 0x3;
                                    let slot_mask: u64 = 0xFFFFu64 << (hw * 16);
                                    let prev = tracker.unwrap_or(0);
                                    *tracker = Some((prev & !slot_mask) | (value & slot_mask));
                                }
                            }
                        };
                    if let Some((rd, value, kind)) = decode_mov_wide(raw) {
                        // `hw` lives at bits 22:21 — re-extract it directly
                        // because `decode_mov_wide` only returns the
                        // already-shifted value.
                        let hw_raw = (raw >> 21) & 0x3;
                        match rd {
                            8 => update(&mut last_x8_imm, value, kind, hw_raw),
                            16 => update(&mut last_x16_imm, value, kind, hw_raw),
                            _ => {
                                // MOV-wide to some other register — leave
                                // the syscall trackers alone.
                            }
                        }
                    } else {
                        // Conservative: any other instruction *might* have
                        // written x8 or x16 (we don't model the full ABI).
                        // Reset so each tracker only fires on a prior
                        // MOV-wide sequence.
                        last_x8_imm = None;
                        last_x16_imm = None;
                    }

                    // Register the instruction itself (after the flow-
                    // control bookkeeping above, matching the x86 path's
                    // sequencing). Collisions with previously-mapped
                    // code mean we ran into someone else's function —
                    // stop and let the existing analysis stand.
                    if !self.disassembly.code_map.contains_key(&i_address)
                        && !self.disassembly.data_map.contains(&i_address)
                        && !state.is_processed(&i_address)?
                    {
                        state.add_instruction(*ins)?;
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
        // (0.6.1) Mirror the x86 path: finalize analysis, then
        // - resolve indirect calls (`BLR x16` through GOT thunks) so
        //   imports surface as `apis` entries and recovered in-image
        //   targets become new function candidates,
        // - promote bare-`b`/`b.cond` jumps recorded during the walk
        //   into tail-call candidates so off-function targets become
        //   their own functions on the next analyser pass.
        if state
            .finalize_analysis(as_gap, &mut self.disassembly)
            .is_ok()
        {
            // block_depth=4 mirrors the x86 path's resolve_register_calls
            // call site — controls how many predecessor levels the
            // back-walk descends through.
            let (api_e, cand_e) = self
                .indirect_call_analyser
                .resolve_register_calls_aarch64(self, &mut state, 4)?;
            for (addr, entry) in api_e {
                match self.disassembly.apis.get_mut(&addr) {
                    Some(s) => {
                        s.referencing_addr.extend(entry.referencing_addr.clone());
                    }
                    None => {
                        self.disassembly.apis.insert(addr, entry);
                    }
                }
            }
            for (target, source) in cand_e {
                self.fc_manager
                    .add_candidate(target, false, Some(source), &self.disassembly)?;
            }
            TailCallAnalyser::finalize_function(self, &state)?;
        }
        self.fc_manager.update_analysis_finished(&start_addr)?;
        if high_accuracy {
            self.fc_manager.update_candidates(&state)?;
        }
        Ok(state)
    }

    fn analyse_function(
        &mut self,
        start_addr: u64,
        as_gap: bool,
        high_accuracy: bool,
    ) -> Result<FunctionAnalysisState> {
        // 0.6.0: dispatch on architecture. The x86 path below is
        // packed with iced-specific assumptions (FlowControl
        // taxonomy, `0xEB` short-jump byte, x86 mnemonic enum
        // comparisons); AArch64 gets its own linear-walker that
        // uses disarm64's mnemonic + the pre-computed direct-branch
        // target resolver in `disassembler::aarch64_branch_target`.
        if matches!(
            self.disassembly.binary_info.file_architecture,
            FileArchitecture::Aarch64
        ) {
            return self.analyse_function_aarch64(start_addr, as_gap, high_accuracy);
        }
        self.check_timeout()?;
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
            // (0.4.1 M2) Track the most recent `mov eax/rax, IMM` value so
            // we can recognise the Linux exit-syscall convention
            // (`mov eax, 60; syscall` and `mov eax, 0xfc; int 0x80`) as a
            // genuine function end, not a mid-function syscall that
            // returns.
            let mut last_exit_reg_imm: Option<u64> = None;

            loop {
                let mut exit_flag = false;
                for ins in &cache {
                    let i_address = ins.offset();
                    let i_size = ins.length() as u32;
                    // x86 mnemonic enum, or a no-op sentinel on AArch64.
                    // The x86-specific match arms below gate on
                    // `flow_control_x86().is_some()` (via the unwrap
                    // default `FlowControl::Next`) so they no-op on
                    // AArch64; arch-agnostic block-ending is handled
                    // by the trailing branch on `DecodedInsn::is_*`.
                    let mnemonic_enum = ins.mnemonic_enum_x86().unwrap_or(Mnemonic::INVALID);
                    let mut mnemonic_str = String::new();
                    let op_str = match ins.as_iced() {
                        Some(iced) => {
                            fmt.format_mnemonic(iced, &mut mnemonic_str);
                            if iced.op_count() == 0 {
                                String::new()
                            } else {
                                let mut s = String::new();
                                fmt.format_all_operands(iced, &mut s);
                                s
                            }
                        }
                        None => {
                            // AArch64: use disarm64's mnemonic + a debug
                            // rendering of the operand bits for the
                            // legacy regex-driven heuristics. They won't
                            // match — the analyser falls through to the
                            // arch-agnostic block-ending branch below.
                            mnemonic_str = ins.format_mnemonic();
                            ins.format_operands().unwrap_or_default()
                        }
                    };

                    cache_pos += i_size as usize;
                    state.set_next_instruction_reachable(true)?;

                    // Check for the "00 00" suspicious-instruction marker by
                    // peeking at the bytes for this instruction. bytes_at
                    // returns Err on a section boundary, which we treat as
                    // "not the suspicious pattern".
                    if self
                        .disassembly
                        .binary_info
                        .bytes_at(i_address, i_size)
                        .map(|b| b == b"\x00\x00")
                        .unwrap_or(false)
                    {
                        state.suspicious_ins_count += 1;
                        if state.suspicious_ins_count > 1 {
                            self.fc_manager.update_analysis_aborted(
                                &start_addr,
                                &format!("too many suspicious instructions 0x{i_address:08x}"),
                            )?;
                            return Ok(state);
                        }
                    }

                    // x86 control-flow taxonomy via iced FlowControl.
                    // On AArch64 we default to FlowControl::Next so all
                    // x86 arms fall through; the arch-agnostic call /
                    // jump / return helpers handle block-ending below.
                    let fc = ins.flow_control_x86().unwrap_or(FlowControl::Next);
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
                    } else if ins.as_iced().is_none() && ins.is_return() {
                        // AArch64 ret — end the block. Other AArch64
                        // branch families (b / bl / b.cond / cbz / tbz)
                        // fall through with `Next` FlowControl and will
                        // be picked up by the block-ending check at the
                        // bottom of the per-instruction body.
                        self.analyze_end_instruction(&mut state)?;
                    } else if Self::is_exit_syscall(ins, last_exit_reg_imm) {
                        // Linux exit syscall conventions:
                        //   x86_64: mov eax, 60 ; syscall          (exit)
                        //   x86_64: mov eax, 231; syscall          (exit_group)
                        //   x86:    mov eax, 1  ; int 0x80         (exit)
                        //   x86:    mov eax, 252; int 0x80         (exit_group)
                        // Treat the syscall site as a function end so the
                        // analyser stops following past it.
                        self.analyze_end_instruction(&mut state)?;
                    } else if ins.as_iced().is_none() && ins.is_branch() {
                        // AArch64 generic branch path: any unconditional
                        // jump (b / br) or conditional branch
                        // (b.cond / cbz / cbnz / tbz / tbnz) ends the
                        // current block. Full follow-the-target lands in
                        // 0.6.1; for 0.6.0 we get a linear-block CFG.
                        state.set_block_ending_instruction(true)?;
                    } else if let Some(prev) = previous_address
                        && prev != 0
                        && i_address != start_addr
                        && previous_mnemonic_str.as_deref() == Some("call")
                    {
                        let instruction_sequence = self.decode_window(i_address);
                        let is_align = self
                            .fc_manager
                            .is_alignment_sequence(&instruction_sequence, &self.disassembly)?;
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
                    // (0.4.1 M2) Update the exit-syscall register tracker.
                    last_exit_reg_imm = Self::extract_exit_reg_imm(ins, last_exit_reg_imm);
                    if !self.disassembly.code_map.contains_key(&i_address)
                        && !self.disassembly.data_map.contains(&i_address)
                        && !state.is_processed(&i_address)?
                    {
                        state.add_instruction(*ins)?;
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

    /// (0.4.1 M2) Track `mov eax, IMM` / `mov rax, IMM` to feed the
    /// exit-syscall recogniser. Returns the new "last exit reg imm"
    /// state. Any non-mov-to-{e,r,a}ax instruction clears the tracker
    /// (because the exit number must be set *immediately* before the
    /// syscall to be the actual call number).
    fn extract_exit_reg_imm(ins: &DecodedInsn, current: Option<u64>) -> Option<u64> {
        use iced_x86::Register;
        // x86 only — AArch64 exit-syscall recognition lands in 0.6.1.
        let Some(iced) = ins.as_iced() else {
            return current;
        };

        // Path 1: `mov eax-family, <imm>` snapshots the tracker.
        if iced.mnemonic() == Mnemonic::Mov
            && iced.op_count() >= 2
            && iced.op_kind(0) == iced_x86::OpKind::Register
            && matches!(
                iced.op_register(0),
                Register::EAX | Register::RAX | Register::AX | Register::AL
            )
        {
            return match iced.op_kind(1) {
                iced_x86::OpKind::Immediate8 => Some(iced.immediate8() as u64),
                iced_x86::OpKind::Immediate16 => Some(iced.immediate16() as u64),
                iced_x86::OpKind::Immediate32 => Some(iced.immediate32() as u64),
                iced_x86::OpKind::Immediate64 => Some(iced.immediate64()),
                iced_x86::OpKind::Immediate8to32 => Some(iced.immediate8to32() as u64),
                iced_x86::OpKind::Immediate8to64 => Some(iced.immediate8to64() as u64),
                iced_x86::OpKind::Immediate32to64 => Some(iced.immediate32to64() as u64),
                // `mov eax, mem` / `mov eax, ebx` — can't statically
                // determine the value; clear conservatively.
                _ => None,
            };
        }

        // (0.6.1, upstream issue #119) Path 2: any instruction whose
        // op0 is eax-family clobbers the tracker (add eax, …;
        // xor eax, eax; lea eax, …; pop eax; etc.).
        if iced.op_count() >= 1
            && iced.op_kind(0) == iced_x86::OpKind::Register
            && matches!(
                iced.op_register(0),
                Register::EAX | Register::RAX | Register::AX | Register::AL
            )
        {
            return None;
        }

        // Path 3: instructions with implicit eax/rax side-effects.
        // These don't have eax as op0 but still clobber it.
        if matches!(
            iced.mnemonic(),
            Mnemonic::Cpuid
                | Mnemonic::Rdtsc
                | Mnemonic::Rdtscp
                | Mnemonic::Rdrand
                | Mnemonic::Rdseed
                | Mnemonic::Xgetbv
                | Mnemonic::Lahf
                | Mnemonic::Xlatb
                | Mnemonic::Cdq
                | Mnemonic::Cwde
                | Mnemonic::Cdqe
                | Mnemonic::Cqo
                | Mnemonic::Cbw
                | Mnemonic::Mul
                | Mnemonic::Div
                | Mnemonic::Idiv
        ) {
            return None;
        }

        // (0.6.1, upstream issue #119) Path 4: anything else preserves
        // the tracker. Previously cleared on every non-mov-to-eax
        // instruction, defeating multi-instruction `mov edi, arg0; mov
        // eax, 60; syscall` patterns. The clobber checks above
        // (op0 + implicit-side-effect mnemonics) keep us correct.
        current
    }

    /// (0.4.1 M2) Recognise the Linux exit-syscall convention. Linux
    /// `exit` is 60 / `exit_group` is 231 on x86_64 (via `syscall`); 1 /
    /// 252 respectively on x86 (via `int 0x80`). x86 only — AArch64
    /// equivalent (`svc #0` with x8 = 93/94) lands in 0.6.1.
    fn is_exit_syscall(ins: &DecodedInsn, last_eax_imm: Option<u64>) -> bool {
        let Some(iced) = ins.as_iced() else {
            return false;
        };
        let mnem = iced.mnemonic();
        let imm = match last_eax_imm {
            Some(v) => v,
            None => return false,
        };
        if matches!(mnem, Mnemonic::Syscall | Mnemonic::Sysenter) {
            return matches!(imm, 60 | 231 | 252);
        }
        if mnem == Mnemonic::Int
            && iced.op_count() == 1
            && let iced_x86::OpKind::Immediate8 = iced.op_kind(0)
            && iced.immediate8() == 0x80
        {
            return matches!(imm, 1 | 252 | 60);
        }
        false
    }

    fn update_label_providers_from_disassembly(&mut self) -> Result<()> {
        // Disjoint-field borrow: split self into the two fields we touch
        // so we can pass `&binary_info` (immut) to a method taking
        // `&mut label_providers`. Avoids needing `unsafe`.
        let Disassembler {
            label_providers,
            disassembly,
            ..
        } = self;
        for provider in label_providers.iter_mut() {
            provider.update(&disassembly.binary_info)?;
        }
        Ok(())
    }
}
