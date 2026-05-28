use crate::disassembler::DecodedInsn;
use crate::{
    DisassemblyResult, FileArchitecture, FunctionAnalysisState, Result, error::Error,
    function_candidate::FunctionCandidate,
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use itertools::Itertools;
use regex::bytes::Regex as BytesRegex;
use std::sync::LazyLock;
use std::{collections::BTreeMap, collections::HashMap, convert::TryInto};

/// Default function-prologue byte patterns scanned across each section.
///
/// Sources:
/// - The first four are classic MSVC: `mov edi, edi; push ebp; mov ebp, esp`
///   (the `8B FF` "hotpatch NOP"), plain `push ebp; mov ebp, esp`, and
///   the AT&T-syntax variant `push ebp; mov ebp, esp` (`55 89 E5`).
/// - 0.4.1 adds:
///   - `F3 0F 1E FA` — `endbr64`, the Intel CET indirect-branch landing
///     pad emitted by GCC / clang with `-fcf-protection` (default on
///     modern Ubuntu, Fedora, RHEL, Debian). Almost every function in a
///     modern dynamically-linked ELF starts with this.
///   - `F3 0F 1E FB` — `endbr32`, the 32-bit equivalent.
///   - `48 89 5C 24 ??` — `mov [rsp+disp8], rbx`, a very common GCC
///     callee-saved-register save in the function preamble.
///   - `48 83 EC ??` — `sub rsp, imm8`, the canonical Sys V AMD64 stack
///     frame setup when no `rbp` chain is used.
///   - `41 57 41 56` — `push r15; push r14`, the start of a typical
///     GCC-emitted register save sequence for functions that touch the
///     extended registers.
static DEFAULT_PROLOGUES: LazyLock<Vec<BytesRegex>> = LazyLock::new(|| {
    vec![
        // MSVC family (32 / 64 bit)
        BytesRegex::new(r"(?-u)\x8B\xFF\x55\x8B\xEC").unwrap(),
        BytesRegex::new(r"(?-u)\x89\xFF\x55\x8B\xEC").unwrap(),
        BytesRegex::new(r"(?-u)\x55\x8B\xEC").unwrap(),
        BytesRegex::new(r"(?-u)\x55\x89\xE5").unwrap(),
        // Intel CET landing pads — used by GCC / clang with -fcf-protection
        BytesRegex::new(r"(?-u)\xF3\x0F\x1E\xFA").unwrap(), // endbr64
        BytesRegex::new(r"(?-u)\xF3\x0F\x1E\xFB").unwrap(), // endbr32
        // GCC / clang Sys V AMD64 prologue families. The `[\S\s]` matches
        // any single byte for the imm8 displacement.
        BytesRegex::new(r"(?-u)\x48\x89\x5C\x24[\S\s]").unwrap(), // mov [rsp+disp8], rbx
        BytesRegex::new(r"(?-u)\x48\x83\xEC[\S\s]").unwrap(),     // sub rsp, imm8
        BytesRegex::new(r"(?-u)\x41\x57\x41\x56").unwrap(),       // push r15; push r14
        // 0.5.2 — Apple-clang x86_64 patterns that previously slipped
        // through (smda-rs missed most /bin/ls-style binaries because of
        // these absences). All very specific multi-byte sequences so the
        // false-positive rate stays low.
        BytesRegex::new(r"(?-u)\x55\x48\x89\xE5").unwrap(), // push rbp; mov rbp, rsp
        BytesRegex::new(r"(?-u)\x48\x81\xEC[\S\s]{4}").unwrap(), // sub rsp, imm32 (large frame)
        BytesRegex::new(r"(?-u)\x48\x89\x6C\x24[\S\s]").unwrap(), // mov [rsp+disp8], rbp
        BytesRegex::new(r"(?-u)\x41\x56\x53").unwrap(),     // push r14; push rbx
        BytesRegex::new(r"(?-u)\x41\x55\x41\x54").unwrap(), // push r13; push r12
        BytesRegex::new(r"(?-u)\x53\x48\x83\xEC").unwrap(), // push rbx; sub rsp, ...
    ]
});
static REF_CANDIDATE: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)\xE8").unwrap());
static BITNESS: LazyLock<BytesRegex> = LazyLock::new(|| BytesRegex::new(r"(?-u)\xFF\x25").unwrap());
static STUB_CHAIN: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)(?P<block>(\xFF\x25[\S\s]{4}){2,})").unwrap());
static STUB_CHAIN_FUNC: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)\xFF\x25(?P<function>[\S\s]{4})").unwrap());
static STUB_CHAIN_BLOCK: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(r"(?-u)(?P<block>(\xFF\x25[\S\s]{4}\x68[\S\s]{4}\xE9[\S\s]{4}){2,})").unwrap()
});
static STUB_CHAIN_BLOCK_FUNC: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)\xFF\x25(?P<function>[\S\s]{4})").unwrap());
static CELL_MATCH: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)\xFF\x15").unwrap());

#[derive(Debug)]
struct GapSequences {
    gs: HashMap<usize, Vec<Vec<u8>>>,
}

impl GapSequences {
    pub fn new() -> GapSequences {
        let mut gs = GapSequences { gs: HashMap::new() };
        gs.gs.insert(
            1,
            vec![
                b"\x90".to_vec(), //NOP1_OVERRIDE_NOP - AMD / nop - INTEL
                b"\xCC".to_vec(), //int3
                b"\x00".to_vec(), //pass over sequences of null bytes
            ],
        );
        gs.gs.insert(
            2,
            vec![
                b"\x66\x90".to_vec(), //NOP2_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8b\xc0".to_vec(),
                b"\x8b\xff".to_vec(), //mov edi, edi
                b"\x8d\x00".to_vec(), //lea eax, dword ptr [eax]
                b"\x86\xc0".to_vec(), //xchg al, al
                b"\x66\x2e".to_vec(), //NOP2_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x89\xf6".to_vec(), //mov esi, esi
            ],
        );
        gs.gs.insert(
            3,
            vec![
                b"\x0f\x1f\x00".to_vec(), // NOP3_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\x40\x00".to_vec(), // lea eax, dword ptr [eax]
                b"\x8d\x00\x00".to_vec(), // lea eax, dword ptr [eax]
                b"\x8d\x49\x00".to_vec(), // lea ecx, dword ptr [ecx]
                b"\x8d\x64\x24".to_vec(), // lea esp, dword ptr [esp]
                b"\x8d\x76\x00".to_vec(),
                b"\x66\x66\x90".to_vec(),
            ],
        );
        gs.gs.insert(
            4,
            vec![
                b"\x0f\x1f\x40\x00".to_vec(), // NOP4_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\x74\x26\x00".to_vec(),
                b"\x66\x66\x66\x90".to_vec(),
            ],
        );
        gs.gs.insert(
            5,
            vec![
                b"\x0f\x1f\x44\x00\x00".to_vec(), //NOP5_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x90\x8d\x74\x26\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            6,
            vec![
                b"\x66\x0f\x1f\x44\x00\x00".to_vec(), // NOP6_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\xb6\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            7,
            vec![
                b"\x0f\x1f\x80\x00\x00\x00\x00".to_vec(), // NOP7_OVERRIDE_NOP - AMD / nop - INTEL,
                b"\x8d\xb4\x26\x00\x00\x00\x00".to_vec(),
                b"\x8D\xBC\x27\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            8,
            vec![
                b"\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP8_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x90\x8d\xb4\x26\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            9,
            vec![
                b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP9_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x89\xf6\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            10,
            vec![
                b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP10_OVERRIDE_NOP - AMD
                b"\x8d\x76\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            11,
            vec![
                b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP11_OVERRIDE_NOP - AMD
                b"\x8d\x74\x26\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            12,
            vec![
                b"\x8d\xb6\x00\x00\x00\x00\x8d\xbf\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            13,
            vec![
                b"\x8d\xb6\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            14,
            vec![
                b"\x8d\xb4\x26\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            15,
            vec![b"\x66\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec()],
        );
        gs
    }
}

#[derive(Debug)]
pub struct FunctionCandidateManager {
    pub bitness: u32,
    identified_alignment: u32,
    code_areas: Vec<(u64, u64)>,
    all_call_refs: HashMap<u64, u64>,
    pub symbol_addresses: Vec<u64>,
    pub candidates: BTreeMap<u64, FunctionCandidate>,
    candidate_offsets: Vec<u64>,
    gs: GapSequences,
    candidate_queue: Vec<u64>,
    gap_pointer: u64,
    previously_analyzed_gap: u64,
    function_gaps: Vec<(u64, u64, u64)>,
}

impl FunctionCandidateManager {
    pub fn new() -> FunctionCandidateManager {
        FunctionCandidateManager {
            bitness: 0,
            identified_alignment: 0,
            code_areas: vec![],
            all_call_refs: HashMap::new(),
            symbol_addresses: vec![],
            candidates: BTreeMap::<u64, FunctionCandidate>::new(),
            candidate_offsets: vec![],
            gs: GapSequences::new(),
            candidate_queue: vec![],
            gap_pointer: 0,
            previously_analyzed_gap: 0,
            function_gaps: vec![],
        }
    }

    pub fn init(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        self.bitness = disassembly.binary_info.bitness;
        self.identified_alignment = 0;
        self.code_areas = disassembly.binary_info.code_areas.clone();
        self.locate_candidates(disassembly)?;
        Ok(())
    }

    fn locate_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        self.locate_symbol_candidates(disassembly)?;
        self.locate_reference_candidates(disassembly)?;
        self.locate_prologue_candidates(disassembly)?;
        //       self.locateLangSpecCandidates()?;
        self.locate_stub_chain_candidates(disassembly)?;
        self.locate_exception_handler_candidates(disassembly)?;
        self.identified_alignment = self.identify_alignment()?;
        Ok(())
    }

    fn locate_symbol_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let s = self.symbol_addresses.clone();
        for symbol_addr in s {
            self.add_symbol_candidate(&symbol_addr, disassembly)?;
        }
        Ok(())
    }

    fn add_symbol_candidate(
        &mut self,
        addr: &u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(*addr))? {
            return Ok(false);
        }
        self.ensure_candidate(*addr, disassembly)?;
        if let Some(s) = self.candidates.get_mut(addr) {
            s.set_is_symbol(true)?;
            s.set_initial_candidate();
        }
        Ok(true)
    }

    fn identify_alignment(&self) -> Result<u32> {
        let mut identified_alignment = 0;
        //        if self.config.USE_ALIGNMENT:
        // (0.6.1) Collapsed the previous three sequential scans over
        // `self.candidates.values()` (one each for total / 16-aligned /
        // 4-aligned counts) into a single pass — mirrors upstream
        // perf PR #109. ~3x reduction in iterator overhead on
        // hot-path analyses.
        let mut num_candidates = 0;
        let mut num_aligned_16_candidates = 0;
        let mut num_aligned_4_candidates = 0;
        for candidate in self.candidates.values() {
            if candidate.call_ref_sources.len() > 1 {
                num_candidates += 1;
                match candidate.alignment {
                    16 => num_aligned_16_candidates += 1,
                    4 => num_aligned_4_candidates += 1,
                    _ => {}
                }
            }
        }
        if num_candidates > 0 {
            let alignment_16_ratio = 1.0 * num_aligned_16_candidates as f32 / num_candidates as f32;
            let alignment_4_ratio = 1.0 * num_aligned_4_candidates as f32 / num_candidates as f32;
            if num_candidates > 20 && alignment_4_ratio > 0.95 {
                identified_alignment = 4;
            }
            if num_candidates > 20 && alignment_16_ratio > 0.95 {
                identified_alignment = 16;
            }
        }
        Ok(identified_alignment)
    }

    /// PE x64 `.pdata` sweep — seeds the candidate scanner with function
    /// starts published by the exception-handler runtime.
    ///
    /// 0.4.2 (M3) tightens validation: each `RUNTIME_FUNCTION` entry now
    /// has its `EndAddress`, `UnwindInfoAddress`, and the pointed-at
    /// `UNWIND_INFO` header checked before the `BeginAddress` is accepted
    /// as a candidate. Drops false-positive seeds from packed or
    /// partially-overwritten `.pdata` sections that the 0.4.1 blind sweep
    /// accepted unconditionally.
    ///
    /// Validation rules (all must hold):
    /// - `EndAddress > BeginAddress`
    /// - `EndAddress - BeginAddress < 16 MiB` (anything larger is almost
    ///   certainly a junk entry rather than a real function range)
    /// - `UnwindInfoAddress` resolves to a VA inside the image
    /// - The `UNWIND_INFO` first byte's low 3 bits (Version) is 1 or 2
    /// - The implied UNWIND_INFO record (4-byte header + `2 * CountOfCodes`
    ///   bytes) fits inside the image
    fn locate_exception_handler_candidates(
        &mut self,
        disassembly: &DisassemblyResult,
    ) -> Result<()> {
        if self.bitness != 64 {
            return Ok(());
        }
        // 0.6.1: ARM64 Windows PE `.pdata` uses a structurally distinct
        // schema from x64 SEH — each `RUNTIME_FUNCTION` entry is 8 bytes
        // (`BeginAddress: u32`, `UnwindData: u32`) instead of x64's
        // 12-byte (Begin, End, UnwindInfo) triple, and `UnwindData` is
        // either a pointer-to-.xdata (bits 1:0 == 00) or a packed
        // unwind record (bits 1:0 != 00). For function discovery we
        // only need `BeginAddress`; UnwindData validation is deferred.
        if matches!(
            disassembly.binary_info.file_architecture,
            FileArchitecture::Aarch64
        ) {
            return self.locate_exception_handler_candidates_aarch64(disassembly);
        }
        let base_addr = disassembly.binary_info.base_addr;
        let bi = &disassembly.binary_info;
        const MAX_FUNC_SPAN: u64 = 16 * 1024 * 1024; // 16 MiB
        for (section_name, section_va_start, section_va_end) in bi.get_sections()? {
            if section_name != ".pdata" {
                continue;
            }
            let mut va = section_va_start;
            while va.checked_add(12).is_some_and(|e| e <= section_va_end) {
                let Ok(packed) = bi.bytes_at(va, 12) else {
                    break;
                };
                let begin_rva =
                    u32::from_le_bytes(packed[0..4].try_into().unwrap_or([0; 4])) as u64;
                let end_rva = u32::from_le_bytes(packed[4..8].try_into().unwrap_or([0; 4])) as u64;
                let unwind_rva =
                    u32::from_le_bytes(packed[8..12].try_into().unwrap_or([0; 4])) as u64;

                // Advance for the next iteration before any continue so we
                // make progress even when validation rejects this entry.
                let Some(next) = va.checked_add(12) else {
                    break;
                };
                va = next;

                if begin_rva == 0 {
                    // All-zero terminator entries are common at the end of .pdata.
                    continue;
                }
                if end_rva <= begin_rva || (end_rva - begin_rva) > MAX_FUNC_SPAN {
                    continue;
                }
                let Some(unwind_va) = base_addr.checked_add(unwind_rva) else {
                    continue;
                };
                let Ok(unwind_hdr) = bi.bytes_at(unwind_va, 4) else {
                    continue;
                };
                let version = unwind_hdr[0] & 0x07;
                if version != 1 && version != 2 {
                    continue;
                }
                // CountOfCodes is a u8, so unwind_total fits in u32
                // trivially: max 4 + 255 * 2 = 514 bytes.
                let count_of_codes = unwind_hdr[2] as u32;
                let unwind_total = 4u32.saturating_add(count_of_codes.saturating_mul(2));
                if bi.bytes_at(unwind_va, unwind_total).is_err() {
                    continue;
                }
                if let Some(addr) = base_addr.checked_add(begin_rva) {
                    self.add_exception_candidate(addr, disassembly)?;
                }
            }
        }
        Ok(())
    }

    /// (0.6.1) ARM64 PE `.pdata` walker. The schema per
    /// Microsoft's ARM64 ABI doc:
    ///
    /// ```text
    /// struct RUNTIME_FUNCTION_ARM64 {
    ///     u32 BeginAddress;   // RVA of the function start (4-byte aligned)
    ///     u32 UnwindData;     // either ptr-to-.xdata or packed unwind
    /// }
    /// ```
    ///
    /// `UnwindData` interpretation by low 2 bits:
    ///   - `00`: pointer to `.xdata` UNWIND_INFO record (the full
    ///     `.xdata` first u32 holds FunctionLength in bits 0:17).
    ///   - non-zero: packed unwind inline. FunctionLength sits at
    ///     bits 2:22 of the u32 (21 bits, in 4-byte units).
    ///
    /// We use `FunctionLength` to filter out garbage entries (where
    /// the implied `EndAddress = BeginAddress + 4*FuncLen` falls
    /// outside the image, or the function span exceeds a sane
    /// upper bound). Real `.pdata` is dense and contiguous; stray
    /// records past the end of the section tend to be all-zero
    /// padding or unrelated bytes that decode to absurd lengths.
    fn locate_exception_handler_candidates_aarch64(
        &mut self,
        disassembly: &DisassemblyResult,
    ) -> Result<()> {
        Self::parse_aarch64_pdata(disassembly, |addr, dis| {
            self.add_exception_candidate(addr, dis)?;
            Ok(())
        })
    }

    /// Internal driver factored out so a unit test can exercise the
    /// `.pdata` parser against a synthetic byte buffer without
    /// constructing a full `DisassemblyResult`.
    ///
    /// `report` is a callback the test can override to capture the
    /// emitted candidate addresses instead of pushing them into
    /// `self.candidates`.
    fn parse_aarch64_pdata<F>(disassembly: &DisassemblyResult, mut report: F) -> Result<()>
    where
        F: FnMut(u64, &DisassemblyResult) -> Result<()>,
    {
        const MAX_FUNC_SPAN_INSTRUCTIONS: u64 = 1 << 20; // 1M insns = 4 MiB
        let base_addr = disassembly.binary_info.base_addr;
        let bi = &disassembly.binary_info;
        let image_end = base_addr.saturating_add(bi.binary_size);

        for (section_name, section_va_start, section_va_end) in bi.get_sections()? {
            if section_name != ".pdata" {
                continue;
            }
            let mut va = section_va_start;
            while va.checked_add(8).is_some_and(|e| e <= section_va_end) {
                let Ok(packed) = bi.bytes_at(va, 8) else {
                    break;
                };
                let begin_rva =
                    u32::from_le_bytes(packed[0..4].try_into().unwrap_or([0; 4])) as u64;
                let unwind_data = u32::from_le_bytes(packed[4..8].try_into().unwrap_or([0; 4]));

                let Some(next) = va.checked_add(8) else {
                    break;
                };
                va = next;

                let Some((checked_begin, packed_len)) =
                    decode_arm64_pdata_entry(begin_rva as u32, unwind_data)
                else {
                    continue;
                };
                let Some(addr) = base_addr.checked_add(checked_begin as u64) else {
                    continue;
                };
                if !disassembly.is_addr_within_memory_image(addr)? {
                    continue;
                }

                // FunctionLength: from packed unwind, or read from
                // .xdata first u32 (bits 0:17) when pointer form.
                let func_len_insns: Option<u64> = match packed_len {
                    Some(n) => Some(n as u64),
                    None => {
                        // Pointer to .xdata at base + (unwind_data & !3).
                        let xdata_rva = (unwind_data & !0x3) as u64;
                        let xdata_va = base_addr.checked_add(xdata_rva);
                        if let Some(xdata_va) = xdata_va
                            && let Ok(hdr) = bi.bytes_at(xdata_va, 4)
                            && let Ok(packed_hdr) = <&[u8; 4]>::try_from(hdr)
                        {
                            let first = u32::from_le_bytes(*packed_hdr);
                            Some((first & 0x0003_FFFF) as u64)
                        } else {
                            None
                        }
                    }
                };

                if let Some(insns) = func_len_insns {
                    // Sanity-check the function span. If we can't get
                    // a length (.xdata unreachable / malformed),
                    // accept the BeginAddress with the original
                    // light-touch validation.
                    if insns == 0 || insns > MAX_FUNC_SPAN_INSTRUCTIONS {
                        continue;
                    }
                    let span_bytes = insns.saturating_mul(4);
                    let Some(end_va) = addr.checked_add(span_bytes) else {
                        continue;
                    };
                    if end_va > image_end {
                        continue;
                    }
                }

                report(addr, disassembly)?;
            }
        }
        Ok(())
    }

    fn locate_stub_chain_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let base_addr = disassembly.binary_info.base_addr;
        for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
            for block in STUB_CHAIN.find_iter(section_bytes) {
                for call_match in
                    STUB_CHAIN_FUNC.find_iter(&section_bytes[block.start()..block.end()])
                {
                    let stub_addr = section_va + block.start() as u64 + call_match.start() as u64;
                    if !self.passes_code_filter(Some(stub_addr))? {
                        continue;
                    }
                    if self.add_prologue_candidate(stub_addr & self.get_bitmask(), disassembly)? {
                        self.set_initial_candidate(stub_addr & self.get_bitmask())?;
                        self.candidates
                            .get_mut(&stub_addr)
                            .ok_or(Error::LogicError(file!(), line!()))?
                            .set_is_stub();
                    }
                }
            }
            for block in STUB_CHAIN_BLOCK.find_iter(section_bytes) {
                for call_match in
                    STUB_CHAIN_BLOCK_FUNC.find_iter(&section_bytes[block.start()..block.end()])
                {
                    let stub_addr = section_va + block.start() as u64 + call_match.start() as u64;
                    if !self.passes_code_filter(Some(stub_addr))? {
                        continue;
                    }
                    if self.add_prologue_candidate(stub_addr & self.get_bitmask(), disassembly)? {
                        self.set_initial_candidate(stub_addr & self.get_bitmask())?;
                        self.candidates
                            .get_mut(&stub_addr)
                            .ok_or(Error::LogicError(file!(), line!()))?
                            .set_is_stub();
                    }
                }
            }
        }
        let _ = base_addr; // keep for symmetry with prior version
        Ok(())
    }

    fn locate_prologue_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        for re_prologue in DEFAULT_PROLOGUES.iter() {
            for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
                for prologue_match in re_prologue.find_iter(section_bytes) {
                    let va = section_va + prologue_match.start() as u64;
                    if !self.passes_code_filter(Some(va))? {
                        continue;
                    }
                    self.add_prologue_candidate(va & self.get_bitmask(), disassembly)?;
                    self.set_initial_candidate(va & self.get_bitmask())?;
                }
            }
        }
        Ok(())
    }

    fn locate_reference_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let base_addr = disassembly.binary_info.base_addr;
        for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
            for call_match in REF_CANDIDATE.find_iter(section_bytes) {
                let va = section_va + call_match.start() as u64;
                if !self.passes_code_filter(Some(va))? {
                    continue;
                }
                if section_bytes.len() - call_match.start() > 5 {
                    let packed_call: &[u8; 4] = &section_bytes
                        [call_match.start() + 1..call_match.start() + 5]
                        .try_into()?;
                    let rel_call_offset = i32::from_le_bytes(*packed_call) as i64;
                    if rel_call_offset == 0 {
                        continue;
                    }
                    let call_destination =
                        ((va as i64 + rel_call_offset + 5) & self.get_bitmask() as i64) as u64;
                    if disassembly.is_addr_within_memory_image(call_destination)?
                        && self.add_reference_candidate(call_destination, va, disassembly)?
                    {
                        self.set_initial_candidate(call_destination)?;
                    }
                }
            }
        }

        if self.bitness == 32 {
            for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
                for call_match in BITNESS.find_iter(section_bytes) {
                    let va = section_va + call_match.start() as u64;
                    // resolve_pointer_reference takes a base-relative
                    // offset (VA - base_addr) — translate.
                    let Some(rel) = va.checked_sub(base_addr) else {
                        continue;
                    };
                    let function_addr = self.resolve_pointer_reference(rel, disassembly).ok();
                    if !self.passes_code_filter(function_addr)? {
                        continue;
                    }
                    let function_addr = function_addr.unwrap();
                    if disassembly.is_addr_within_memory_image(function_addr)?
                        && self.add_reference_candidate(function_addr, va, disassembly)?
                    {
                        self.set_initial_candidate(function_addr)?;
                    }
                }
            }

            for (section_va, section_bytes) in disassembly.binary_info.section_slices() {
                for call_match in CELL_MATCH.find_iter(section_bytes) {
                    let va = section_va + call_match.start() as u64;
                    let Some(rel) = va.checked_sub(base_addr) else {
                        continue;
                    };
                    let function_addr = self.resolve_pointer_reference(rel, disassembly).ok();
                    if !self.passes_code_filter(function_addr)? {
                        continue;
                    }
                    let function_addr = function_addr.unwrap();
                    if disassembly.is_addr_within_memory_image(function_addr)?
                        && self.add_reference_candidate(function_addr, va, disassembly)?
                    {
                        self.set_initial_candidate(function_addr)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn resolve_pointer_reference(
        &self,
        offset: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<u64> {
        let addr_offset = offset.checked_add(2).ok_or(Error::IntegerOverflow(
            "resolve_pointer_reference offset+2",
            offset,
            2,
        ))?;
        if self.bitness == 32 {
            let addr_block: &[u8; 4] = disassembly.get_raw_bytes(addr_offset, 4)?.try_into()?;
            let function_pointer = u32::from_le_bytes(*addr_block) as u64;
            return disassembly.dereference_dword(function_pointer);
        }
        if self.bitness == 64 {
            let addr_block: &[u8; 4] = disassembly.get_raw_bytes(addr_offset, 4)?.try_into()?;
            let mut function_pointer = u32::from_le_bytes(*addr_block) as u64;
            // RIP-relative; the instruction is 6 (`FF 15`) or 7 (`FF 25`)
            // bytes long depending on the opcode. wrapping_add matches the
            // x86 semantics — if the RIP target wraps around the address
            // space it's still a deterministic value, which the caller
            // gates with `is_addr_within_memory_image`.
            let prefix = disassembly.get_raw_bytes(offset, 2)?;
            if prefix == b"\xFF\x25" {
                function_pointer = function_pointer.wrapping_add(offset).wrapping_add(7);
            } else if prefix == b"\xFF\x15" {
                function_pointer = function_pointer.wrapping_add(offset).wrapping_add(6);
            } else {
                return Err(Error::LogicError(file!(), line!()));
            }
            let absolute = disassembly
                .binary_info
                .base_addr
                .checked_add(function_pointer)
                .ok_or(Error::IntegerOverflow(
                    "resolve_pointer_reference base+ptr",
                    disassembly.binary_info.base_addr,
                    function_pointer,
                ))?;
            return Ok(absolute);
        }
        Err(Error::LogicError(file!(), line!()))
    }

    fn get_bitmask(&self) -> u64 {
        //        if self.bitness == 64{
        0xFFFFFFFFFFFFFFFF
        //        }
        //        0xFFFFFFFF
    }

    fn passes_code_filter(&self, address: Option<u64>) -> Result<bool> {
        match address {
            Some(addr) => {
                for (start, end) in &self.code_areas {
                    if *start <= addr && *end > addr {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn ensure_candidate(&mut self, addr: u64, disassembly: &DisassemblyResult) -> Result<bool> {
        // (0.6.1, upstream issue #85) Cap total candidate count.
        // Pathological binaries (corrupted .pdata, dense prologue-
        // pattern matches across all bytes, attacker-crafted section
        // layouts) can otherwise drive `self.candidates` into
        // unbounded growth. The cap is generous (a real PE/ELF rarely
        // exceeds ~50k functions) but provides a hard upper bound so
        // analysis fails gracefully rather than OOMs. Already-queued
        // candidates keep being processed; only new insertions are
        // refused.
        //
        // Checked before `.entry()` so we don't conflict with the
        // mutable borrow that `entry()` takes.
        const MAX_CANDIDATES: usize = 100_000;
        if self.candidates.len() >= MAX_CANDIDATES && !self.candidates.contains_key(&addr) {
            return Ok(false);
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.candidates.entry(addr) {
            e.insert(FunctionCandidate::new(&disassembly.binary_info, addr)?);
            return Ok(true);
        }
        Ok(true)
    }

    pub fn add_reference_candidate(
        &mut self,
        addr: u64,
        source_ref: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        if !self.ensure_candidate(addr, disassembly)? {
            // (0.6.1) MAX_CANDIDATES cap reached — drop silently.
            return Ok(false);
        }
        self.all_call_refs.insert(source_ref, addr);
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .add_call_ref(source_ref)?;
        Ok(true)
    }

    fn add_prologue_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        Ok(true)
    }

    fn set_initial_candidate(&mut self, addr: u64) -> Result<()> {
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_initial_candidate();
        Ok(())
    }

    fn add_exception_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_exception_handler();
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_initial_candidate();
        Ok(true)
    }

    pub fn get_queue(&self) -> Result<Vec<u64>> {
        let mut res = vec![];
        for addr in self.candidates.keys() {
            res.push(*addr);
        }
        Ok(res)
    }

    //    pub fn get_candidate(&self, addr: &u64) -> Result<&FunctionCandidate>{
    //        Ok(self.candidates.get(addr).ok_or(Error::LogicError(file!(), line!()))?)
    //    }

    pub fn get_function_start_candidates(&self) -> Result<Vec<u64>> {
        Ok(self.candidate_offsets.clone())
    }

    pub fn is_alignment_sequence(
        &self,
        instruction_sequence: &[DecodedInsn],
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        let mut is_alignment_sequence = false;
        if !instruction_sequence.is_empty() {
            let mut current_offset = instruction_sequence[0].offset();
            for instruction in instruction_sequence {
                let len = instruction.length();
                // 0.4.0: bytes are looked up on demand from BinaryInfo
                // instead of being owned by the DecodedInsn.
                let Ok(bytes) = instruction.bytes_in(&disassembly.binary_info) else {
                    break;
                };
                if self
                    .gs
                    .gs
                    .get(&len)
                    .is_some_and(|set| set.contains(&bytes.to_vec()))
                {
                    current_offset += len as u64;
                    if current_offset.is_multiple_of(16) {
                        is_alignment_sequence = true;
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        Ok(is_alignment_sequence)
    }

    pub fn is_function_candidate(&self, addr: u64) -> Result<bool> {
        Ok(self.candidates.contains_key(&addr))
    }

    pub fn add_candidate(
        &mut self,
        addr: u64,
        is_gap: bool,                  /*False*/
        reference_source: Option<u64>, /*None*/
        disassembly: &DisassemblyResult,
    ) -> Result<()> {
        if !self.passes_code_filter(Some(addr))? {
            return Err(Error::LogicError(file!(), line!()));
        }
        // (0.6.1) ensure_candidate returns Ok(false) when the
        // MAX_CANDIDATES cap is hit. Silently drop instead of
        // erroring — the caller treats this as "we ran out of
        // budget for new candidates" rather than a hard failure.
        if !self.ensure_candidate(addr, disassembly)? {
            return Ok(());
        }
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_gap_candidate(is_gap)?;
        if let Some(reference_source) = reference_source {
            self.candidates
                .get_mut(&addr)
                .ok_or(Error::LogicError(file!(), line!()))?
                .add_call_ref(reference_source)?;
        }
        self.candidate_queue.push(addr);
        //        self.candidate_queue.update()?;
        Ok(())
    }

    pub fn update_analysis_aborted(&mut self, addr: &u64, reason: &str) -> Result<()> {
        //LOGGER.debug("function analysis of 0x%08x aborted: %s", addr, reason)
        if let Some(mm) = self.candidates.get_mut(addr) {
            mm.set_analysis_aborted(reason)?;
        }
        Ok(())
    }

    pub fn update_analysis_finished(&mut self, addr: &u64) -> Result<()> {
        //LOGGER.debug("function analysis of 0x%08x successfully completed.", addr)
        if let Some(mm) = self.candidates.get_mut(addr) {
            mm.set_analysis_completed()?;
        }
        Ok(())
    }

    pub fn update_candidates(&mut self, state: &FunctionAnalysisState) -> Result<()> {
        // if let Ok(_s) = std::env::var("HIGH_ACCURACY") {
        if let Ok(conflicts) = state.identify_call_conflicts(&self.all_call_refs) {
            for (candidate_addr, conflict) in conflicts {
                if let Some(c) = self.candidates.get_mut(&candidate_addr) {
                    c.remove_call_refs(conflict)?;
                }
            }

            // self.candidate_queue.update();
        }
        Ok(())
    }

    pub fn next_gap_candidate(
        &mut self,
        start_gap_pointer: Option<u64>,
        disassembly: &DisassemblyResult,
    ) -> Result<u64> {
        if let Some(s) = start_gap_pointer {
            self.gap_pointer = s;
        }
        if self.gap_pointer == 0 {
            self.init_gap_search(disassembly)?;
        }
        //LOGGER.debug("nextGapCandidate() finding new gap
        //candidate, current gap_ptr: 0x%08x", self.gap_pointer)
        loop {
            if disassembly.binary_info.base_addr + disassembly.binary_info.binary_size
                < self.gap_pointer
            {
                //LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return Err(Error::LogicError(file!(), line!()));
            }
            let gap_offset = self.gap_pointer - disassembly.binary_info.base_addr;
            if gap_offset >= disassembly.binary_info.binary_size {
                return Err(Error::LogicError(file!(), line!()));
            }
            //compatibility with python2/3...
            let byte = disassembly.get_raw_byte(gap_offset)?;
            if self.gs.gs[&1].contains(&vec![byte]) {
                //LOGGER.debug("nextGapCandidate() found 0xCC / 0x00 - gap_ptr += 1: 0x%08x", self.gap_pointer)
                self.gap_pointer += 1;
                continue;
            }
            // Try to find a single instruction at the current gap that's a
            // NOP encoding; if so, skip it and continue looking.
            //
            // x86: iced Decoder identifies any of the multi-byte NOP
            // encodings (90, 66 90, 0F 1F 00, …) — variable length.
            // AArch64: the canonical NOP is a fixed 4-byte word
            // `1f 20 03 d5` (i.e. u32 `0xd503201f` decoded LE). 0.6.0
            // gated this off; 0.6.1 adds the direct word match.
            if matches!(
                disassembly.binary_info.file_architecture,
                FileArchitecture::Aarch64
            ) {
                // gap_offset + 4 must still be in-bounds for a NOP
                // match. If not (e.g. last 3 bytes of the binary), fall
                // through to the multi-byte gap scan below — gs[&4]
                // already contains the same pattern as a defensive
                // belt-and-suspenders.
                if gap_offset + 4 <= disassembly.binary_info.binary_size {
                    let buf = disassembly.get_raw_bytes(gap_offset, 4)?;
                    if buf == [0x1F, 0x20, 0x03, 0xD5] {
                        self.gap_pointer += 4;
                        continue;
                    }
                }
            } else {
                let buf = disassembly.get_raw_bytes(gap_offset, 15)?;
                let mut decoder =
                    Decoder::with_ip(self.bitness, buf, gap_offset, DecoderOptions::NONE);
                if decoder.can_decode() {
                    let insn = decoder.decode();
                    if !insn.is_invalid() && matches!(insn.mnemonic(), Mnemonic::Nop) {
                        self.gap_pointer += decoder.position() as u64;
                        continue;
                    }
                }
            }
            {
                //# try to find effective NOPs and skip them.
                let mut found_multi_byte_nop = false;
                // Iterate widest → narrowest so we match the longest
                // multi-byte NOP first. The previous `15u32..1` range was
                // empty (typo from the iced rewrite) and silently disabled
                // multi-byte NOP gap detection.
                let max_gap = *self
                    .gs
                    .gs
                    .keys()
                    .max()
                    .ok_or(Error::LogicError(file!(), line!()))?
                    as u32;
                for gap_length in (2..=max_gap).rev() {
                    if self.gs.gs[&(gap_length as usize)].contains(
                        &disassembly
                            .get_raw_bytes(gap_offset, gap_length as u64)?
                            .to_vec(),
                    ) {
                        //LOGGER.debug("nextGapCandidate() found %d byte effective nop - gap_ptr += %d: 0x%08x", gap_length, gap_length, self.gap_pointer)
                        self.gap_pointer += gap_length as u64;
                        found_multi_byte_nop = true;
                        break;
                    }
                }
                if found_multi_byte_nop {
                    continue;
                }
                //# we know this place from data already
                if disassembly.data_map.contains(&self.gap_pointer) {
                    //LOGGER.debug("nextGapCandidate() gap_ptr is already inside data map: 0x%08x", self.gap_pointer)
                    self.gap_pointer += 1;
                    continue;
                }
                if disassembly.code_map.contains_key(&self.gap_pointer) {
                    //LOGGER.debug("nextGapCandidate() gap_ptr is already inside code map: 0x%08x", self.gap_pointer)
                    self.gap_pointer = self.get_next_gap(false, disassembly)?;
                    continue;
                }
                //# we may have a candidate here
                //LOGGER.debug("nextGapCandidate() using 0x%08x as candidate", self.gap_pointer)
                let _start_byte = disassembly.get_raw_byte(gap_offset)?;
            }
            let has_common_prologue = true; //start_byte in
            // FunctionCandidate(self.gap_pointer, start_byte,
            // self.bitness).common_gap_starts[self.bitness]
            if (self.previously_analyzed_gap == self.gap_pointer) || !has_common_prologue {
                //LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed", self.gap_pointer)
                self.gap_pointer = self.get_next_gap(true, disassembly)?;
            // } else if !has_common_prologue {
            //     //LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%08x)", self.gap_pointer, ord(start_byte))
            //     self.gap_pointer = self.get_next_gap(true, disassembly)?;
            } else {
                self.previously_analyzed_gap = self.gap_pointer;
                self.add_gap_candidate(self.gap_pointer, disassembly)?;
                return Ok(self.gap_pointer);
            }
        }
    }

    pub fn get_next_gap(&self, dont_skip: bool, disassembly: &DisassemblyResult) -> Result<u64> {
        let mut next_gap = self.get_bitmask();
        for gap in &self.function_gaps {
            if gap.0 > self.gap_pointer {
                next_gap = gap.0;
                break;
            }
        }
        //LOGGER.debug("getNextGap(%s) for 0x%08x based on gap_map: 0x%08x", dont_skip, self.gap_pointer, next_gap)
        //# we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if dont_skip && disassembly.code_map.contains_key(&self.gap_pointer) {
            let function = disassembly.ins2fn[&self.gap_pointer];
            if next_gap > disassembly.function_borders[&function].1 {
                next_gap = disassembly.function_borders[&function].1;
            }
            //LOGGER.debug("getNextGap(%s) without skip => after checking versus code map: 0x%08x", dont_skip, next_gap)
        }
        //LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", dont_skip, next_gap)
        Ok(next_gap)
    }

    pub fn add_tailcall_candidate(
        &mut self,
        addr: &u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(*addr))? {
            return Ok(false);
        }
        self.ensure_candidate(*addr, disassembly)?;
        self.candidates
            .get_mut(addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_tailcall_candidate(true)?;
        Ok(true)
    }

    pub fn get_aborted_candidates(&self) -> Result<Vec<u64>> {
        let mut aborted = vec![];
        for (addr, candidate) in &self.candidates {
            if candidate.analysis_aborted {
                aborted.push(*addr);
            }
        }
        Ok(aborted)
    }

    pub fn init_gap_search(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        if self.gap_pointer == 0 {
            //LOGGER.debug("initGapSearch()")
            self.gap_pointer = self.get_bitmask();
            self.update_function_gaps(disassembly)?;
            if !self.function_gaps.is_empty() {
                self.gap_pointer = self.function_gaps[0].0;
            }
        }
        // sort gaps by start address
        self.function_gaps.sort_by_key(|gap| gap.0);
        //LOGGER.debug("initGapSearch() gaps are:")
        for _gap in &self.function_gaps {
            //LOGGER.debug("initGapSearch() 0x%08x - 0x%08x == %d",
            // gap[0], gap[1], gap[2])
        }
        Ok(())
    }

    pub fn add_gap_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_gap_candidate(true)?;
        Ok(true)
    }

    pub fn update_function_gaps(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let mut gaps = vec![];
        let mut prev_ins = 0;
        let mut min_code = self.get_bitmask();
        let mut max_code = 0;
        for f in disassembly.code_map.keys() {
            if min_code > *f {
                min_code = *f;
            }
            if max_code < *f {
                max_code = *f;
            }
        }
        for code_area in &self.code_areas {
            if code_area.0 < min_code && min_code < code_area.1 && min_code != code_area.0 {
                gaps.push((code_area.0, min_code, min_code - code_area.0));
            }
            if code_area.0 < max_code && max_code < code_area.1 && max_code != code_area.1 {
                gaps.push((max_code, code_area.1, code_area.1 - max_code));
            }
        }
        for (ins, _) in disassembly.code_map.iter().sorted() {
            if prev_ins != 0 && ins - prev_ins > 1 {
                gaps.push((prev_ins + 1, *ins, ins - prev_ins))
            }
            prev_ins = *ins
        }
        self.function_gaps = gaps;
        Ok(())
    }
}

/// (0.6.1) Pure ARM64 `.pdata` entry decoder. Extracted from the
/// I/O-bound walker so we can unit-test the field-layout + filter
/// logic without constructing a `DisassemblyResult`.
///
/// Returns `None` for entries that should be skipped (zero
/// `BeginAddress` / unaligned). Otherwise returns
/// `(BeginAddress, packed_func_len)` where `packed_func_len` is
/// `Some(n)` for inline-packed unwind (length in 4-byte units) and
/// `None` for pointer-to-`.xdata` form — the caller is then
/// responsible for following the pointer to read `FunctionLength`.
#[must_use]
pub(crate) fn decode_arm64_pdata_entry(
    begin_rva: u32,
    unwind_data: u32,
) -> Option<(u32, Option<u32>)> {
    if begin_rva == 0 {
        return None; // terminator / hole
    }
    if (begin_rva & 0x3) != 0 {
        return None; // misaligned — ARM64 functions are 4-byte aligned
    }
    let packed_len = if (unwind_data & 0x3) == 0 {
        None // pointer to .xdata; caller follows
    } else {
        Some((unwind_data >> 2) & 0x001F_FFFF)
    };
    Some((begin_rva, packed_len))
}

#[cfg(test)]
mod arm64_pdata_tests {
    use super::decode_arm64_pdata_entry;

    #[test]
    fn skips_zero_begin_rva() {
        // All-zero terminator entries are common at the end of .pdata.
        assert_eq!(decode_arm64_pdata_entry(0, 0), None);
    }

    #[test]
    fn skips_unaligned_begin_rva() {
        // ARM64 instructions are 4-byte aligned. A misaligned
        // BeginAddress is structurally impossible for a real function.
        assert_eq!(decode_arm64_pdata_entry(0x1001, 0x15), None);
        assert_eq!(decode_arm64_pdata_entry(0x1002, 0x15), None);
        assert_eq!(decode_arm64_pdata_entry(0x1003, 0x15), None);
    }

    #[test]
    fn decodes_packed_unwind_funclen() {
        // FuncLen=10 insns, Flag=01 (full packed).
        // Encoding: bits 0:1=01, bits 2:22=10.
        let unwind = (10u32 << 2) | 0b01;
        let result = decode_arm64_pdata_entry(0x1000, unwind);
        assert_eq!(result, Some((0x1000, Some(10))));
    }

    #[test]
    fn decodes_packed_unwind_max_funclen() {
        // FuncLen at its 21-bit maximum: 0x1FFFFF insns.
        let max = 0x001F_FFFF;
        let unwind = (max << 2) | 0b01;
        let result = decode_arm64_pdata_entry(0x1000, unwind);
        assert_eq!(result, Some((0x1000, Some(max))));
    }

    #[test]
    fn detects_xdata_pointer_form() {
        // bits 1:0 == 00 → pointer to .xdata. Returns None for the
        // packed length so the caller knows to follow.
        let unwind = 0x0000_1000; // arbitrary aligned pointer
        let result = decode_arm64_pdata_entry(0x1000, unwind);
        assert_eq!(result, Some((0x1000, None)));
    }

    #[test]
    fn full_pdata_entry_round_trip() {
        // Synthetic 8-byte RUNTIME_FUNCTION_ARM64 entry:
        //   BeginAddress = 0x1000
        //   UnwindData   = packed, FuncLen = 5
        let entry = [
            0x00, 0x10, 0x00, 0x00, // BeginAddress = 0x1000
            0x15, 0x00, 0x00, 0x00, // UnwindData = (5<<2)|1 = 0x15
        ];
        let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let unwind = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        assert_eq!(
            decode_arm64_pdata_entry(begin, unwind),
            Some((0x1000, Some(5)))
        );
    }
}
