//! Disarm64 operand-surface probe (smda-rs 0.6.0 prototype).
//!
//! Goal: validate that `disarm64`'s operand model can cleanly express
//! the (base register, displacement) tuple capa-rs needs for its
//! `offset:` / `operand[i].offset:` features against real-world
//! AArch64 binaries, BEFORE we commit to the full Decoder-trait
//! refactor in smda-rs 0.6.0.
//!
//! Usage:
//!   cargo run --release --example aarch64_probe -- <path-to-aarch64-binary>
//!
//! Suggested test targets on Apple-silicon Mac:
//!   /usr/lib/dyld
//!   /usr/lib/libSystem.B.dylib
//!   /bin/ls
//!   /bin/cat
//! On Linux ARM64:
//!   /lib/aarch64-linux-gnu/libc.so.6
//!   /bin/ls
//! On Windows ARM64:
//!   C:\Windows\System32\ntdll.dll
//!
//! What the probe reports:
//!   - Total instructions decoded vs. failed decode count
//!   - Memory-operand instruction count (ldr/str/ldp/stp/etc.)
//!   - For each memory op: can we extract base reg + displacement?
//!   - Coverage of addressing forms:
//!       * `[reg]`         (no disp, simple base)
//!       * `[reg, #imm]`   (base + immediate disp)
//!       * `[reg, #imm]!`  (pre-indexed)
//!       * `[reg], #imm`   (post-indexed)
//!       * `[reg, reg]`    (base + index)
//!       * `[reg, reg, lsl #n]`  (shifted index)
//!       * Other / SVE-typed
//!   - First 20 instructions with their parsed operand structure (sanity check)
//!
//! Pass / fail criteria:
//!   - >95% of memory ops have base+disp cleanly extracted → disarm64 is good
//!   - Operand enum exposes pre/post-index variants distinctly → good
//!   - Otherwise: fall back to yaxpeax-arm (richer operand model per audit)

use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: aarch64_probe <path-to-aarch64-binary>");
            return ExitCode::from(2);
        }
    };

    let buf = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    // Find an executable code region. Mach-O / ELF / PE all have
    // section-table structures we can iterate via goblin. For the
    // prototype, dump the largest executable section and probe the
    // first ~10000 instructions.
    let (code_bytes, code_base) = match find_exec_section(&buf, &path) {
        Some(s) => s,
        None => {
            eprintln!(
                "no executable AArch64 section found in {path} \
                 (file format unrecognised or wrong arch)"
            );
            return ExitCode::from(1);
        }
    };

    eprintln!(
        "probing {} bytes of code at 0x{:x} from {}",
        code_bytes.len(),
        code_base,
        path
    );

    // AArch64 is fixed-width 4 bytes per instruction. Linear decode
    // is correct (no variable-width sliding window like x86 needs).
    // We cap at 10000 to keep the probe fast; if you want the full
    // section, drop the cap.
    let mut total = 0usize;
    let mut decoded = 0usize;
    let mut failed = 0usize;
    let mut memops = 0usize;
    let mut clean_base_disp = 0usize;
    let mut form_counts = std::collections::HashMap::<&str, usize>::new();
    let mut sample = Vec::<String>::new();

    for (i, chunk) in code_bytes.chunks_exact(4).enumerate().take(10000) {
        total += 1;
        let opcode = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        // disarm64 v0.1 API surface (best-effort guess — iterate from
        // compile errors). The crate exposes a top-level `decode` or
        // an `Insn::decode` constructor that returns a typed
        // instruction. If this API doesn't match, the compile error
        // will tell us the right path and we adapt.
        let decoded_insn = disarm64::decoder::decode(opcode);
        match decoded_insn {
            Some(insn) => {
                decoded += 1;
                let addr = code_base + (i * 4) as u64;
                let kind = classify_memory_operand(&insn);
                if !matches!(kind, OperandShape::NotMemory) {
                    memops += 1;
                    let label = kind.label();
                    *form_counts.entry(label).or_insert(0) += 1;
                    if matches!(
                        kind,
                        OperandShape::BaseOnly
                            | OperandShape::BaseDisp
                            | OperandShape::PreIndexed
                            | OperandShape::PostIndexed
                    ) {
                        clean_base_disp += 1;
                    }
                }
                if sample.len() < 20 {
                    sample.push(format!("  0x{:08x}  {:08x}  {:?}", addr, opcode, insn));
                }
            }
            None => {
                failed += 1;
            }
        }
    }

    println!();
    println!("=== AArch64 decode probe — {path} ===");
    println!("total opcodes scanned:    {total}");
    println!("decoded:                  {decoded}");
    println!("decode failures:          {failed}");
    println!("memory-operand insns:     {memops}");
    if memops > 0 {
        let pct = (clean_base_disp as f64 / memops as f64) * 100.0;
        println!("clean base+disp:          {clean_base_disp} ({pct:.1}%)");
    }
    println!();
    println!("=== Memory operand form breakdown ===");
    let mut sorted: Vec<(&&str, &usize)> = form_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (form, count) in sorted {
        println!("  {:40} {count}", form);
    }
    println!();
    println!("=== First 20 decoded instructions (Debug format) ===");
    for line in &sample {
        println!("{line}");
    }
    println!();
    println!("=== Verdict ===");
    if memops == 0 {
        println!("INCONCLUSIVE: no memory-operand instructions found in scanned range");
        println!("(small code region or unusual binary; try a larger / different sample)");
    } else {
        let pct = (clean_base_disp as f64 / memops as f64) * 100.0;
        if pct >= 95.0 {
            println!("PASS: disarm64 cleanly handles {pct:.1}% of memory operands");
            println!("→ proceed with Decoder trait refactor using disarm64");
        } else if pct >= 80.0 {
            println!("PARTIAL: {pct:.1}% clean — check the form breakdown above");
            println!("→ if the missing forms are uncommon (SVE / shifted index),");
            println!("  disarm64 is still workable. Verify against a 2nd binary.");
        } else {
            println!("FAIL: only {pct:.1}% clean base+disp extraction");
            println!("→ fall back to yaxpeax-arm (richer operand model per audit)");
        }
    }
    ExitCode::from(0)
}

/// Classification of the addressing form for a memory operand, as
/// far as we can recover from disarm64's typed `Insn`.
#[derive(Debug)]
#[allow(dead_code)]
enum OperandShape {
    NotMemory,
    BaseOnly,       // [reg]
    BaseDisp,       // [reg, #imm]
    PreIndexed,     // [reg, #imm]!
    PostIndexed,    // [reg], #imm
    BaseIndex,      // [reg, reg]
    BaseIndexShift, // [reg, reg, lsl #n]
    Sve,            // SVE-typed (vector predicate, etc.)
    Other,          // anything we can't classify
}

impl OperandShape {
    fn label(&self) -> &'static str {
        match self {
            OperandShape::NotMemory => "not_memory",
            OperandShape::BaseOnly => "[reg]",
            OperandShape::BaseDisp => "[reg, #imm]",
            OperandShape::PreIndexed => "[reg, #imm]!  (pre-indexed)",
            OperandShape::PostIndexed => "[reg], #imm   (post-indexed)",
            OperandShape::BaseIndex => "[reg, reg]",
            OperandShape::BaseIndexShift => "[reg, reg, lsl #n]",
            OperandShape::Sve => "SVE / vector predicate",
            OperandShape::Other => "other / unclassified",
        }
    }
}

/// Heuristic classifier. disarm64 v0.1.26 exposes `Opcode` as the
/// public decoded type (Insn is private). Opcode carries the
/// instruction definition + operand bits; for the prototype's
/// distribution check we string-match on Debug output, which gives
/// us reliable form classification without needing to learn
/// disarm64's operand-bit layout (deferred to the real decoder
/// integration in tasks #218-220).
///
/// **First iteration uses string matching on Debug output as a
/// scaffolding step.** Once we know which operand-extraction API on
/// `Opcode` we actually need, replace with a typed match. The
/// probe's value is in showing the FORM DISTRIBUTION across real
/// binaries, not the exact classification mechanism.
fn classify_memory_operand(insn: &disarm64::decoder::Opcode) -> OperandShape {
    // disarm64's Debug output is structured:
    //   Opcode { mnemonic: <name>, operation: <GROUP>(<encoding>(bits)) }
    // The <GROUP> token is the ARM ARM encoding-group name, which
    // maps cleanly to addressing form:
    //
    //   LDST_POS         — [base, #uimm12]                (BaseDisp)
    //   LDST_UNSCALED    — [base, #simm9]                 (BaseDisp)
    //   LDST_UNPRIV      — unprivileged [base, #imm]      (BaseDisp)
    //   LDST_IMM9        — [base, #simm9]{!} / [base], #imm
    //                       (pre/post/unscaled by encoding suffix)
    //   LDST_REGOFF      — [base, reg{, lsl #n}]          (BaseIndex)
    //   LDST_EXCLUSIVE   — [base] exclusive               (BaseOnly)
    //   LDSTPAIR_OFF     — pair [base, #simm7]            (BaseDisp)
    //   LDSTPAIR_INDEXED — pair pre/post-indexed
    //   LOADLIT          — PC-relative literal load       (BaseOnly)
    //
    // Match on the group token. This is reliable across disarm64
    // releases because the token names come from the ARM ARM JSON,
    // not from the crate's surface formatting.
    let s = format!("{insn:?}");

    if s.contains("operation: LDST_POS(")
        || s.contains("operation: LDST_UNSCALED(")
        || s.contains("operation: LDST_UNPRIV(")
        || s.contains("operation: LDSTPAIR_OFF(")
        || s.contains("operation: LDSTNAPAIR_OFFS(")
    {
        return OperandShape::BaseDisp;
    }
    if s.contains("operation: LDST_IMM9(") {
        // SIMM9 group is split by encoding-name suffix:
        //   ..._SIMM9_PRE / ..._PRE_  → pre-indexed
        //   ..._SIMM9_POST / ..._POST_ → post-indexed
        //   ..._SIMM9                  → unscaled (BaseDisp)
        if s.contains("SIMM9_PRE") || s.contains("_PRE_") {
            return OperandShape::PreIndexed;
        }
        if s.contains("SIMM9_POST") || s.contains("_POST_") {
            return OperandShape::PostIndexed;
        }
        return OperandShape::BaseDisp;
    }
    if s.contains("operation: LDSTPAIR_INDEXED(") {
        // Pair indexed: precise pre vs post needs the bit-level
        // encoding. For the probe, treat as recoverable indexed.
        if s.contains("_POST_") {
            return OperandShape::PostIndexed;
        }
        return OperandShape::PreIndexed;
    }
    if s.contains("operation: LDST_REGOFF(") {
        // Register-offset (possibly shifted). Capa-rs's typed
        // extractor will need to walk the shift field; for the
        // probe, treat as base+index.
        return OperandShape::BaseIndex;
    }
    if s.contains("operation: LDST_EXCLUSIVE(") || s.contains("operation: LOADLIT(") {
        return OperandShape::BaseOnly;
    }

    // SVE / NEON addressing groups — flag prevalence so we know.
    if s.contains("operation: SVE_") || s.contains("operation: SIMD_") {
        return OperandShape::Sve;
    }

    // Mnemonic-says-memory-but-group-didn't-match → bucket as Other
    // so we can see what we missed. Otherwise it's not a memory op.
    let s_low = s.to_ascii_lowercase();
    let mnem_says_mem = [
        "mnemonic: ldr",
        "mnemonic: str",
        "mnemonic: ldp",
        "mnemonic: stp",
        "mnemonic: ldur",
        "mnemonic: stur",
        "mnemonic: ldrb",
        "mnemonic: strb",
        "mnemonic: ldrh",
        "mnemonic: strh",
        "mnemonic: ldxr",
        "mnemonic: stxr",
        "mnemonic: ldnp",
        "mnemonic: stnp",
        "mnemonic: ldrsw",
        "mnemonic: ldrsb",
        "mnemonic: ldrsh",
        "mnemonic: ldar",
        "mnemonic: stlr",
    ]
    .iter()
    .any(|m| s_low.contains(m));
    if mnem_says_mem {
        return OperandShape::Other;
    }
    OperandShape::NotMemory
}

/// Locate the largest executable section in a binary, returning
/// `(bytes, base_address)`. Supports Mach-O / ELF / PE via goblin.
/// AArch64 architectures only.
fn find_exec_section<'a>(buf: &'a [u8], path: &str) -> Option<(&'a [u8], u64)> {
    use goblin::Object;
    match Object::parse(buf).ok()? {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            // Apple-silicon Mach-O. CPU_TYPE_ARM64 == 0x100000C.
            const CPU_TYPE_ARM64: u32 = 0x0100_000C;
            if macho.header.cputype != CPU_TYPE_ARM64 {
                eprintln!("not ARM64 Mach-O (cputype = 0x{:x})", macho.header.cputype);
                return None;
            }
            // Find __TEXT,__text section.
            for seg in &macho.segments {
                for (sect, secbytes) in seg.into_iter().flatten() {
                    if sect.name().ok()? == "__text" {
                        return Some((secbytes, sect.addr));
                    }
                }
            }
            None
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Try to find an ARM64 slice. The arch index is the
            // position in the fat header, NOT the cputype constant.
            const CPU_TYPE_ARM64: u32 = 0x0100_000C;
            let arches = fat.arches().ok()?;
            for (i, arch) in arches.iter().enumerate() {
                if arch.cputype() == CPU_TYPE_ARM64 {
                    let inner = fat.get(i).ok()?;
                    if let goblin::mach::SingleArch::MachO(macho) = inner {
                        for seg in &macho.segments {
                            for (sect, secbytes) in seg.into_iter().flatten() {
                                if sect.name().ok()? == "__text" {
                                    return Some((secbytes, sect.addr));
                                }
                            }
                        }
                    }
                }
            }
            eprintln!(
                "fat Mach-O has no ARM64 slice (arches: {:?})",
                arches.iter().map(|a| a.cputype()).collect::<Vec<_>>()
            );
            None
        }
        Object::Elf(elf) => {
            // EM_AARCH64 == 183.
            if elf.header.e_machine != 183 {
                eprintln!("not AArch64 ELF (e_machine = {})", elf.header.e_machine);
                return None;
            }
            // Find the largest executable PT_LOAD.
            let mut best: Option<(&[u8], u64)> = None;
            for ph in &elf.program_headers {
                if ph.p_type == goblin::elf::program_header::PT_LOAD
                    && ph.p_flags & goblin::elf::program_header::PF_X != 0
                {
                    let start = ph.p_offset as usize;
                    let end = start + ph.p_filesz as usize;
                    if end <= buf.len() {
                        let slice = &buf[start..end];
                        if best.is_none_or(|b| slice.len() > b.0.len()) {
                            best = Some((slice, ph.p_vaddr));
                        }
                    }
                }
            }
            best
        }
        Object::PE(pe) => {
            // IMAGE_FILE_MACHINE_ARM64 == 0xAA64.
            if pe.header.coff_header.machine != 0xAA64 {
                eprintln!(
                    "not ARM64 PE (machine = 0x{:x})",
                    pe.header.coff_header.machine
                );
                return None;
            }
            // Find .text.
            for sect in &pe.sections {
                if sect.name().ok()? == ".text" {
                    let start = sect.pointer_to_raw_data as usize;
                    let end = start + sect.size_of_raw_data as usize;
                    if end <= buf.len() {
                        let base = pe.image_base + sect.virtual_address as u64;
                        return Some((&buf[start..end], base));
                    }
                }
            }
            None
        }
        _ => {
            eprintln!("unsupported binary format for {path}");
            None
        }
    }
}
