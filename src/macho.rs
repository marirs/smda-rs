//! Mach-O loader for Intel binaries (0.5.0).
//!
//! Parses x86_64 (and i386, where it still appears) Mach-O object files
//! and slices their segments into `SectionMap`s. Mirrors the
//! `pe::map_binary` / `elf::map_binary` surface so `parse_inner` can
//! treat all three formats uniformly.
//!
//! Fat binaries are sliced down to the Intel architecture (preferring
//! x86_64 over i386); ARM slices are ignored. If no Intel slice exists
//! the loader returns `Error::UnsupportedFormatError`.
//!
//! **Limitations in this first cut (0.5.0):**
//! - Imports come from the lazy/non-lazy bind opcode stream when goblin
//!   exposes them; otherwise empty. Resolution to DLL + symbol name is
//!   best-effort.
//! - Exports come from the export trie. Each entry's `(name, vmaddr,
//!   forwarder)` is captured.
//! - Code areas are derived from segments whose `initprot` has
//!   `VM_PROT_EXECUTE`. No `__objc_methlist` or Swift runtime parsing.
//! - DYLD chained-fixup format (newer macOS 12+ binaries) is not
//!   followed — those binaries still load and disassemble, but their
//!   import names may not surface.

use crate::{Error, Result, SectionMap};
use goblin::mach::{Mach, MachO};

const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 7 | 0x0100_0000; // CPU_ARCH_ABI64
/// 0.6.0 — CPU_TYPE_ARM64 = 12 | CPU_ARCH_ABI64.
pub(crate) const CPU_TYPE_ARM64: u32 = 12 | 0x0100_0000;

/// (0.6.1, upstream issue #118) Map a Mach-O `cputype` to bitness.
/// Returns `None` for unsupported CPU types instead of silently
/// falling through.
#[must_use]
pub fn bitness_from_cputype(cputype: u32) -> Option<u32> {
    match cputype {
        CPU_TYPE_X86 => Some(32),
        CPU_TYPE_X86_64 | CPU_TYPE_ARM64 => Some(64),
        _ => None,
    }
}

/// (0.6.1, upstream issue #118) Map a Mach-O `cputype` to
/// [`crate::FileArchitecture`]. Returns `None` for unsupported
/// CPU types. Centralised here so the loader, the report writer,
/// and any downstream consumer all agree on the same mapping.
#[must_use]
pub fn architecture_from_cputype(cputype: u32) -> Option<crate::FileArchitecture> {
    match cputype {
        CPU_TYPE_X86 => Some(crate::FileArchitecture::I386),
        CPU_TYPE_X86_64 => Some(crate::FileArchitecture::AMD64),
        CPU_TYPE_ARM64 => Some(crate::FileArchitecture::Aarch64),
        _ => None,
    }
}

/// Pull the Intel Mach-O out of `binary`. Retained for source compat;
/// new callers should prefer [`extract_macho`] (Intel + ARM64).
pub fn extract_intel(binary: &[u8]) -> Result<MachO<'_>> {
    let mach = goblin::mach::Mach::parse(binary)?;
    match mach {
        Mach::Binary(m) => {
            let ct = m.header.cputype();
            if ct == CPU_TYPE_X86_64 || ct == CPU_TYPE_X86 {
                Ok(m)
            } else {
                Err(Error::UnsupportedFormatError)
            }
        }
        Mach::Fat(fat) => {
            for want in [CPU_TYPE_X86_64, CPU_TYPE_X86] {
                for (i, arch) in fat.iter_arches().enumerate() {
                    let arch = arch?;
                    if arch.cputype == want
                        && let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i)
                    {
                        return Ok(m);
                    }
                }
            }
            Err(Error::UnsupportedFormatError)
        }
    }
}

/// 0.6.0 — pull a supported Mach-O slice out of `binary`. Accepts
/// `CPU_TYPE_ARM64`, `CPU_TYPE_X86_64`, and `CPU_TYPE_X86`.
///
/// Thin (single-arch) binaries return that slice if its `cputype` is
/// supported. Fat (universal) binaries pick the slice matching the
/// `prefer` order, falling back to other supported slices.
///
/// Returns `Error::UnsupportedFormatError` if no supported slice
/// exists.
///
/// Compatibility shim — new callers should prefer
/// [`extract_macho_with_offset`] which also returns the slice's
/// offset in the fat file (needed to translate slice-relative
/// `fileoff` fields into whole-buffer indices).
pub fn extract_macho(binary: &[u8], prefer: crate::MachoArchPreference) -> Result<MachO<'_>> {
    extract_macho_with_offset(binary, prefer).map(|(m, _)| m)
}

/// 0.6.0 fix — like [`extract_macho`] but also returns the byte
/// offset of the chosen slice within the input `binary`. For thin
/// Mach-O this is always 0; for fat (universal) Mach-O the load
/// commands record `fileoff` values RELATIVE TO THE SLICE START,
/// which `map_binary` has to combine with this offset to produce
/// correct indices into the input buffer. Without this adjustment,
/// reads at `bytes_at(va)` on a fat binary land in the wrong slice
/// (or the fat header padding) and the analyser silently decodes
/// garbage — see the 0.6.0 debugging note where /bin/ls's ARM64
/// entry was reading as `udf #0` (4 bytes of zeros) because we were
/// indexing the x86_64 slice's bytes.
pub fn extract_macho_with_offset(
    binary: &[u8],
    prefer: crate::MachoArchPreference,
) -> Result<(MachO<'_>, u64)> {
    let mach = goblin::mach::Mach::parse(binary)?;
    match mach {
        Mach::Binary(m) => {
            let ct = m.header.cputype();
            if ct == CPU_TYPE_ARM64 || ct == CPU_TYPE_X86_64 || ct == CPU_TYPE_X86 {
                Ok((m, 0))
            } else {
                Err(Error::UnsupportedFormatError)
            }
        }
        Mach::Fat(fat) => {
            for want in fat_arch_order(prefer) {
                for (i, arch) in fat.iter_arches().enumerate() {
                    let arch = arch?;
                    if arch.cputype == want
                        && let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i)
                    {
                        // The slice starts at `arch.offset` bytes into
                        // the fat file. Every fileoff in `m.segments`
                        // is relative to that.
                        return Ok((m, arch.offset as u64));
                    }
                }
            }
            Err(Error::UnsupportedFormatError)
        }
    }
}

/// 0.6.0 — return the preferred-to-least-preferred cputype iteration
/// order for fat-Mach-O slice selection. Hosts other than ARM64 /
/// x86_64 / x86 default to ARM64-first for `HostNative` because that
/// matches the modern-Mac-malware use case.
fn fat_arch_order(prefer: crate::MachoArchPreference) -> [u32; 3] {
    use crate::MachoArchPreference;
    match prefer {
        MachoArchPreference::HostNative => match std::env::consts::ARCH {
            "aarch64" | "arm64" => [CPU_TYPE_ARM64, CPU_TYPE_X86_64, CPU_TYPE_X86],
            "x86_64" => [CPU_TYPE_X86_64, CPU_TYPE_ARM64, CPU_TYPE_X86],
            "x86" | "i686" => [CPU_TYPE_X86, CPU_TYPE_X86_64, CPU_TYPE_ARM64],
            _ => [CPU_TYPE_ARM64, CPU_TYPE_X86_64, CPU_TYPE_X86],
        },
        MachoArchPreference::Aarch64First => [CPU_TYPE_ARM64, CPU_TYPE_X86_64, CPU_TYPE_X86],
        MachoArchPreference::X86_64First => [CPU_TYPE_X86_64, CPU_TYPE_ARM64, CPU_TYPE_X86],
        MachoArchPreference::X86First => [CPU_TYPE_X86, CPU_TYPE_X86_64, CPU_TYPE_ARM64],
    }
}

/// 0.6.0 — true if the resolved Mach-O slice is ARM64.
#[must_use]
pub fn is_arm64(mach: &MachO) -> bool {
    mach.header.cputype() == CPU_TYPE_ARM64
}

/// Image base = vmaddr of the first non-`__PAGEZERO` segment.
/// `__PAGEZERO` (when present) sits at vmaddr 0 with a huge vmsize and
/// is invalid to execute; the real load base is the `__TEXT` segment.
#[must_use]
pub fn get_base_address(mach: &MachO) -> u64 {
    for seg in &mach.segments {
        let name = std::str::from_utf8(&seg.segname).unwrap_or("");
        let name = name.trim_end_matches('\0');
        if name == "__PAGEZERO" {
            continue;
        }
        return seg.vmaddr;
    }
    0
}

/// 64 if the Mach-O is 64-bit, 32 otherwise.
#[must_use]
pub fn get_bitness(mach: &MachO) -> u32 {
    if mach.is_64 { 64 } else { 32 }
}

/// Mach-O section-flag attributes (`section_64.flags` high 24 bits).
/// Bit 31 = `S_ATTR_PURE_INSTRUCTIONS`, bit 10 = `S_ATTR_SOME_INSTRUCTIONS`.
const VM_PROT_EXECUTE: u32 = 0x04;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// Code-area extents — (va_start, va_end) of every section that
/// actually holds instructions. 0.5.2 tightened this from "the entire
/// executable segment" to "sections with `S_ATTR_PURE_INSTRUCTIONS` /
/// `S_ATTR_SOME_INSTRUCTIONS` flags, or whose sectname is a known
/// code-bearing one (`__text`, `__stubs`, `__stub_helper`)". The pre-
/// 0.5.2 behaviour included the `__TEXT` segment's load-commands
/// header bytes, which produced a junk 1-insn "function" at base_addr.
///
/// Falls back to the whole segment (old behaviour) only when the
/// segment exposes no sections that goblin could parse — necessary for
/// raw / stripped binaries where the section table is gone.
#[must_use]
pub fn get_code_areas(mach: &MachO) -> Vec<(u64, u64)> {
    let mut areas = Vec::new();
    for seg in &mach.segments {
        let seg_name = std::str::from_utf8(&seg.segname).unwrap_or("");
        let seg_name = seg_name.trim_end_matches('\0');
        let is_text_seg = seg_name.starts_with("__TEXT");
        let is_exec_seg = seg.initprot & VM_PROT_EXECUTE != 0;
        if !(is_text_seg || is_exec_seg) {
            continue;
        }
        let mut added_any = false;
        if let Ok(sections) = seg.sections() {
            for (sect, _data) in sections {
                let sect_name = std::str::from_utf8(&sect.sectname).unwrap_or("");
                let sect_name = sect_name.trim_end_matches('\0');
                let has_instr_flag =
                    sect.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
                let is_code_section = matches!(
                    sect_name,
                    "__text" | "__stubs" | "__stub_helper" | "__symbol_stub"
                );
                if !(has_instr_flag || is_code_section) {
                    continue;
                }
                if let Some(end) = sect.addr.checked_add(sect.size) {
                    areas.push((sect.addr, end));
                    added_any = true;
                }
            }
        }
        // Fallback when the segment has no parsed sections (corrupted /
        // stripped binary): include the whole segment so we don't lose
        // discovery entirely.
        if !added_any && let Some(end) = seg.vmaddr.checked_add(seg.vmsize) {
            areas.push((seg.vmaddr, end));
        }
    }
    areas
}

/// Mirror of `pe::map_binary` / `elf::map_binary`. `base_addr` is
/// accepted for API symmetry; Mach-O segments already carry absolute
/// VAs so it isn't added in. `prefer` selects which slice to walk on
/// fat (universal) binaries; ignored for thin Mach-O.
pub fn map_binary(
    binary: &[u8],
    base_addr: u64,
    prefer: crate::MachoArchPreference,
) -> Result<Vec<SectionMap>> {
    let _ = base_addr;
    // 0.6.0 fix — use `extract_macho_with_offset` so we get the
    // slice's offset in the fat file. Segment fileoffs are slice-
    // relative; we add `slice_offset` to translate to whole-buffer
    // indices. For thin Mach-O `slice_offset` is 0 (unchanged).
    let (mach, slice_offset) = extract_macho_with_offset(binary, prefer)?;
    let slice_offset = usize::try_from(slice_offset).map_err(|_| Error::UnsupportedFormatError)?;
    let mut section_maps = Vec::with_capacity(mach.segments.len());
    for seg in &mach.segments {
        let name = std::str::from_utf8(&seg.segname).unwrap_or("");
        if name.trim_end_matches('\0') == "__PAGEZERO" {
            continue;
        }
        if seg.vmsize == 0 {
            continue;
        }
        let Some(va_end) = seg.vmaddr.checked_add(seg.vmsize) else {
            continue;
        };
        // 0.5.1 security: u64 -> usize casts on attacker-controlled
        // fileoff / filesize. 32-bit hosts would silently truncate;
        // try_from rejects oversized values instead.
        let Ok(seg_fileoff) = usize::try_from(seg.fileoff) else {
            continue;
        };
        // 0.6.0 fix — combine slice-relative seg.fileoff with the
        // slice's offset in the fat file. For thin Mach-O this is
        // a no-op (slice_offset = 0).
        let Some(file_offset) = slice_offset.checked_add(seg_fileoff) else {
            continue;
        };
        let Ok(declared_size) = usize::try_from(seg.filesize) else {
            continue;
        };
        // Clamp declared_size to what the file actually contains. A
        // malformed Mach-O that declares filesize past the buffer end
        // would otherwise let downstream bytes_at over-read.
        let file_size = match file_offset.checked_add(declared_size) {
            Some(end) if end <= binary.len() => declared_size,
            _ => binary.len().saturating_sub(file_offset),
        };
        section_maps.push(SectionMap {
            va_start: seg.vmaddr,
            va_end,
            file_offset,
            file_size,
        });
    }
    Ok(section_maps)
}

/// `(section_name, va_start, va_size)` for every section across every
/// non-`__PAGEZERO` segment. Used to fill `BinaryInfo.sections`.
#[must_use]
pub fn get_sections(mach: &MachO) -> Vec<(String, u64, usize)> {
    let mut out = Vec::new();
    for seg in &mach.segments {
        let seg_name = std::str::from_utf8(&seg.segname).unwrap_or("");
        if seg_name.trim_end_matches('\0') == "__PAGEZERO" {
            continue;
        }
        if let Ok(sections) = seg.sections() {
            for (sect, _data) in sections {
                let sect_name = std::str::from_utf8(&sect.sectname).unwrap_or("");
                let combined = format!(
                    "{},{}",
                    seg_name.trim_end_matches('\0'),
                    sect_name.trim_end_matches('\0')
                );
                // 0.5.1: u64 -> usize via try_from; skip oversized
                // sections rather than truncating on 32-bit hosts.
                if let Ok(size) = usize::try_from(sect.size) {
                    out.push((combined, sect.addr, size));
                }
            }
        }
    }
    out
}

/// 0.6.4 — Mach-O API resolver, the missing peer of
/// `elf::extract_elf_dynamic_apis`. Builds a `HashMap<VA, (dylib,
/// name)>` that the analyser plumbs into
/// `DisassemblyResult::addr_to_api`, so capa-rs (and any other
/// consumer that asks "what API lives at this address?") can
/// resolve Mach-O imports the same way it does ELF dynamic
/// imports.
///
/// What address are we registering?
/// goblin's `Import.offset` is the **file offset** of the bound
/// pointer slot — the `__DATA,__got` or `__DATA,__la_symbol_ptr`
/// (or `__DATA_CONST,__got` on modern macOS) entry that dyld
/// fills in at load time. We translate that file offset to a
/// virtual address via the binary's already-built `section_maps`,
/// so the key in the returned map is the slot's VA.
///
/// Why the slot VA (and not the stub VA in `__TEXT,__stubs`)?
/// On ARM64 PIC-compiled code — which is everything on Apple
/// Silicon — direct `bl _printf` lowers to either:
///   * `bl _printf_stub` where the stub is 3 instructions
///     (`adrp x16, slot@PAGE; ldr x16, [x16, slot@PAGEOFF]; br x16`),
///     so the BL target is the stub VA. The stub immediately
///     dereferences the slot we register here — capa's
///     instruction-walker can follow that one hop.
///   * `adrp xN, slot@GOTPAGE; ldr xN, [xN, slot@GOTPAGEOFF];
///     blr xN` inlined at the call site, where the BLR target
///     register holds the slot value loaded by the LDR. Again
///     dereferences the slot we registered.
///
/// Registering the slot VA is the single most useful key for
/// modern macOS analysis; stub-VA enumeration via
/// `LC_DYSYMTAB.indirectsymoff` is a follow-up
/// (most analysers already chase the slot through the
/// `apirefs` walker).
///
/// Fat binaries: import offsets goblin returns are SLICE-RELATIVE
/// (inside the chosen ARM64 / x86_64 slice). The
/// `section_maps[i].file_offset` field is WHOLE-FILE-RELATIVE
/// (slice_offset already folded in by `map_binary`). We re-derive
/// the slice offset via `extract_macho_with_offset` and add it to
/// `import.offset` before looking up the section map. Thin
/// Mach-O has `slice_offset = 0` so this is a no-op for the
/// common case.
///
/// Returns an empty map on any failure (no panics) — the analyser
/// continues without API resolution, which is the same
/// graceful-degradation pattern as the ELF path.
#[must_use]
pub fn extract_macho_dynamic_apis(
    binary: &[u8],
    section_maps: &[SectionMap],
    prefer: crate::MachoArchPreference,
) -> std::collections::HashMap<u64, (Option<String>, Option<String>)> {
    let mut api_map = std::collections::HashMap::new();
    let Ok((mach, slice_offset)) = extract_macho_with_offset(binary, prefer) else {
        return api_map;
    };
    let Ok(imports) = mach.imports() else {
        return api_map;
    };
    let Ok(slice_off_usz) = usize::try_from(slice_offset) else {
        return api_map;
    };
    for imp in &imports {
        let Ok(slice_rel_off) = usize::try_from(imp.offset) else {
            continue;
        };
        let Some(abs_file_off) = slice_rel_off.checked_add(slice_off_usz) else {
            continue;
        };
        // Linear scan of section_maps to find the segment that
        // contains the bound-pointer slot. Mach-O typically has <10
        // segments — not worth a sorted-binary-search.
        for sm in section_maps {
            let seg_end = match sm.file_offset.checked_add(sm.file_size) {
                Some(e) => e,
                None => continue,
            };
            if abs_file_off >= sm.file_offset && abs_file_off < seg_end {
                let intra_seg_off = (abs_file_off - sm.file_offset) as u64;
                let va = sm.va_start.saturating_add(intra_seg_off);
                api_map.insert(
                    va,
                    (Some(imp.dylib.to_string()), Some(imp.name.to_string())),
                );
                break;
            }
        }
    }

    // (0.6.5) Second pass — walk `__TEXT,__stubs` (and the
    // symbol-pointer sections) via `LC_DYSYMTAB.indirectsymoff` to
    // register STUB VAs. Pre-0.6.5 we only registered __DATA bound-
    // pointer slot VAs (covers ADRP+LDR+BLR patterns where the call
    // target is the loaded register value); direct `bl _stub` calls
    // — overwhelmingly the most common call form on ARM64 PIC code
    // — were unresolved because the BL target is the stub address
    // inside __TEXT,__stubs, not the slot.
    //
    // Algorithm (Apple `<mach-o/loader.h>` §indirect symbol table):
    //   1. Find LC_DYSYMTAB → `(indirectsymoff, nindirectsyms)`.
    //   2. Read `nindirectsyms` u32-LE entries from raw bytes at
    //      `slice_offset + indirectsymoff`. Each entry is either a
    //      symbol-table index OR the sentinel `INDIRECT_SYMBOL_LOCAL`
    //      (`0x8000_0000`) / `INDIRECT_SYMBOL_ABS` (`0x4000_0000`).
    //   3. Collect `mach.symbols()` into a Vec<String> so we can
    //      look up symbol names by index.
    //   4. For every section whose `flags & 0xff` is a stub /
    //      symbol-pointer type, derive entry size & count, then for
    //      each entry: `stub_va = section.addr + i * entry_size`,
    //      `sym_idx = indirect_syms[section.reserved1 + i]`, look
    //      up symbol name, register `(stub_va, name)`.
    //
    // Section types we cover (low byte of section.flags):
    //   - S_SYMBOL_STUBS              (0x08) — __TEXT,__stubs /
    //                                   __auth_stubs. Entry size in
    //                                   section.reserved2.
    //   - S_NON_LAZY_SYMBOL_POINTERS  (0x06) — __DATA,__got /
    //                                   __DATA_CONST,__got. Entry =
    //                                   pointer width (4 / 8).
    //   - S_LAZY_SYMBOL_POINTERS      (0x07) — __DATA,__la_symbol_ptr.
    //                                   Entry = pointer width.
    //   - S_LAZY_DYLIB_SYMBOL_POINTERS(0x10) — __DATA,__ld_symbol_ptr
    //                                   (older). Entry = pointer width.
    //
    // Bound-pointer entries we already added in the first pass are
    // re-keyed at the same VA here (cheap HashMap re-insert with
    // identical value, no behaviour change).
    {
        use goblin::mach::load_command::CommandVariant;
        // S_* section type constants — Apple `<mach-o/loader.h>`.
        const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x06;
        const S_LAZY_SYMBOL_POINTERS: u32 = 0x07;
        const S_SYMBOL_STUBS: u32 = 0x08;
        const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
        const SECTION_TYPE_MASK: u32 = 0xff;
        // Indirect-symbol-table sentinel bits.
        const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
        const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
        const INDIRECT_SYMBOL_SENTINEL_MASK: u32 = INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS;

        // 1. Locate LC_DYSYMTAB.
        let dysymtab = mach.load_commands.iter().find_map(|lc| match &lc.command {
            CommandVariant::Dysymtab(ds) => Some(ds),
            _ => None,
        });
        let Some(dysymtab) = dysymtab else {
            return api_map;
        };
        if dysymtab.nindirectsyms == 0 {
            return api_map;
        }

        // 2. Read the indirect symbol table. Each entry is a u32-LE.
        // The on-disk offset is slice-relative; fold in slice_offset
        // to index into the whole-buffer `binary` slice.
        let Ok(indirectsymoff_usz) = usize::try_from(dysymtab.indirectsymoff) else {
            return api_map;
        };
        let Some(table_start) = indirectsymoff_usz.checked_add(slice_off_usz) else {
            return api_map;
        };
        let Ok(n_indirect_usz) = usize::try_from(dysymtab.nindirectsyms) else {
            return api_map;
        };
        let Some(table_bytes_len) = n_indirect_usz.checked_mul(4) else {
            return api_map;
        };
        let Some(table_end) = table_start.checked_add(table_bytes_len) else {
            return api_map;
        };
        if table_end > binary.len() {
            return api_map;
        }
        let table_slice = &binary[table_start..table_end];
        let mut indirect_syms: Vec<u32> = Vec::with_capacity(n_indirect_usz);
        for chunk in table_slice.chunks_exact(4) {
            indirect_syms.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }

        // 3. Collect symbol names indexed by position. goblin's
        // `MachO::symbols()` yields `Result<(Cow<str>, Nlist)>`; we
        // keep the name string (or empty on error so positional
        // indexing stays aligned with the on-disk symbol table).
        let symbol_names: Vec<String> = mach
            .symbols()
            .map(|res| match res {
                Ok((name, _nlist)) => name.to_string(),
                Err(_) => String::new(),
            })
            .collect();

        // 4. Per-bitness pointer width for symbol-pointer sections
        // (stub sections use `reserved2` directly so this is only
        // for S_*_SYMBOL_POINTERS).
        const CPU_ARCH_ABI64: u32 = 0x0100_0000;
        let is_64 = mach.header.cputype() & CPU_ARCH_ABI64 != 0;
        let ptr_size: u64 = if is_64 { 8 } else { 4 };

        // 5. Walk segment load commands and parse each section
        // header manually — goblin's generalised `Section` type
        // drops the `reserved1` / `reserved2` fields we need
        // (those live only on the format-specific `Section32` /
        // `Section64` types behind the generic API). We re-derive
        // the section-header file position from
        // `slice_off_usz + lc.offset + sizeof(SegmentCommand{32,64})`
        // and read the fields directly.
        //
        // Endianness: Apple has shipped exclusively little-endian
        // (x86, x86_64, arm64) since the PowerPC retirement. We
        // parse LE unconditionally. A big-endian PowerPC Mach-O
        // would silently fail this pass — analysis continues, just
        // without stub-VA resolution.
        use goblin::mach::load_command::CommandVariant as CV;
        // SegmentCommand{32,64} sizes (Apple <mach-o/loader.h>).
        const SIZEOF_SEGMENT_COMMAND_32: usize = 56;
        const SIZEOF_SEGMENT_COMMAND_64: usize = 72;
        // Section{32,64} sizes (right after the segment command,
        // contiguous in raw bytes).
        const SIZEOF_SECTION_32: usize = 68;
        const SIZEOF_SECTION_64: usize = 80;

        for lc in &mach.load_commands {
            let (nsects, lc_size, sect_size) = match &lc.command {
                CV::Segment32(seg) => (
                    seg.nsects as usize,
                    SIZEOF_SEGMENT_COMMAND_32,
                    SIZEOF_SECTION_32,
                ),
                CV::Segment64(seg) => (
                    seg.nsects as usize,
                    SIZEOF_SEGMENT_COMMAND_64,
                    SIZEOF_SECTION_64,
                ),
                _ => continue,
            };
            let Some(seg_abs_off) = slice_off_usz.checked_add(lc.offset) else {
                continue;
            };
            let Some(first_sect_off) = seg_abs_off.checked_add(lc_size) else {
                continue;
            };

            for i_sect in 0..nsects {
                let Some(sh_off) = first_sect_off.checked_add(i_sect.saturating_mul(sect_size))
                else {
                    break;
                };
                let Some(sh_end) = sh_off.checked_add(sect_size) else {
                    break;
                };
                if sh_end > binary.len() {
                    break;
                }
                let sh = &binary[sh_off..sh_end];

                // Field offsets within Section{32,64}:
                //   Section64 (80 bytes): sectname[16] segname[16]
                //     addr u64 @32, size u64 @40, offset u32 @48,
                //     align u32 @52, reloff u32 @56, nreloc u32 @60,
                //     flags u32 @64, reserved1 u32 @68,
                //     reserved2 u32 @72, reserved3 u32 @76.
                //   Section32 (68 bytes): sectname[16] segname[16]
                //     addr u32 @32, size u32 @36, offset u32 @40,
                //     align u32 @44, reloff u32 @48, nreloc u32 @52,
                //     flags u32 @56, reserved1 u32 @60,
                //     reserved2 u32 @64.
                let (addr, size, flags, reserved1, reserved2);
                if sect_size == SIZEOF_SECTION_64 {
                    addr = u64::from_le_bytes([
                        sh[32], sh[33], sh[34], sh[35], sh[36], sh[37], sh[38], sh[39],
                    ]);
                    size = u64::from_le_bytes([
                        sh[40], sh[41], sh[42], sh[43], sh[44], sh[45], sh[46], sh[47],
                    ]);
                    flags = u32::from_le_bytes([sh[64], sh[65], sh[66], sh[67]]);
                    reserved1 = u32::from_le_bytes([sh[68], sh[69], sh[70], sh[71]]);
                    reserved2 = u32::from_le_bytes([sh[72], sh[73], sh[74], sh[75]]);
                } else {
                    addr = u32::from_le_bytes([sh[32], sh[33], sh[34], sh[35]]) as u64;
                    size = u32::from_le_bytes([sh[36], sh[37], sh[38], sh[39]]) as u64;
                    flags = u32::from_le_bytes([sh[56], sh[57], sh[58], sh[59]]);
                    reserved1 = u32::from_le_bytes([sh[60], sh[61], sh[62], sh[63]]);
                    reserved2 = u32::from_le_bytes([sh[64], sh[65], sh[66], sh[67]]);
                }

                let stype = flags & SECTION_TYPE_MASK;
                let entry_size: u64 = match stype {
                    S_SYMBOL_STUBS => reserved2 as u64,
                    S_NON_LAZY_SYMBOL_POINTERS
                    | S_LAZY_SYMBOL_POINTERS
                    | S_LAZY_DYLIB_SYMBOL_POINTERS => ptr_size,
                    _ => continue,
                };
                if entry_size == 0 {
                    // Defensive — `reserved2` of zero on a stub
                    // section would loop forever. Apple stubs are
                    // always 6, 10, 12, or 16 bytes; never 0.
                    continue;
                }
                let n_entries = size / entry_size;
                let reserved1_usz = reserved1 as usize;
                for i in 0..n_entries {
                    let Some(idx_in_table) = reserved1_usz.checked_add(i as usize) else {
                        break;
                    };
                    let Some(&raw_sym) = indirect_syms.get(idx_in_table) else {
                        break;
                    };
                    // Skip sentinels — these slots have no symbol
                    // name (LOCAL = static function pointer, ABS =
                    // resolved at link time to an absolute value).
                    if raw_sym & INDIRECT_SYMBOL_SENTINEL_MASK != 0 {
                        continue;
                    }
                    let sym_idx = raw_sym as usize;
                    let Some(name) = symbol_names.get(sym_idx) else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let stub_va = addr.saturating_add(i.saturating_mul(entry_size));
                    // Mach-O symbol names are Apple-mangled with a
                    // leading underscore (`_printf`). Strip it for
                    // consistency with the ELF / PE paths and with
                    // capa rule conventions (rules say `printf`,
                    // not `_printf`).
                    let clean = name.strip_prefix('_').unwrap_or(name).to_string();
                    // Dylib name isn't on the indirect-symbol path
                    // (that data lives in the bind opcode stream the
                    // first pass already walked). Preserve any
                    // existing dylib name registered for this VA in
                    // the first pass.
                    let dylib = api_map.get(&stub_va).and_then(|(d, _)| d.clone());
                    api_map.insert(stub_va, (dylib, Some(clean)));
                }
            }
        }
    }

    api_map
}

/// Best-effort import list — `(dylib_name, symbol_name, _0)`. Pulled
/// from `MachO::imports()` which walks the bind / lazy-bind opcode
/// streams. Returns an empty Vec on parse failure.
#[must_use]
pub fn get_imports(mach: &MachO) -> Vec<(String, String, usize)> {
    let Ok(imports) = mach.imports() else {
        return Vec::new();
    };
    imports
        .iter()
        .filter_map(|i| {
            // 0.5.1: usize::try_from rejects oversized offsets on
            // 32-bit hosts rather than silently truncating.
            usize::try_from(i.offset)
                .ok()
                .map(|off| (i.dylib.to_string(), i.name.to_string(), off))
        })
        .collect()
}

/// Best-effort export list — `(name, vmaddr, None)`. Pulled from the
/// export trie via `MachO::exports()`. Returns an empty Vec on parse
/// failure or unsupported chained-fixup format.
#[must_use]
pub fn get_exports(mach: &MachO) -> Vec<(String, usize, Option<String>)> {
    let Ok(exports) = mach.exports() else {
        return Vec::new();
    };
    exports
        .iter()
        .filter_map(|e| {
            usize::try_from(e.offset)
                .ok()
                .map(|off| (e.name.clone(), off, None))
        })
        .collect()
}

/// Entry-point VA. Mach-O records this as either an `LC_MAIN`
/// entryoff (offset into `__TEXT`) or an `LC_UNIXTHREAD` thread state
/// register dump. We honour `LC_MAIN` when present (most common on
/// modern macOS / iOS); otherwise return 0.
#[must_use]
pub fn get_entry_point(mach: &MachO, base_addr: u64) -> u64 {
    // 0.6.0 fix: goblin's `MachO.entry` returns the absolute VA for
    // LC_MAIN binaries (the Apple-silicon / modern Intel default —
    // entryoff is parsed and combined with the __TEXT segment vmaddr
    // by goblin before exposure). For older LC_UNIXTHREAD binaries
    // it returns the thread-state PC, which is also absolute.
    //
    // The pre-0.6.0 path added `base_addr` unconditionally, which
    // double-counted: for /bin/ls (base 0x1_0000_0000, real entry
    // 0x1_0000_0960) we ended up at 0x2_0000_0960 — outside
    // `code_areas`, silently rejected by `passes_code_filter`.
    // The bug was invisible until AArch64 work made the entry the
    // primary function-discovery seed.
    //
    // Treat values that already look like absolute VAs (i.e.
    // >= base_addr) as VAs; treat smaller values (which would only
    // happen on degenerate Mach-Os with base_addr == 0 or a very
    // old format) as offsets to be added in.
    match mach.entry {
        0 => 0,
        e if e >= base_addr => e,
        off => base_addr.saturating_add(off),
    }
}
