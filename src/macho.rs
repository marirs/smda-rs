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
