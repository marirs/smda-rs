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

/// Pull the Intel Mach-O out of `binary`. For fat binaries, prefers
/// x86_64 over i386; returns `Error::UnsupportedFormatError` if neither
/// is present.
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
            // Prefer x86_64, fall back to i386.
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

/// Code-area extents — (va_start, va_end) of every segment that
/// either (a) carries VM_PROT_EXECUTE in `initprot`, or (b) is named
/// `__TEXT` / starts with `__TEXT`. The name fallback catches binaries
/// where the protection bits aren't set as we'd expect (goblin's field
/// layout for `initprot` varies between Mach-O dialects).
const VM_PROT_EXECUTE: u32 = 0x04;

#[must_use]
pub fn get_code_areas(mach: &MachO) -> Vec<(u64, u64)> {
    let mut areas = Vec::new();
    for seg in &mach.segments {
        let name = std::str::from_utf8(&seg.segname).unwrap_or("");
        let name = name.trim_end_matches('\0');
        let is_text = name.starts_with("__TEXT");
        let is_exec = seg.initprot & VM_PROT_EXECUTE != 0;
        if !(is_text || is_exec) {
            continue;
        }
        if let Some(end) = seg.vmaddr.checked_add(seg.vmsize) {
            areas.push((seg.vmaddr, end));
        }
    }
    areas
}

/// Mirror of `pe::map_binary` / `elf::map_binary`. `base_addr` is
/// accepted for API symmetry; Mach-O segments already carry absolute
/// VAs so it isn't added in.
pub fn map_binary(binary: &[u8], base_addr: u64) -> Result<Vec<SectionMap>> {
    let _ = base_addr;
    let mach = extract_intel(binary)?;
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
        let file_offset = seg.fileoff as usize;
        let declared_size = seg.filesize as usize;
        let file_size = if file_offset
            .checked_add(declared_size)
            .map(|e| e <= binary.len())
            .unwrap_or(false)
        {
            declared_size
        } else {
            binary.len().saturating_sub(file_offset)
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
                out.push((combined, sect.addr, sect.size as usize));
            }
        }
    }
    out
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
        .map(|i| (i.dylib.to_string(), i.name.to_string(), i.offset as usize))
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
        .map(|e| (e.name.clone(), e.offset as usize, None))
        .collect()
}

/// Entry-point VA. Mach-O records this as either an `LC_MAIN`
/// entryoff (offset into `__TEXT`) or an `LC_UNIXTHREAD` thread state
/// register dump. We honour `LC_MAIN` when present (most common on
/// modern macOS / iOS); otherwise return 0.
#[must_use]
pub fn get_entry_point(mach: &MachO, base_addr: u64) -> u64 {
    match mach.entry {
        0 => 0,
        off => base_addr.saturating_add(off),
    }
}
