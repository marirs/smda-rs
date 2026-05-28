//! Go `pclntab` parser (0.4.2 N1).
//!
//! Recovers function-start VAs and source-level names from the Go runtime's
//! `pclntab` (PC-line-table) blob embedded in every Go binary. This is the
//! single highest-value name-recovery source for stripped Go malware —
//! samples that look like one huge blob of `main_*` mystery functions
//! become navigable when their `pclntab` is parsed.
//!
//! Four magic versions are supported, matching the upstream Python smda
//! coverage:
//!
//! | Magic        | Go versions      | Layout                          |
//! |--------------|------------------|---------------------------------|
//! | `0xFFFFFFFB` | Go 1.2 – 1.15    | "v1.2" / "v1.12"                |
//! | `0xFFFFFFFA` | Go 1.16 – 1.17   | "v1.16"                         |
//! | `0xFFFFFFF1` | Go 1.18 – 1.19   | "v1.18" (textStart-relative)    |
//! | `0xFFFFFFF0` | Go 1.20+         | "v1.20" (textStart-relative)    |
//!
//! The parser is intentionally conservative: any field that fails a
//! bounds / sanity check is skipped, the rest of the table is still
//! attempted. A malformed `pclntab` therefore degrades gracefully to
//! "fewer names recovered" rather than failing the whole analysis.

use std::collections::HashMap;

/// Result of parsing a pclntab.
///
/// `version` and `pclntab_offset` are populated for downstream
/// inspection (debug / diagnostic tooling); no in-crate reader.
#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct GoSymbols {
    /// Map of function-start VA → demangled Go function name.
    pub func_names: HashMap<u64, String>,
    /// Which Go version family was detected.
    pub version: Option<GoVersion>,
    /// Where the magic was located in the input bytes (file offset).
    pub pclntab_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoVersion {
    V12,  // 0xFFFFFFFB — Go 1.2 – 1.15
    V116, // 0xFFFFFFFA — Go 1.16 – 1.17
    V118, // 0xFFFFFFF1 — Go 1.18 – 1.19
    V120, // 0xFFFFFFF0 — Go 1.20+
}

const MAGIC_V12: u32 = 0xFFFF_FFFB;
const MAGIC_V116: u32 = 0xFFFF_FFFA;
const MAGIC_V118: u32 = 0xFFFF_FFF1;
const MAGIC_V120: u32 = 0xFFFF_FFF0;

/// Scan `raw` for a pclntab header. Returns `(file_offset, version)` on the
/// first match. Linear scan over the binary; for a 100 MB sample this is a
/// few tens of milliseconds.
///
/// The header is recognised by `(magic, 0x00, 0x00, quantum, ptrsize)` where
/// `quantum` is 1 (x86/amd64) or 4 (arm) and `ptrsize` is 4 or 8. The
/// trailing-byte check rejects the vast majority of spurious magic
/// collisions.
#[must_use]
pub fn find_pclntab(raw: &[u8]) -> Option<(usize, GoVersion)> {
    if raw.len() < 8 {
        return None;
    }
    let mut i = 0usize;
    while i + 8 <= raw.len() {
        let m = u32::from_le_bytes(raw[i..i + 4].try_into().ok()?);
        let version = match m {
            MAGIC_V12 => GoVersion::V12,
            MAGIC_V116 => GoVersion::V116,
            MAGIC_V118 => GoVersion::V118,
            MAGIC_V120 => GoVersion::V120,
            _ => {
                i += 1;
                continue;
            }
        };
        // Trailing structure check: bytes 4,5 must be 0; byte 6 ∈ {1, 2, 4};
        // byte 7 ∈ {4, 8}. The "quantum=2" is rare but valid (some Go
        // variants), accept it.
        let z1 = raw[i + 4];
        let z2 = raw[i + 5];
        let quantum = raw[i + 6];
        let ptrsize = raw[i + 7];
        if z1 == 0 && z2 == 0 && matches!(quantum, 1 | 2 | 4) && matches!(ptrsize, 4 | 8) {
            return Some((i, version));
        }
        i += 1;
    }
    None
}

/// Top-level entry: scan `raw` and, on hit, parse out function-start VAs +
/// names. `text_section_va` is the VA of the `.text` section (PE) or the
/// executable PT_LOAD segment (ELF) — used as the `textStart` reference
/// for v1.18 / v1.20 (relative encoding). Pass `0` when unknown; v1.2 and
/// v1.16 layouts encode absolute VAs and ignore the parameter.
#[must_use]
pub fn parse(raw: &[u8], text_section_va: u64) -> GoSymbols {
    let Some((off, version)) = find_pclntab(raw) else {
        return GoSymbols::default();
    };
    let mut out = GoSymbols {
        func_names: HashMap::new(),
        version: Some(version),
        pclntab_offset: Some(off),
    };
    let tab = &raw[off..];
    let _ = match version {
        GoVersion::V12 => parse_v12(tab, off, raw, &mut out.func_names),
        GoVersion::V116 => parse_v116(tab, off, raw, &mut out.func_names),
        GoVersion::V118 | GoVersion::V120 => {
            parse_v118(tab, off, raw, text_section_va, &mut out.func_names)
        }
    };
    out
}

/// Read a u32 / u64 of `ptrsize` bytes (little-endian).
fn read_uintptr(buf: &[u8], offset: usize, ptrsize: u8) -> Option<u64> {
    match ptrsize {
        4 => buf
            .get(offset..offset + 4)?
            .try_into()
            .ok()
            .map(|b: [u8; 4]| u32::from_le_bytes(b) as u64),
        8 => buf
            .get(offset..offset + 8)?
            .try_into()
            .ok()
            .map(u64::from_le_bytes),
        _ => None,
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// Walk a NUL-terminated string starting at `raw[name_file_offset..]`.
fn read_cstr(raw: &[u8], name_file_offset: usize) -> Option<String> {
    let bytes = raw.get(name_file_offset..)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if end == 0 || end > 512 {
        // Empty or absurdly long names are almost certainly mis-aligned reads.
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
}

/// Go 1.2 layout.
///
/// ```text
///   +0   magic         (4 bytes, already validated)
///   +4   pad           (2 bytes, 0,0)
///   +6   quantum       (1 byte)
///   +7   ptrsize       (1 byte)
///   +8   nfunc         (ptrsize)
///   +8+ps  functab     (nfunc * 2 * ptrsize entries: entry VA, funcoff)
///        each funcoff points into the pclntab; at that offset the
///        `_func` struct starts:
///          +0 entry (ptrsize)
///          +ps nameoff (4 bytes) — offset into pclntab where name string lives
/// ```
fn parse_v12(
    tab: &[u8],
    tab_file_offset: usize,
    raw: &[u8],
    out: &mut HashMap<u64, String>,
) -> Option<()> {
    let ptrsize = *tab.get(7)?;
    let ps = ptrsize as usize;
    let nfunc = read_uintptr(tab, 8, ptrsize)?;
    if nfunc == 0 || nfunc > 1_000_000 {
        return None;
    }
    let entry_size = ps.checked_mul(2)?;
    let functab_off = 8usize.checked_add(ps)?;
    // 0.5.1 security: every offset arithmetic step uses checked_*. funcoff
    // and nameoff come from the on-disk pclntab — they are attacker-
    // controlled. Wrapping would panic in debug and silently corrupt in
    // release.
    for i in 0..nfunc as usize {
        let Some(row) = i
            .checked_mul(entry_size)
            .and_then(|x| x.checked_add(functab_off))
        else {
            return Some(());
        };
        let Some(entry_va) = read_uintptr(tab, row, ptrsize) else {
            continue;
        };
        let Some(funcoff_pos) = row.checked_add(ps) else {
            continue;
        };
        let funcoff = match read_uintptr(tab, funcoff_pos, ptrsize) {
            Some(f) => f as usize,
            None => continue,
        };
        let Some(nameoff_pos) = funcoff.checked_add(ps) else {
            continue;
        };
        let nameoff = match read_u32(tab, nameoff_pos) {
            Some(n) => n as usize,
            None => continue,
        };
        let Some(name_file_off) = tab_file_offset.checked_add(nameoff) else {
            continue;
        };
        if let Some(name) = read_cstr(raw, name_file_off)
            && !name.is_empty()
        {
            out.insert(entry_va, name);
        }
    }
    Some(())
}

/// Go 1.16 layout (similar to v1.2 but adds `funcnameOffset` field).
///
/// ```text
///   +0   magic        (4)
///   +4   pad          (2)
///   +6   quantum      (1)
///   +7   ptrsize      (1)
///   +8   nfunc        (ptrsize)
///   +8+ps  nfiles     (ptrsize)
///   +8+2ps funcname_offset (ptrsize) — offset within tab of funcname table
///   +8+3ps cuoffset    (ptrsize)
///   +8+4ps filetab_offset (ptrsize)
///   +8+5ps pctab_offset   (ptrsize)
///   +8+6ps pcln_offset    (ptrsize)
///   +8+7ps functab        — (nfunc * 2 * ptrsize)
///        each _func at funcoff:
///          +0 entry (ptrsize)
///          +ps nameoff (4)
/// ```
fn parse_v116(
    tab: &[u8],
    tab_file_offset: usize,
    raw: &[u8],
    out: &mut HashMap<u64, String>,
) -> Option<()> {
    let ptrsize = *tab.get(7)?;
    let ps = ptrsize as usize;
    let nfunc = read_uintptr(tab, 8, ptrsize)?;
    if nfunc == 0 || nfunc > 1_000_000 {
        return None;
    }
    let funcname_offset =
        read_uintptr(tab, 8usize.checked_add(ps.checked_mul(2)?)?, ptrsize)? as usize;
    let pcln_offset = read_uintptr(tab, 8usize.checked_add(ps.checked_mul(6)?)?, ptrsize)? as usize;
    let entry_size = ps.checked_mul(2)?;
    let functab_off = pcln_offset;
    for i in 0..nfunc as usize {
        let Some(row) = i
            .checked_mul(entry_size)
            .and_then(|x| x.checked_add(functab_off))
        else {
            return Some(());
        };
        let Some(entry_va) = read_uintptr(tab, row, ptrsize) else {
            continue;
        };
        let Some(funcoff_pos) = row.checked_add(ps) else {
            continue;
        };
        let funcoff = match read_uintptr(tab, funcoff_pos, ptrsize) {
            Some(f) => f as usize,
            None => continue,
        };
        let Some(nameoff_pos) = funcoff.checked_add(ps) else {
            continue;
        };
        let nameoff = match read_u32(tab, nameoff_pos) {
            Some(n) => n as usize,
            None => continue,
        };
        let Some(name_file_off) = tab_file_offset
            .checked_add(funcname_offset)
            .and_then(|x| x.checked_add(nameoff))
        else {
            continue;
        };
        if let Some(name) = read_cstr(raw, name_file_off)
            && !name.is_empty()
        {
            out.insert(entry_va, name);
        }
    }
    Some(())
}

/// Go 1.18 / 1.20 layout — adds `textStart` and switches `entry` to
/// u32-relative offsets.
///
/// ```text
///   +0   magic        (4)
///   +4   pad          (2)
///   +6   quantum      (1)
///   +7   ptrsize      (1)
///   +8   nfunc        (ptrsize)
///   +8+ps  nfiles     (ptrsize)
///   +8+2ps textStart  (ptrsize) — base VA for relative entries
///   +8+3ps funcname_offset (ptrsize)
///   +8+4ps cuoffset (ptrsize)
///   +8+5ps filetab_offset (ptrsize)
///   +8+6ps pctab_offset (ptrsize)
///   +8+7ps pcln_offset (ptrsize)
///   +pcln_offset functab — (nfunc * 2 * 4 bytes)
///        each entry: u32 entry_off (relative to textStart), u32 funcoff
///        each _func at funcoff:
///          +0 entry_off (u32, relative to textStart) — for v1.20
///          +4 nameoff (u32)
/// ```
///
/// If the table-encoded `textStart` is 0 (some PE samples seen in the wild),
/// fall back to the caller-supplied `text_section_va`.
fn parse_v118(
    tab: &[u8],
    tab_file_offset: usize,
    raw: &[u8],
    text_section_va_fallback: u64,
    out: &mut HashMap<u64, String>,
) -> Option<()> {
    let ptrsize = *tab.get(7)?;
    let ps = ptrsize as usize;
    let nfunc = read_uintptr(tab, 8, ptrsize)?;
    if nfunc == 0 || nfunc > 1_000_000 {
        return None;
    }
    let mut text_start = read_uintptr(tab, 8usize.checked_add(ps.checked_mul(2)?)?, ptrsize)?;
    if text_start == 0 {
        text_start = text_section_va_fallback;
    }
    let funcname_offset =
        read_uintptr(tab, 8usize.checked_add(ps.checked_mul(3)?)?, ptrsize)? as usize;
    let pcln_offset = read_uintptr(tab, 8usize.checked_add(ps.checked_mul(7)?)?, ptrsize)? as usize;
    // v1.18+ functab entries are fixed 8 bytes (two u32s) regardless of ptrsize.
    let entry_size = 8usize;
    for i in 0..nfunc as usize {
        let Some(row) = i
            .checked_mul(entry_size)
            .and_then(|x| x.checked_add(pcln_offset))
        else {
            return Some(());
        };
        let Some(entry_off) = read_u32(tab, row).map(|v| v as u64) else {
            continue;
        };
        let Some(funcoff_pos) = row.checked_add(4) else {
            continue;
        };
        let funcoff = match read_u32(tab, funcoff_pos) {
            Some(f) => f as usize,
            None => continue,
        };
        // _func struct: +0 entry_off (u32), +4 nameoff (u32). pctab sits
        // after the functab so the absolute offset is pcln_offset + funcoff + 4.
        let Some(nameoff_pos) = pcln_offset
            .checked_add(funcoff)
            .and_then(|x| x.checked_add(4))
        else {
            continue;
        };
        let nameoff = match read_u32(tab, nameoff_pos) {
            Some(n) => n as usize,
            None => continue,
        };
        let Some(entry_va) = text_start.checked_add(entry_off) else {
            continue;
        };
        let Some(name_file_off) = tab_file_offset
            .checked_add(funcname_offset)
            .and_then(|x| x.checked_add(nameoff))
        else {
            continue;
        };
        if let Some(name) = read_cstr(raw, name_file_off)
            && !name.is_empty()
        {
            out.insert(entry_va, name);
        }
    }
    Some(())
}
