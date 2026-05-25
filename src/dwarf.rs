//! Minimal DWARF symbol resolver (0.4.2 — MinGW PE).
//!
//! Walks `.debug_info` / `.debug_abbrev` / `.debug_str` in PE files compiled
//! with MinGW-GCC and recovers `(function_va, function_name)` pairs from
//! `DW_TAG_subprogram` DIEs that carry a `DW_AT_low_pc`.
//!
//! Limited intentionally: no inline-function expansion, no DW_AT_specification
//! fallback, no DWARF v5 split-unit support. Those add a lot of code for
//! marginal recovery on the typical MinGW malware sample. Upstream extensions
//! can layer on top of `gimli` directly if needed.
//!
//! Failure modes are silent: missing sections, malformed DWARF, or any
//! `gimli::Error` returns an empty map. DWARF parsing should never fail
//! the whole analysis.

use std::collections::HashMap;

/// Look for MinGW-GCC DWARF debug sections in `pe_bytes` and recover
/// `(low_pc_va, function_name)` pairs from `DW_TAG_subprogram` DIEs.
///
/// `image_base` is the PE `ImageBase` — needed because DWARF `low_pc`
/// values may be encoded as RVAs or as absolute VAs depending on the
/// toolchain (newer MinGW emits VAs, older emits RVAs). We accept the
/// value as-is when it looks like an absolute VA (>= `image_base`);
/// otherwise add `image_base`.
#[must_use]
pub fn parse_pe(pe_bytes: &[u8], image_base: u64) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let pe = match goblin::Object::parse(pe_bytes) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return out,
    };
    let section = |name: &str| -> &[u8] {
        for s in &pe.sections {
            let sec_name = std::str::from_utf8(&s.name).unwrap_or("");
            // Section names may have a trailing NUL or "/n" string-table
            // ref; match on the prefix only.
            if sec_name.trim_end_matches('\0').starts_with(name) {
                let start = s.pointer_to_raw_data as usize;
                let len = s.size_of_raw_data as usize;
                if let Some(slice) = pe_bytes.get(start..start.saturating_add(len)) {
                    return slice;
                }
            }
        }
        &[]
    };

    let debug_info = section(".debug_info");
    let debug_abbrev = section(".debug_abbrev");
    let debug_str = section(".debug_str");
    if debug_info.is_empty() || debug_abbrev.is_empty() {
        return out;
    }

    let endian = gimli::LittleEndian;
    let dwarf = gimli::Dwarf {
        debug_info: gimli::DebugInfo::new(debug_info, endian),
        debug_abbrev: gimli::DebugAbbrev::new(debug_abbrev, endian),
        debug_str: gimli::DebugStr::new(debug_str, endian),
        ..Default::default()
    };

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let unit_ref = unit.unit_ref(&dwarf);
        let mut entries = unit_ref.entries();
        while let Ok(Some((_delta, entry))) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            // low_pc is a code address or absolute VA.
            let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
                Ok(Some(gimli::AttributeValue::Addr(a))) => a,
                _ => continue,
            };
            if low_pc == 0 {
                continue;
            }
            // Prefer DW_AT_linkage_name (mangled, more specific) if present,
            // fall back to DW_AT_name.
            let name_attr = entry
                .attr_value(gimli::DW_AT_linkage_name)
                .ok()
                .flatten()
                .or_else(|| {
                    entry
                        .attr_value(gimli::DW_AT_MIPS_linkage_name)
                        .ok()
                        .flatten()
                })
                .or_else(|| entry.attr_value(gimli::DW_AT_name).ok().flatten());
            let Some(av) = name_attr else { continue };
            let Ok(slice) = unit_ref.attr_string(av) else {
                continue;
            };
            let raw = match std::str::from_utf8(slice.slice()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if raw.is_empty() {
                continue;
            }
            // Resolve mangled C++ / Rust names where we can; pass through
            // C names unchanged.
            let demangled = crate::demangle::maybe_demangle(raw);

            // Newer MinGW emits absolute VAs; older emits RVAs. Heuristic:
            // any value < image_base is treated as RVA.
            let va = if low_pc >= image_base {
                low_pc
            } else {
                image_base.saturating_add(low_pc)
            };
            out.insert(va, demangled);
        }
    }
    out
}
