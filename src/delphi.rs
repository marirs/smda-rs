//! Delphi VMT (Virtual Method Table) scanner (0.4.2).
//!
//! Detects Delphi-compiled binaries by scanning every readable section
//! for the `vmtSelfPtr` self-reference signature. When found, recovers
//! the class name (Pascal short string) and walks the user-virtual-method
//! table to seed method addresses as function candidates with
//! `ClassName::vmt_N` symbol names.
//!
//! Covers Delphi 7 → XE10+ for 32-bit code where the VMT layout has
//! been stable for two decades. Best-effort scan for 64-bit code (Delphi
//! 64-bit doubled the offsets but kept the same self-pointer
//! convention).
//!
//! Failure modes are silent: any bounds violation, malformed string, or
//! non-executable method pointer skips the candidate rather than failing
//! the whole analysis. Conservative class-name filter (printable ASCII,
//! length ≤ 100) drops most false positives.
//!
//! ## VMT layout (32-bit Delphi)
//!
//! ```text
//!   ... (system fields at negative offsets from vtable start) ...
//!   -0x4C  vmtSelfPtr      (4 bytes)  = vtable_VA  ← signature
//!   -0x2C  vmtClassName    (4 bytes)  → Pascal short string
//!   -0x24  vmtParent       (4 bytes)  → parent VMT
//!   ...
//!    0x00  user virtual method 0      ← vtable starts here
//!    0x04  user virtual method 1
//!    ...
//! ```
//!
//! 64-bit Delphi doubles every offset: `vmtSelfPtr` at `-0x98`,
//! `vmtClassName` at `-0x58`, etc. Pointer size is 8 bytes.

use crate::BinaryInfo;
use std::collections::HashMap;

const VMT_SELFPTR_OFF_32: u64 = 0x4C;
const VMT_CLASSNAME_OFF_32: u64 = 0x2C;
const VMT_SELFPTR_OFF_64: u64 = 0x98;
const VMT_CLASSNAME_OFF_64: u64 = 0x58;
const MAX_VTABLE_METHODS: usize = 256;
const MAX_CLASSNAME_LEN: u8 = 100;

/// Scan `bi` for Delphi VMTs. Returns a map from each discovered virtual
/// method's VA to its symbolic name (`ClassName::vmt_<index>`). The
/// vtable's class-info VA itself is **not** in the returned map — only
/// the executable method addresses, which is what the candidate scanner
/// + `function_symbols` pipeline want.
///
/// Empty map on non-Delphi binaries (no VMT signatures found) or on
/// unsupported pointer sizes.
#[must_use]
pub fn parse(bi: &BinaryInfo) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let ptrsize = bi.bitness / 8;
    if ptrsize != 4 && ptrsize != 8 {
        return out;
    }
    let (selfptr_off, classname_off) = if ptrsize == 4 {
        (VMT_SELFPTR_OFF_32, VMT_CLASSNAME_OFF_32)
    } else {
        (VMT_SELFPTR_OFF_64, VMT_CLASSNAME_OFF_64)
    };
    // Distance from vmtSelfPtr position to vmtClassName position.
    // Both sit at negative offsets from vtable start; classname is
    // closer to vtable start (selfptr_off > classname_off).
    let selfptr_to_classname = selfptr_off - classname_off;

    for sm in &bi.section_maps {
        let Some(end) = sm.file_offset.checked_add(sm.file_size) else {
            continue;
        };
        let Some(sec_bytes) = bi.raw_data.get(sm.file_offset..end) else {
            continue;
        };
        let step = ptrsize as usize;
        if sec_bytes.len() < step {
            continue;
        }
        // Scan at pointer-aligned positions.
        let mut i = 0usize;
        while i + step <= sec_bytes.len() {
            let value = read_ptr(&sec_bytes[i..], ptrsize);
            // Compute the VA of position i (saturating to avoid overflow
            // on contrived inputs).
            let va_at_i = sm.va_start.saturating_add(i as u64);
            // Signature: this position holds a pointer to (this_va + selfptr_off).
            if value != 0 && value == va_at_i.saturating_add(selfptr_off) {
                let vtable_va = value;
                // Class-name pointer position = vmtSelfPtr position + (selfptr_off - classname_off)
                let cname_pos_in_section = i.saturating_add(selfptr_to_classname as usize);
                if cname_pos_in_section + step <= sec_bytes.len() {
                    let cname_ptr = read_ptr(&sec_bytes[cname_pos_in_section..], ptrsize);
                    if let Some(class_name) = read_pascal_short_string(bi, cname_ptr) {
                        // Walk the user virtual method table.
                        for (m_va, m_idx) in walk_vtable(bi, vtable_va, ptrsize) {
                            // Don't overwrite if another VMT (or another
                            // symbol source) already named this address.
                            out.entry(m_va)
                                .or_insert_with(|| format!("{class_name}::vmt_{m_idx}"));
                        }
                    }
                }
            }
            i += step;
        }
    }
    out
}

fn read_ptr(buf: &[u8], ptrsize: u32) -> u64 {
    match ptrsize {
        4 if buf.len() >= 4 => u32::from_le_bytes(buf[0..4].try_into().unwrap_or([0; 4])) as u64,
        8 if buf.len() >= 8 => u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

/// Read a Pascal short string (`length byte | ASCII bytes`) at `va`.
/// Filters out empty, overlong, and non-printable strings to keep
/// false-positive VMT hits from leaking junk class names.
fn read_pascal_short_string(bi: &BinaryInfo, va: u64) -> Option<String> {
    if va == 0 {
        return None;
    }
    let len_byte = bi.bytes_at(va, 1).ok()?[0];
    if len_byte == 0 || len_byte > MAX_CLASSNAME_LEN {
        return None;
    }
    let bytes = bi.bytes_at(va.checked_add(1)?, len_byte as u32).ok()?;
    if !bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'_')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Walk the user-virtual-method table at `vtable_va`. Stops at the first
/// null pointer, the first pointer outside the image, or after
/// [`MAX_VTABLE_METHODS`] entries. Returns `(method_va, index)` pairs.
fn walk_vtable(bi: &BinaryInfo, vtable_va: u64, ptrsize: u32) -> Vec<(u64, usize)> {
    let mut out = Vec::new();
    for idx in 0..MAX_VTABLE_METHODS {
        let off = (idx as u64).saturating_mul(ptrsize as u64);
        let Some(pos) = vtable_va.checked_add(off) else {
            break;
        };
        let Ok(buf) = bi.bytes_at(pos, ptrsize) else {
            break;
        };
        let mptr = read_ptr(buf, ptrsize);
        if mptr == 0 {
            break;
        }
        if !is_addr_in_image(bi, mptr) {
            break;
        }
        out.push((mptr, idx));
    }
    out
}

fn is_addr_in_image(bi: &BinaryInfo, va: u64) -> bool {
    bi.section_maps
        .iter()
        .any(|sm| va >= sm.va_start && va < sm.va_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileArchitecture, FileFormat, SectionMap};

    /// Build a synthetic 32-bit Delphi VMT inside a 0x300-byte blob:
    ///
    /// - Class name `TFoo` at offset 0x100 (Pascal short string: `[4, 'T', 'F', 'o', 'o']`).
    /// - vtable_start at VA `base + 0x18C`.
    /// - vmtSelfPtr at offset 0x140, value `base + 0x18C` (= vtable_start).
    /// - vmtClassName at offset 0x140 + (0x4C - 0x2C) = 0x160, value `base + 0x100`.
    /// - user virtual method 0 at vtable offset 0x18C, value `base + 0x1F0` (an in-image pointer).
    /// - vtable terminator (null) at offset 0x190.
    #[test]
    fn detects_synthetic_32bit_vmt() {
        let base = 0x400000u64;
        let mut bytes = vec![0u8; 0x300];

        // Pascal short string at 0x100: length 4, "TFoo".
        bytes[0x100] = 4;
        bytes[0x101..0x105].copy_from_slice(b"TFoo");

        // vmtSelfPtr at 0x140 → vtable_start (base + 0x18C).
        let vtable_va = base + 0x18C;
        bytes[0x140..0x144].copy_from_slice(&(vtable_va as u32).to_le_bytes());

        // vmtClassName at 0x160 → classname VA (base + 0x100).
        bytes[0x160..0x164].copy_from_slice(&((base + 0x100) as u32).to_le_bytes());

        // user virtual method 0 at vtable_start (offset 0x18C).
        let method_va = base + 0x1F0;
        bytes[0x18C..0x190].copy_from_slice(&(method_va as u32).to_le_bytes());
        // Implicit zero at 0x190 stops the vtable walk.

        // Wrap in a BinaryInfo with a single section covering the whole blob.
        // We can't go through `from_buffer` because that takes ownership of the
        // borrow; construct the struct directly to keep this self-contained.
        let bi = BinaryInfo {
            file_format: FileFormat::PE,
            file_architecture: FileArchitecture::I386,
            base_addr: base,
            raw_data: &bytes,
            section_maps: vec![SectionMap {
                va_start: base,
                va_end: base + bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len(),
            }],
            binary_size: bytes.len() as u64,
            bitness: 32,
            code_areas: vec![],
            component: String::new(),
            family: String::new(),
            file_path: String::new(),
            is_library: false,
            is_buffer: false,
            sha256: String::new(),
            entry_point: 0,
            sections: vec![("test".to_string(), base, bytes.len())],
            imports: vec![],
            exports: vec![],
            // (0.6.5) Mach-O slice preference plumbed through
            // BinaryInfo; defaults are harmless for non-Mach-O
            // formats like this PE test fixture.
            macho_arch_preference: crate::MachoArchPreference::HostNative,
        };

        let result = parse(&bi);
        assert!(
            !result.is_empty(),
            "expected at least one VMT method, got empty result"
        );
        assert!(
            result.contains_key(&method_va),
            "expected method VA 0x{method_va:x} in result, got {result:?}"
        );
        assert_eq!(result[&method_va], "TFoo::vmt_0");
    }

    /// 64-bit Delphi: offsets double (0x4C → 0x98, 0x2C → 0x58); pointers are u64.
    #[test]
    fn detects_synthetic_64bit_vmt() {
        let base = 0x140000000u64;
        let mut bytes = vec![0u8; 0x400];

        bytes[0x100] = 4;
        bytes[0x101..0x105].copy_from_slice(b"TBar");

        let vtable_va = base + 0x240;
        // vmtSelfPtr at 0x1A8 (= 0x240 - 0x98)
        let selfptr_off_in_blob = 0x240 - 0x98;
        bytes[selfptr_off_in_blob..selfptr_off_in_blob + 8]
            .copy_from_slice(&vtable_va.to_le_bytes());

        // vmtClassName at 0x240 - 0x58 = 0x1E8
        let cname_off_in_blob = 0x240 - 0x58;
        bytes[cname_off_in_blob..cname_off_in_blob + 8]
            .copy_from_slice(&(base + 0x100).to_le_bytes());

        // user virtual method 0 at vtable_start
        let method_va = base + 0x300;
        bytes[0x240..0x248].copy_from_slice(&method_va.to_le_bytes());
        // implicit zero at 0x248 stops walk

        let bi = BinaryInfo {
            file_format: FileFormat::PE,
            file_architecture: FileArchitecture::AMD64,
            base_addr: base,
            raw_data: &bytes,
            section_maps: vec![SectionMap {
                va_start: base,
                va_end: base + bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len(),
            }],
            binary_size: bytes.len() as u64,
            bitness: 64,
            code_areas: vec![],
            component: String::new(),
            family: String::new(),
            file_path: String::new(),
            is_library: false,
            is_buffer: false,
            sha256: String::new(),
            entry_point: 0,
            sections: vec![("test".to_string(), base, bytes.len())],
            imports: vec![],
            exports: vec![],
            // (0.6.5) Mach-O slice preference plumbed through
            // BinaryInfo; defaults are harmless for non-Mach-O
            // formats like this PE test fixture.
            macho_arch_preference: crate::MachoArchPreference::HostNative,
        };

        let result = parse(&bi);
        assert!(
            !result.is_empty(),
            "expected at least one VMT method (64-bit), got empty result"
        );
        assert!(
            result.contains_key(&method_va),
            "expected method VA 0x{method_va:x} in result, got {result:?}"
        );
        assert_eq!(result[&method_va], "TBar::vmt_0");
    }
}
