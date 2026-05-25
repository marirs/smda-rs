//! PE debug-directory extraction (0.5.0).
//!
//! Surfaces parsed debug-directory records — primarily the
//! CodeView/PDB record — so downstream tooling can do symbol-server
//! (Microsoft SymSrv / Mozilla / Chromium symbol stores) lookups
//! without re-parsing the PE.
//!
//! Implemented via `goblin::pe::debug::DebugData`, which exposes
//! pre-parsed views of the most common entry types. The raw
//! `IMAGE_DEBUG_DIRECTORY` headers (timestamp, type code) aren't
//! exposed at this API level — instead we infer which entry kinds
//! were present from which `Option<…_info>` fields goblin populated.
//!
//! Returns `None` on:
//! - non-PE binaries (ELF / MachO / Buffer),
//! - PE files without an `IMAGE_DIRECTORY_ENTRY_DEBUG`,
//! - malformed debug directories that goblin couldn't parse.

use serde::{Deserialize, Serialize};

/// PE debug directory metadata. All fields are populated best-effort
/// from the first CodeView (PDB) entry in the debug directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct XMetadata {
    /// CodeView PDB GUID (16 bytes, lowercase hex, no hyphens), e.g.
    /// `"d4c3b2a18877665544332211ffffffff"`. Format matches what
    /// symbol stores key off.
    pub pdb_guid: Option<String>,
    /// CodeView PDB "age" — increments on every PDB rebuild.
    pub pdb_age: Option<u32>,
    /// PDB filename as embedded in the CodeView record (often a
    /// build-time absolute path like
    /// `D:\src\proj\Release\mybinary.pdb`).
    pub pdb_filename: Option<String>,
    /// Which debug-entry kinds goblin recognised in the directory.
    /// Useful for telling apart MSVC (codeview + vcfeature + pogo)
    /// vs MinGW (codeview only) vs Rust-msvc (codeview + repro) vs
    /// reproducible-build PEs (repro). Values are upstream names —
    /// `"codeview_pdb70"`, `"codeview_pdb20"`, `"vcfeature"`,
    /// `"ex_dll_characteristics"`, `"repro"`, `"pogo"`.
    ///
    /// `Vec<String>` (not `Vec<&'static str>`) so the struct stays
    /// `Deserialize` for callers that round-trip reports through JSON.
    pub debug_entry_kinds: Vec<String>,
}

/// Try to extract debug metadata from a PE blob. Returns `None` when
/// nothing useful was found (non-PE input, no debug directory, or
/// goblin parse failure).
#[must_use]
pub fn parse_pe(pe_bytes: &[u8]) -> Option<XMetadata> {
    let pe = match goblin::Object::parse(pe_bytes) {
        Ok(goblin::Object::PE(p)) => p,
        _ => return None,
    };
    let dbg = pe.debug_data.as_ref()?;
    let mut out = XMetadata::default();

    // Tag every parsed sub-record so callers can build "this PE is
    // MSVC vs MinGW vs Rust" heuristics without re-parsing.
    if dbg.codeview_pdb70_debug_info.is_some() {
        out.debug_entry_kinds.push("codeview_pdb70".to_string());
    }
    if dbg.codeview_pdb20_debug_info.is_some() {
        out.debug_entry_kinds.push("codeview_pdb20".to_string());
    }
    if dbg.vcfeature_info.is_some() {
        out.debug_entry_kinds.push("vcfeature".to_string());
    }
    if dbg.ex_dll_characteristics_info.is_some() {
        out.debug_entry_kinds
            .push("ex_dll_characteristics".to_string());
    }
    if dbg.repro_info.is_some() {
        out.debug_entry_kinds.push("repro".to_string());
    }
    if dbg.pogo_info.is_some() {
        out.debug_entry_kinds.push("pogo".to_string());
    }

    // CodeView (PDB 7.0 / RSDS) — the modern format MSVC + clang-cl emit.
    if let Some(cv) = dbg.codeview_pdb70_debug_info.as_ref() {
        out.pdb_guid = Some(hex_lower(&cv.signature));
        out.pdb_age = Some(cv.age);
        let raw = cv.filename;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if end > 0
            && let Ok(s) = std::str::from_utf8(&raw[..end])
        {
            out.pdb_filename = Some(s.to_string());
        }
    } else if let Some(cv) = dbg.codeview_pdb20_debug_info.as_ref() {
        // NB10 / PDB 2.0 — legacy MSVC.
        out.pdb_age = Some(cv.age);
        let raw = cv.filename;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        if end > 0
            && let Ok(s) = std::str::from_utf8(&raw[..end])
        {
            out.pdb_filename = Some(s.to_string());
        }
        out.pdb_guid = Some(format!("{:08x}", cv.signature));
    }

    if out == XMetadata::default() {
        None
    } else {
        Some(out)
    }
}

/// PDB 7.0 signature is a GUID — 16 raw bytes. SymSrv keys off the
/// concatenated lowercase-hex form, no separators.
fn hex_lower(sig: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in sig.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
