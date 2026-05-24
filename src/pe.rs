use crate::{Result, SectionMap, error::Error};
use std::convert::TryInto;

pub fn get_bitness(binary: &[u8]) -> Result<u32> {
    let mut bitness_id = 0;
    if let Ok(pe_offset) = get_pe_offset(binary)
        && pe_offset != 0
        && binary.len() as u64 >= pe_offset + 0x6
    {
        let bb: [u8; 2] = binary[pe_offset as usize + 0x4..pe_offset as usize + 0x6].try_into()?;
        bitness_id = u16::from_le_bytes(bb);
    }
    match bitness_id {
        0x14c => Ok(32),
        0x8664 => Ok(64),
        _ => Err(Error::UnsupportedPEBitnessIDError(bitness_id)),
    }
}

pub fn get_base_address(binary: &[u8]) -> Result<u64> {
    let _base_addr = 0;
    let pe_offset = get_pe_offset(binary)?;
    if pe_offset != 0 && binary.len() >= pe_offset as usize + 0x38 {
        if get_bitness(binary)? == 32 {
            let bb: [u8; 4] =
                binary[pe_offset as usize + 0x34..pe_offset as usize + 0x38].try_into()?;
            return Ok(u32::from_le_bytes(bb) as u64);
        } else if get_bitness(binary)? == 64 {
            let bb: [u8; 8] =
                binary[pe_offset as usize + 0x30..pe_offset as usize + 0x38].try_into()?;
            return Ok(u64::from_le_bytes(bb));
        }
    }
    Err(Error::PEBaseAddressError)
}

pub fn get_pe_offset(binary: &[u8]) -> Result<u64> {
    if binary.len() >= 0x40 {
        let bb: [u8; 2] = binary[0x3c..0x3c + 2].try_into()?;
        let pe_offset = u16::from_le_bytes(bb) as u64;
        return Ok(pe_offset);
    }
    Ok(0)
}

pub fn get_code_areas(binary: &[u8], pe: &goblin::pe::PE) -> Result<Vec<(u64, u64)>> {
    let mut res = vec![];
    let base_address = get_base_address(binary)?;
    for section in &pe.sections {
        if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
            let Some(section_start) = base_address.checked_add(section.virtual_address as u64)
            else {
                continue;
            };
            let mut section_size = section.virtual_size as u64;
            if !section_size.is_multiple_of(0x1000) {
                let pad = 0x1000 - (section_size % 0x1000);
                section_size = match section_size.checked_add(pad) {
                    Some(s) => s,
                    None => continue,
                };
            }
            let Some(section_end) = section_start.checked_add(section_size) else {
                continue;
            };
            res.push((section_start, section_end));
        }
    }
    Ok(res)
}

/// Hard cap on PE image size (matches the 100 MB limit that was hard-coded
/// in 0.2.x and the analogous ELF cap in `elf::MAX_MAPPED_BYTES`).
const MAX_MAPPED_BYTES: u64 = 100 * 1024 * 1024;

/// Parse the PE section table and return a `Vec<SectionMap>` describing
/// where each loaded section lives in both file and virtual-address space.
/// Zero-copy: this is metadata only, no bytes are copied. Callers
/// (`BinaryInfo`) thread the result through `bytes_at(va, len)` to read
/// section bytes on demand.
///
/// Pre-0.4.0 this allocated a contiguous mapped image (`Vec<u8>`) the
/// size of the virtual layout; 0.4.0 replaces that with the section
/// table so callers borrow directly from the input.
pub fn map_binary(binary: &[u8], base_addr: u64) -> Result<Vec<SectionMap>> {
    let pe_offset = get_pe_offset(binary)? as usize;
    let mut num_sections = 0;
    let mut optional_header_size = 0xF8;

    // pe_offset + 0x8 — pe_offset is u16-bounded by get_pe_offset, but
    // bound-check still to be tidy.
    let after_num_sect = pe_offset
        .checked_add(0x8)
        .ok_or(Error::PEOutOfBoundsSectionError)?;
    if binary.len() >= after_num_sect {
        num_sections =
            u16::from_le_bytes(binary[pe_offset + 0x6..pe_offset + 0x8].try_into()?) as usize;
        let bitness = get_bitness(binary)?;
        if bitness == 64 {
            optional_header_size = 0x108;
        }
    }

    // pe_offset + optional_header_size + num_sections * 0x28 — all
    // attacker-controlled-bounded; check each step.
    let header_end = pe_offset
        .checked_add(optional_header_size)
        .and_then(|h| {
            num_sections
                .checked_mul(0x28)
                .and_then(|s| h.checked_add(s))
        })
        .ok_or(Error::PEOutOfBoundsSectionError)?;
    if binary.len() < header_end {
        return Err(Error::PEOutOfBoundsSectionError);
    }

    let mut section_infos = Vec::with_capacity(num_sections);
    for section_index in 0..num_sections {
        let section_offset = section_index * 0x28; // num_sections * 0x28 was bounded above.
        let slice_start = pe_offset + optional_header_size + section_offset + 0x8;
        let slice_end = slice_start + 0x10;
        let virt_size = u32::from_le_bytes(binary[slice_start..slice_start + 4].try_into()?);
        let virt_offset = u32::from_le_bytes(binary[slice_start + 4..slice_start + 8].try_into()?);
        let raw_size = u32::from_le_bytes(binary[slice_start + 8..slice_start + 12].try_into()?);
        let raw_offset = u32::from_le_bytes(binary[slice_start + 12..slice_end].try_into()?);
        let section_info = hashmap! {
            "section_index".to_string() => section_index as u32,
            "virt_size".to_string() => virt_size,
            "virt_offset".to_string() => virt_offset,
            "raw_size".to_string() => raw_size,
            "raw_offset".to_string() => raw_offset
        };
        section_infos.push(section_info);
    }

    let mut max_virt_section_offset: u64 = 0;
    let mut min_raw_section_offset: u32 = 0xFFFFFFFF;

    for section_info in &section_infos {
        let virt_offset = section_info["virt_offset"] as u64;
        let virt_size = section_info["virt_size"] as u64;
        let raw_size = section_info["raw_size"] as u64;
        // Skip overflowing sections rather than wrapping (which historically
        // made `max_virt_section_offset` come out below `min_raw_section_offset`
        // and panic the slice copy below).
        if let Some(end) = virt_offset.checked_add(virt_size) {
            max_virt_section_offset = max_virt_section_offset.max(end);
        }
        if let Some(end) = virt_offset.checked_add(raw_size) {
            max_virt_section_offset = max_virt_section_offset.max(end);
        }
        if section_info["raw_offset"] > 0x200 {
            min_raw_section_offset = min_raw_section_offset.min(section_info["raw_offset"]);
        }
    }

    if max_virt_section_offset == 0 || max_virt_section_offset >= MAX_MAPPED_BYTES {
        return Err(Error::PEOutOfBoundsSectionError);
    }

    let mut section_maps = Vec::with_capacity(section_infos.len() + 1);

    // Synthetic "headers" section covering the PE header + section table.
    // Pre-0.4.0 these bytes were copied into the front of the mapped image
    // (the `min_raw_section_offset` clamp); we now expose them in VA space
    // by adding a section that runs from base_addr to the first section.
    let header_len = (min_raw_section_offset as usize).min(binary.len());
    if header_len > 0 {
        section_maps.push(SectionMap {
            va_start: base_addr,
            va_end: base_addr.saturating_add(header_len as u64),
            file_offset: 0,
            file_size: header_len,
        });
    }

    for section_info in &section_infos {
        let virt_offset = section_info["virt_offset"] as u64;
        let raw_offset = section_info["raw_offset"] as u64;
        let raw_size = section_info["raw_size"] as u64;
        let virt_size = section_info["virt_size"] as u64;

        // Skip sections with overflowing arithmetic rather than wrapping.
        let Some(va_start) = base_addr.checked_add(virt_offset) else {
            continue;
        };
        // The VA range is the larger of virtual_size and the on-disk size
        // (matches the historical behaviour of the mapped-image loader,
        // where the section occupied max(virt_size, raw_size) bytes).
        let va_extent = virt_size.max(raw_size);
        let Some(va_end) = va_start.checked_add(va_extent) else {
            continue;
        };
        // Clamp the on-disk extent to what the file actually contains —
        // a malformed PE that declares more bytes than exist would
        // otherwise let `bytes_at` over-read.
        let Some(binary_raw_end) = raw_offset.checked_add(raw_size) else {
            continue;
        };
        let file_size = if binary_raw_end <= binary.len() as u64 {
            raw_size
        } else {
            (binary.len() as u64).saturating_sub(raw_offset)
        };
        let (Ok(file_offset), Ok(file_size)) =
            (usize::try_from(raw_offset), usize::try_from(file_size))
        else {
            continue;
        };
        if file_offset >= binary.len() {
            continue;
        }
        section_maps.push(SectionMap {
            va_start,
            va_end,
            file_offset,
            file_size,
        });
    }

    // Keep sorted by va_start so `BinaryInfo::locate` finds the right
    // section quickly. For PE the section table is already in order, but
    // a malformed file could break that — sort defensively.
    section_maps.sort_by_key(|s| s.va_start);

    Ok(section_maps)
}
