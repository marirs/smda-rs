use crate::{Result, error::Error};
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

pub fn map_binary(binary: &[u8]) -> Result<Vec<u8>> {
    let mut mapped_binary = vec![];
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

    if max_virt_section_offset > 0 && max_virt_section_offset < MAX_MAPPED_BYTES {
        // Safe: bounded above.
        let mapped_len = max_virt_section_offset as usize;
        mapped_binary.resize(mapped_len, 0_u8);
        // Copy the headers — clamp to (mapped_len, binary.len()) so we
        // never panic on a section table that lies about raw_offset.
        let header_copy_len = (min_raw_section_offset as usize)
            .min(binary.len())
            .min(mapped_binary.len());
        if header_copy_len > 0 {
            mapped_binary[..header_copy_len].clone_from_slice(&binary[..header_copy_len]);
        }
    }

    for section_info in &section_infos {
        let virt_offset = section_info["virt_offset"] as u64;
        let raw_offset = section_info["raw_offset"] as u64;
        let raw_size = section_info["raw_size"] as u64;

        // All arithmetic on attacker-controlled u32-as-u64; use checked_add
        // and skip the section on any overflow rather than wrapping.
        let Some(mapped_to) = virt_offset.checked_add(raw_size) else {
            continue;
        };
        let Some(binary_raw_end) = raw_offset.checked_add(raw_size) else {
            continue;
        };

        if binary_raw_end > binary.len() as u64 || mapped_to > mapped_binary.len() as u64 {
            continue;
        }

        let (Ok(dst_start), Ok(dst_end), Ok(src_start), Ok(src_end)) = (
            usize::try_from(virt_offset),
            usize::try_from(mapped_to),
            usize::try_from(raw_offset),
            usize::try_from(binary_raw_end),
        ) else {
            continue;
        };

        let (Some(dst), Some(src)) = (
            mapped_binary.get_mut(dst_start..dst_end),
            binary.get(src_start..src_end),
        ) else {
            continue;
        };
        dst.clone_from_slice(src);
    }

    Ok(mapped_binary)
}
