use crate::{Result, SectionMap, error::Error};
use goblin::elf::program_header::{PT_DYNAMIC, PT_LOAD};
use std::collections::{HashMap, HashSet};

pub fn get_bitness(binary: &[u8]) -> Result<u32> {
    let elffile = match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => elf,
        _ => return Err(Error::UnsupportedFormatError),
    };
    let machine_type = elffile.header.e_machine;
    if machine_type == goblin::elf::header::EM_X86_64 {
        return Ok(64);
    } else if machine_type == goblin::elf::header::EM_386
        || machine_type == goblin::elf::header::EM_ARM
    {
        return Ok(32);
    }
    Err(Error::UnsupportedPEBitnessIDError(11))
}

pub fn get_base_address(binary: &[u8]) -> Result<u64> {
    match goblin::Object::parse(binary)? {
        goblin::Object::Elf(elf) => {
            let mut base = elf
                .program_headers
                .iter()
                .filter(|ph| ph.p_type == PT_LOAD)
                .map(|ph| ph.p_vaddr.saturating_sub(ph.p_offset))
                .min()
                .unwrap_or(0);

            if base == 0
                && let Some(min_vaddr) = elf
                    .program_headers
                    .iter()
                    .filter(|ph| ph.p_type == PT_LOAD && ph.p_vaddr != 0)
                    .map(|ph| ph.p_vaddr)
                    .min()
            {
                base = min_vaddr;
            }

            Ok(base)
        }
        _ => Err(Error::UnsupportedFormatError),
    }
}

pub fn get_code_areas(_binary: &[u8], pe: &goblin::elf::Elf) -> Result<Vec<(u64, u64)>> {
    let mut res = vec![];
    for section in &pe.section_headers {
        if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
            let section_start = section.sh_addr;
            let mut section_size = section.sh_size;

            // ELF spec: sh_addralign of 0 or 1 means no alignment constraint.
            // A malformed binary with sh_addralign = 0 would otherwise panic
            // on the `%` below.
            if section.sh_addralign > 1 && !section_size.is_multiple_of(section.sh_addralign) {
                let pad = section.sh_addralign - (section_size % section.sh_addralign);
                section_size = match section_size.checked_add(pad) {
                    Some(s) => s,
                    None => continue, // overflowing alignment — skip section
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

fn align(v: &u64, alignment: &u64) -> u64 {
    let remainder = v % alignment;
    if remainder == 0 {
        return *v;
    }
    v + (alignment - remainder)
}

/// Hard cap on the declared VA range — prevents an attacker-crafted ELF
/// from making `bytes_at` lookups misbehave on a multi-gigabyte VA span.
/// Matches the PE-side cap in `pe::MAX_MAPPED_BYTES`.
const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;

/// Parse the ELF segment + section tables and return a `Vec<SectionMap>`
/// describing where each loaded segment / section lives in both file and
/// virtual-address space. Zero-copy: this is metadata only, no bytes are
/// copied. Callers (`BinaryInfo`) thread the result through
/// `bytes_at(va, len)` to read on demand.
///
/// Pre-0.4.0 this allocated a contiguous mapped image (`Vec<u8>`) the
/// size of the virtual layout; 0.4.0 replaces that with the section
/// table.
pub fn map_binary(binary: &[u8], base_addr: u64) -> Result<Vec<SectionMap>> {
    let elffile = match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => elf,
        _ => return Err(Error::UnsupportedFormatError),
    };

    let mut max_virtual_address = 0_u64;

    for segment in &elffile.program_headers {
        if segment.p_type == PT_LOAD
            && segment.p_vaddr > 0
            && let Some(end) = segment.p_vaddr.checked_add(segment.p_memsz)
        {
            max_virtual_address = max_virtual_address.max(end);
        }
    }

    if max_virtual_address == 0 {
        for section in &elffile.section_headers {
            if section.sh_addr > 0
                && let Some(end) = section.sh_addr.checked_add(section.sh_size)
            {
                max_virtual_address = max_virtual_address.max(end);
            }
        }
    }

    if max_virtual_address == 0 {
        return Err(Error::UnsupportedFormatError);
    }

    // `max_virtual_address` and `base_addr` are both attacker-controlled —
    // checked_sub catches the case where base_addr was computed from one
    // segment but max_virtual_address landed below it.
    let virtual_size = max_virtual_address
        .checked_sub(base_addr)
        .ok_or(Error::IntegerOverflow(
            "elf::map_binary virtual_size",
            max_virtual_address,
            base_addr,
        ))?;
    if virtual_size == 0 || virtual_size > MAX_MAPPED_BYTES {
        return Err(Error::MalformedInputError(
            "elf::map_binary virtual_size",
            virtual_size,
            MAX_MAPPED_BYTES,
        ));
    }
    let _ = align; // align() still used by other code paths if any; silence unused warning.

    let mut section_maps: Vec<SectionMap> = Vec::new();

    // PT_LOAD segments are the authoritative layout for ELF.
    for segment in &elffile.program_headers {
        if segment.p_type != PT_LOAD || segment.p_vaddr == 0 {
            continue;
        }

        let p_offset_usize = match usize::try_from(segment.p_offset) {
            Ok(v) if v < binary.len() => v,
            _ => continue,
        };

        // p_vaddr < base_addr is possible on crafted ELFs because base_addr
        // is computed across the PT_LOAD set; skip the segment in that case.
        let Some(_rva) = segment.p_vaddr.checked_sub(base_addr) else {
            continue;
        };
        // Clamp file_size to what the file actually contains, so a section
        // declaring more bytes than exist on disk doesn't let `bytes_at`
        // over-read.
        let file_size = segment
            .p_filesz
            .min((binary.len() as u64).saturating_sub(segment.p_offset));
        if file_size == 0 {
            continue;
        }
        let Some(va_end) = segment.p_vaddr.checked_add(segment.p_memsz) else {
            continue;
        };
        let Ok(file_size_us) = usize::try_from(file_size) else {
            continue;
        };
        section_maps.push(SectionMap {
            va_start: segment.p_vaddr,
            va_end,
            file_offset: p_offset_usize,
            file_size: file_size_us,
        });
    }

    // Also include any SHF_ALLOC section whose VA isn't already covered by
    // a PT_LOAD segment. This catches edge cases in stripped binaries where
    // section headers exist but program headers don't fully describe the
    // layout. Sections already inside an existing VA range are skipped.
    for section in &elffile.section_headers {
        if section.sh_addr == 0 || section.sh_addr < base_addr {
            continue;
        }
        let Some(src_end_u64) = section.sh_offset.checked_add(section.sh_size) else {
            continue;
        };
        if src_end_u64 > binary.len() as u64 {
            continue;
        }
        let Some(va_end) = section.sh_addr.checked_add(section.sh_size) else {
            continue;
        };
        // Skip if any existing PT_LOAD-derived section already covers this VA.
        if section_maps
            .iter()
            .any(|s| s.va_start <= section.sh_addr && section.sh_addr < s.va_end)
        {
            continue;
        }
        let (Ok(file_offset), Ok(file_size)) = (
            usize::try_from(section.sh_offset),
            usize::try_from(section.sh_size),
        ) else {
            continue;
        };
        section_maps.push(SectionMap {
            va_start: section.sh_addr,
            va_end,
            file_offset,
            file_size,
        });
    }

    section_maps.sort_by_key(|s| s.va_start);
    Ok(section_maps)
}

/// Extracts ALL symbols (dynamic + static + exported)
pub fn extract_all_symbols(
    binary: &[u8],
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut symbol_map = HashMap::new();

    match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => {
            let dependencies = get_dynamic_dependencies(binary, &elf)?;
            let lib_map = create_library_mapping(&dependencies);

            // 1. Dynamic imported symbols (with precise relocations)
            let dynamic_symbols = extract_dynamic_symbols_with_relocations(&elf, &lib_map)?;
            symbol_map.extend(dynamic_symbols);

            // 2. Static symbols (local functions)
            let static_symbols = extract_static_symbols(&elf)?;
            symbol_map.extend(static_symbols);

            // 3. Exported symbols
            let exported_symbols = extract_exported_symbols(&elf)?;
            symbol_map.extend(exported_symbols);

            // 4. Fallback for unmapped dynamic symbols
            let fallback_symbols =
                extract_elf_dynamic_apis_fallback_internal(&elf, &lib_map, binary)?;
            for (addr, (lib, name)) in fallback_symbols {
                symbol_map.entry(addr).or_insert((lib, name));
            }
        }
        Err(e) => return Err(Error::ParseError(e)),
        _ => return Err(Error::UnsupportedFormatError),
    }

    Ok(symbol_map)
}

/// Extracts only dynamic APIs (for compatibility with original code)
pub fn extract_elf_dynamic_apis(
    binary: &[u8],
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut api_map = HashMap::new();

    match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => {
            let dependencies = get_dynamic_dependencies(binary, &elf)?;
            let lib_map = create_library_mapping(&dependencies);

            // Realocations (more precise)
            let relocation_symbols = extract_dynamic_symbols_with_relocations(&elf, &lib_map)?;
            api_map.extend(relocation_symbols);

            // Fallback for dynamic APIs
            let fallback_symbols =
                extract_elf_dynamic_apis_fallback_internal(&elf, &lib_map, binary)?;
            for (addr, (lib, name)) in fallback_symbols {
                api_map.entry(addr).or_insert((lib, name));
            }
        }
        Err(e) => return Err(Error::ParseError(e)),
        _ => {}
    }

    Ok(api_map)
}

/// Extract only local functions (static symbols without library context)
pub fn extract_local_functions(binary: &[u8]) -> Result<Vec<(u64, String)>> {
    let all_symbols = extract_all_symbols(binary)?;

    let local_functions: Vec<(u64, String)> = all_symbols
        .into_iter()
        .filter_map(|(addr, (lib, name))| {
            if lib.is_none() || lib.as_ref().map(|l| l == "SELF").unwrap_or(false) {
                name.map(|n| (addr, n))
            } else {
                None
            }
        })
        .collect();

    Ok(local_functions)
}

fn extract_dynamic_symbols_with_relocations(
    elf: &goblin::elf::Elf,
    lib_map: &HashMap<&str, String>,
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut symbols = HashMap::new();

    // Obtain the base address from the program headers
    let base_addr = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr.saturating_sub(ph.p_offset))
        .min()
        .unwrap_or(0);

    for reloc in &elf.pltrelocs {
        let sym_idx = reloc.r_sym;

        if let Some(symbol) = elf.dynsyms.get(sym_idx)
            && let Some(symbol_name) = elf.dynstrtab.get_at(symbol.st_name)
            && !symbol_name.is_empty()
        {
            let library = detect_library_from_symbol(symbol_name, lib_map);
            // Apply base address to the relocation offset
            let final_addr = base_addr + reloc.r_offset;
            symbols.insert(final_addr, (library, Some(symbol_name.to_string())));
        }
    }

    for reloc in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
        let sym_idx = reloc.r_sym;

        if let Some(symbol) = elf.dynsyms.get(sym_idx)
            && let Some(symbol_name) = elf.dynstrtab.get_at(symbol.st_name)
            && !symbol_name.is_empty()
        {
            let library = detect_library_from_symbol(symbol_name, lib_map);

            // Apply base address to the relocation offset
            let final_addr = base_addr + reloc.r_offset;
            symbols.insert(final_addr, (library, Some(symbol_name.to_string())));
        }
    }

    Ok(symbols)
}

fn extract_static_symbols(
    elf: &goblin::elf::Elf,
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut symbols = HashMap::new();

    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name)
            && !name.is_empty()
            && sym.st_value != 0
        {
            let symbol_type = sym.st_info & 0xf;
            if symbol_type == 2 {
                // STT_FUNC
                symbols.insert(sym.st_value, (None, Some(name.to_string())));
            }
        }
    }

    Ok(symbols)
}

fn extract_exported_symbols(
    elf: &goblin::elf::Elf,
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut symbols = HashMap::new();

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
            && !name.is_empty()
            && sym.st_value != 0
        {
            let is_exported = sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize;
            if is_exported {
                symbols.insert(
                    sym.st_value,
                    (Some("SELF".to_string()), Some(name.to_string())),
                );
            }
        }
    }

    Ok(symbols)
}

fn extract_elf_dynamic_apis_fallback_internal(
    elf: &goblin::elf::Elf,
    lib_map: &HashMap<&str, String>,
    binary: &[u8],
) -> Result<HashMap<u64, (Option<String>, Option<String>)>> {
    let mut api_map = HashMap::new();

    let got_section = elf
        .section_headers
        .iter()
        .find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".got.plt"
            } else {
                false
            }
        })
        .or_else(|| {
            elf.section_headers.iter().find(|section| {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    name == ".got"
                } else {
                    false
                }
            })
        });

    let (got_addr, got_offset, got_size) = match got_section {
        Some(section) => (section.sh_addr, section.sh_offset, section.sh_size),
        None => return Ok(api_map),
    };

    let mut imported_symbols = Vec::new();
    let mut seen_symbols = HashSet::new();

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.is_empty() || seen_symbols.contains(name) {
                continue;
            }

            let is_imported = sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize
                && sym.st_value == 0;

            if is_imported {
                let library = detect_library_from_symbol(name, lib_map);
                imported_symbols.push((name.to_string(), library));
                seen_symbols.insert(name);
            }
        }
    }

    let entry_size = if elf.is_64 { 8 } else { 4 };
    let first_api_offset =
        if got_section.and_then(|s| elf.shdr_strtab.get_at(s.sh_name)) == Some(".got.plt") {
            3 * entry_size
        } else {
            0
        };

    let Some(got_limit) = got_addr.checked_add(got_size) else {
        return Ok(api_map);
    };
    for (i, (api_name, library)) in imported_symbols.iter().enumerate() {
        let Some(i_offset) = (i as u64).checked_mul(entry_size) else {
            break;
        };
        let Some(rel_offset) = first_api_offset.checked_add(i_offset) else {
            break;
        };
        let Some(got_entry_addr) = got_addr.checked_add(rel_offset) else {
            break;
        };
        if got_entry_addr >= got_limit {
            break;
        }

        let Some(got_file_offset) = got_offset.checked_add(rel_offset) else {
            break;
        };
        let Some(got_file_end) = got_file_offset.checked_add(entry_size) else {
            break;
        };
        let (Ok(fo), Ok(fe)) = (
            usize::try_from(got_file_offset),
            usize::try_from(got_file_end),
        ) else {
            break;
        };

        if let Some(bytes) = binary.get(fo..fe) {
            // chunks-exact guarantees `bytes.len() == entry_size`; defensive
            // unwrap_or never fires.
            let ptr = if elf.is_64 {
                u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as u64
            };

            let is_got_plt =
                got_section.and_then(|s| elf.shdr_strtab.get_at(s.sh_name)) == Some(".got.plt");
            if ptr != 0 || is_got_plt {
                api_map.insert(got_entry_addr, (library.clone(), Some(api_name.clone())));
            }
        }
    }

    Ok(api_map)
}

fn get_dynamic_dependencies(binary: &[u8], elf: &goblin::elf::Elf) -> Result<Vec<String>> {
    let mut dependencies = Vec::new();

    for phdr in &elf.program_headers {
        if phdr.p_type == PT_DYNAMIC {
            // p_offset + p_filesz may overflow on a crafted ELF; skip the
            // segment in that case.
            let Some(end_u64) = phdr.p_offset.checked_add(phdr.p_filesz) else {
                continue;
            };
            if end_u64 > binary.len() as u64 {
                continue;
            }
            let (Ok(start), Ok(end)) = (usize::try_from(phdr.p_offset), usize::try_from(end_u64))
            else {
                continue;
            };

            let Some(dynamic_data) = binary.get(start..end) else {
                continue;
            };
            let entry_size = if elf.is_64 { 16 } else { 8 };

            for chunk in dynamic_data.chunks_exact(entry_size) {
                // chunks_exact guarantees chunk.len() == entry_size, so the
                // try_into() calls below cannot fail; .unwrap_or([0; N])
                // is purely defensive against future refactors.
                let (tag, val) = if elf.is_64 {
                    let tag_b: [u8; 8] = chunk[0..8].try_into().unwrap_or([0; 8]);
                    let val_b: [u8; 8] = chunk[8..16].try_into().unwrap_or([0; 8]);
                    (u64::from_le_bytes(tag_b), u64::from_le_bytes(val_b))
                } else {
                    let tag_b: [u8; 4] = chunk[0..4].try_into().unwrap_or([0; 4]);
                    let val_b: [u8; 4] = chunk[4..8].try_into().unwrap_or([0; 4]);
                    (
                        u32::from_le_bytes(tag_b) as u64,
                        u32::from_le_bytes(val_b) as u64,
                    )
                };

                if tag == 1 {
                    // DT_NEEDED
                    if let Ok(name_offset) = usize::try_from(val)
                        && let Some(lib_name) = elf.dynstrtab.get_at(name_offset)
                    {
                        dependencies.push(lib_name.to_string());
                    }
                }

                if tag == 0 {
                    // DT_NULL
                    break;
                }
            }
            break;
        }
    }

    Ok(dependencies)
}

fn create_library_mapping(dependencies: &[String]) -> HashMap<&str, String> {
    let mut lib_map = HashMap::new();

    for dep in dependencies {
        if dep.contains("libc.so") {
            lib_map.insert("libc", dep.clone());
        } else if dep.contains("libstdc++.so") {
            lib_map.insert("libstdc++", dep.clone());
        } else if dep.contains("libgcc_s.so") {
            lib_map.insert("libgcc_s", dep.clone());
        } else if dep.contains("libpthread.so") {
            lib_map.insert("libpthread", dep.clone());
        } else if dep.contains("libdl.so") {
            lib_map.insert("libdl", dep.clone());
        } else if dep.contains("libm.so") {
            lib_map.insert("libm", dep.clone());
        } else if dep.contains("libssl.so") {
            lib_map.insert("libssl", dep.clone());
        } else if dep.contains("libcrypto.so") {
            lib_map.insert("libcrypto", dep.clone());
        } else if dep.contains("libz.so") {
            lib_map.insert("libz", dep.clone());
        }
    }

    lib_map
}

fn detect_library_from_symbol(
    symbol_name: &str,
    lib_map: &HashMap<&str, String>,
) -> Option<String> {
    let clean_name = symbol_name.split("@@").next().unwrap_or(symbol_name);

    // 1. PATTERN KNOWN LIBRARIES
    let library_patterns = [
        ("_Z", "libstdc++"),
        ("socket", "libc"),
        ("connect", "libc"),
        ("bind", "libc"),
        ("open", "libc"),
        ("read", "libc"),
        ("write", "libc"),
        ("fork", "libc"),
        ("exec", "libc"),
        ("wait", "libc"),
        ("pthread_", "libpthread"),
        ("crypto_", "libcrypto"),
        ("ssl_", "libssl"),
    ];

    for (pattern, lib) in library_patterns {
        if clean_name.contains(pattern) {
            return lib_map.get(lib).cloned();
        }
    }

    // 2. FUNCTIONS KNOWN TO BE IN LIBRARIES
    let libc_functions = [
        "printf", "scanf", "malloc", "free", "memcpy", "strcpy", "strlen", "fopen", "fclose",
        "fread", "fwrite", "exit", "abort", "sprintf", "strcmp", "strcat", "memset", "calloc",
        "realloc", "puts", "gets", "atoi", "atof", "strtol", "rand", "srand", "time", "system",
        "getpid", "getppid", "getuid", "getgid", "geteuid", "getegid",
    ];

    let pthread_functions = [
        "pthread_create",
        "pthread_join",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_cond_wait",
        "pthread_cond_signal",
        "pthread_detach",
        "pthread_exit",
        "pthread_self",
    ];

    let libdl_functions = ["dlopen", "dlsym", "dlclose", "dlerror"];
    let libm_functions = [
        "sin", "cos", "tan", "log", "exp", "sqrt", "pow", "floor", "ceil",
    ];
    let ssl_functions = [
        "SSL_new",
        "SSL_connect",
        "SSL_read",
        "SSL_write",
        "SSL_free",
    ];
    let crypto_functions = ["EVP_encrypt", "EVP_decrypt", "MD5", "SHA1", "AES_encrypt"];
    let z_functions = ["deflate", "inflate", "compress", "uncompress", "gzip"];

    if libc_functions.contains(&clean_name) {
        return lib_map.get("libc").cloned();
    } else if pthread_functions.contains(&clean_name) {
        return lib_map.get("libpthread").cloned();
    } else if libdl_functions.contains(&clean_name) {
        return lib_map.get("libdl").cloned();
    } else if libm_functions.contains(&clean_name) {
        return lib_map.get("libm").cloned();
    } else if ssl_functions.contains(&clean_name) {
        return lib_map.get("libssl").cloned();
    } else if crypto_functions.contains(&clean_name) {
        return lib_map.get("libcrypto").cloned();
    } else if z_functions.contains(&clean_name) {
        return lib_map.get("libz").cloned();
    }

    // 3. PREFIX BASED DETECTION
    if clean_name.starts_with("pthread_") {
        return lib_map.get("libpthread").cloned();
    } else if clean_name.starts_with("SSL_") || clean_name.starts_with("TLS_") {
        return lib_map.get("libssl").cloned();
    } else if clean_name.starts_with("EVP_") || clean_name.starts_with("AES_") {
        return lib_map.get("libcrypto").cloned();
    } else if clean_name.starts_with("_Z") {
        return lib_map.get("libstdc++").cloned();
    }

    // 4. FALLBACK LOGIC
    // For unknown functions like unknown.Init(), assign to available library
    let non_libc_libs: Vec<_> = lib_map
        .values()
        .filter(|lib| !lib.contains("libc.so"))
        .collect();

    if !non_libc_libs.is_empty() {
        // hashing to avoid collisions
        let hash = clean_name
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        let lib_index = (hash as usize) % non_libc_libs.len();
        return Some(non_libc_libs[lib_index].clone());
    }

    // some libraries may not be detected
    if !lib_map.is_empty() {
        let all_libs: Vec<_> = lib_map.values().collect();
        let hash = clean_name
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        let lib_index = (hash as usize) % all_libs.len();
        return Some(all_libs[lib_index].clone());
    }

    None
}
