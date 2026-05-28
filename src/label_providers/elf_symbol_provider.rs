use crate::{BinaryInfo, Result, demangle};

#[derive(Debug)]
pub struct ElfSymbolProvider {
    func_symbols: std::collections::HashMap<u64, String>,
}

impl ElfSymbolProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            func_symbols: std::collections::HashMap::new(),
        })
    }

    pub fn update(&mut self, binary_info: &BinaryInfo) -> Result<()> {
        // Symbol sources handled here: the ELF entry point (so the OEP
        // gets a friendly label) and any symbols in `.symtab` /
        // `.dynsym` whose type is `STT_FUNC`. Imported-API resolution
        // (PLT / GOT slot → symbol-name via `.rela.plt` / `.rela.dyn`)
        // is handled separately by `elf::extract_elf_dynamic_apis`,
        // which feeds `Disassembler::addr_to_api`. Don't duplicate
        // that here — keeps the two concerns (local function names
        // vs. imported APIs) cleanly separated.
        if let goblin::Object::Elf(elf) = goblin::Object::parse(binary_info.raw_data)? {
            self.parse_oep(&elf)?;
            self.parse_symbols(&elf.syms, &elf.strtab)?;
            self.parse_symbols(&elf.dynsyms, &elf.strtab)?;
        }
        Ok(())
    }

    fn parse_oep(&mut self, elf: &goblin::elf::Elf) -> Result<()> {
        self.func_symbols
            .insert(elf.header.e_entry, "original_entry_point".to_string());
        Ok(())
    }

    fn parse_symbols(
        &mut self,
        symbols: &goblin::elf::sym::Symtab,
        strtab: &goblin::strtab::Strtab,
    ) -> Result<()> {
        for symbol in symbols {
            if symbol.is_function() && symbol.st_value != 0 {
                let raw = strtab.get_at(symbol.st_name).unwrap_or("");
                // 0.4.2 (N3): demangle Rust-mangled symbols in place. Non-Rust
                // names pass through unchanged.
                let func_name = demangle::maybe_demangle(raw);
                self.func_symbols.insert(symbol.st_value, func_name);
            }
        }
        Ok(())
    }

    pub fn get_functions_symbols(&self) -> Result<&std::collections::HashMap<u64, String>> {
        Ok(&self.func_symbols)
    }
}
