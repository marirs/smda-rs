use crate::{BinaryInfo, Result};

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
        if let goblin::Object::Elf(elf) = goblin::Object::parse(&binary_info.raw_data)? {
            self.parse_oep(&elf)?;
//            self.parse_exports(&elf)?;
            self.parse_symbols(&elf.syms, &elf.strtab)?;
            self.parse_symbols(&elf.dynsyms, &elf.strtab)?;
        //     for reloc in elf.dynrelas.iter(){
        //         if reloc.r_sym != 0{
        //             let address = match reloc.r_type{
        //                 _ => reloc.r_offset
        //             };
        //             self.func_symbols.insert(address, elf.strtab.get_at(elf.dynsyms.to_vec()[reloc.r_sym].st_name).unwrap_or("").to_string());
        //         }
        //     }
        //     // for reloc in elf.dynrels.iter(){
        //     //     if reloc.r_sym != 0{
        //     //         let address = match reloc.r_type{
        //     //             _ => reloc.r_offset
        //     //         };
        //     //         self.func_symbols.insert(address, elf.strtab.get_at(elf.dynsyms.to_vec()[reloc.r_sym].st_name).unwrap_or("").to_string());
        //     //    }
        //     // }
        //     for reloc in elf.pltrelocs.iter(){
        //         if reloc.r_sym != 0{
        //             eprintln!("{}", reloc.r_type);
        //             let address = match reloc.r_type{
        //                 _ => reloc.r_offset
        //             };
        //             self.func_symbols.insert(address, elf.strtab.get_at(elf.dynsyms.to_vec()[reloc.r_sym].st_name).unwrap_or("").to_string());
        //         }
        //     }
        }
        // eprintln!("{:#02x?}", self.func_symbols);
            // eprintln!("{}", self.func_symbols.len());
        Ok(())
    }

    fn parse_oep(&mut self, elf: &goblin::elf::Elf) -> Result<()>{
        self.func_symbols.insert(elf.header.e_entry, "original_entry_point".to_string());
        Ok(())
    }

//    fn parse_exports(&mut self, elf: &goblin::elf::Elf) -> Result<()>{
//        for function in elf.exported_functions{
//            self.func_symbols.insert(function.address, function.name);
//        }
//        Ok(())
//    }

    fn parse_symbols(&mut self, symbols: &goblin::elf::sym::Symtab, strtab: &goblin::strtab::Strtab) -> Result<()>{
        for symbol in symbols{
            if symbol.is_function(){
                if symbol.st_value != 0{
                    let func_name = strtab.get_at(symbol.st_name).unwrap_or("");
                    self.func_symbols.insert(symbol.st_value, func_name.to_string());
                }
            }
        }
        Ok(())
    }

    pub fn get_functions_symbols(&self) -> Result<&std::collections::HashMap<u64, String>> {
        Ok(&self.func_symbols)
    }
}
