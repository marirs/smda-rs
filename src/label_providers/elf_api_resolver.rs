use crate::{BinaryInfo, Result};
use goblin::Object;

#[derive(Debug)]
pub struct ElfApiResolver {
    is_buffer: bool,
    api_map: std::collections::HashMap<String, std::collections::HashMap<u64, (String, String)>>,
}

impl ElfApiResolver {
    pub fn new() -> Result<ElfApiResolver> {
        let mut war = ElfApiResolver {
            is_buffer: false,
            api_map: std::collections::HashMap::new(),
        };
        war.api_map
            .insert("lief".to_string(), std::collections::HashMap::new());
        Ok(war)
    }

    pub fn update(&mut self, binary_info: &BinaryInfo) -> Result<()> {
        self.is_buffer = binary_info.is_buffer;
        if !self.is_buffer {
            //setup import table info from LIEF
            let mut address = 0x401700;
            if let Object::Elf(elf) = Object::parse(&binary_info.raw_data)? {
                for reloc in elf.pltrelocs.iter() {
                    if reloc.r_sym != 0 {
                        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                            if sym.is_import() && sym.is_function() {
                                self.api_map.get_mut("lief").unwrap().insert(
                                    address,
                                    (
                                        "".to_string(),
                                        elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string(),
                                    ),
                                );
                                address += 0x10;
                            }
                        }
                    }
                }
                //     let mut lib = None;
                //     if relocation.symbol.has_version && relocation.symbol.symbol_version.has_auxiliary_version{
                //         //# like "GLIBC_2.2.5"
                //         lib = Some(relocation.symbol.symbol_version.symbol_version_auxiliary.name);
                //         let name = relocation.symbol.name;
                //         let address = relocation.address;

                //         self._api_map["lief"].insert(address, (lib, name));
                //     }
            }
        }
        Ok(())
    }

    pub fn get_api(
        &self,
        to_addr: u64,
        _absolute_addr: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        if let Some(s) = self.api_map.get("lief") {
            if let Some((dll, api)) = s.get(&to_addr) {
                return Ok((Some(dll.to_string()), Some(api.to_string())));
            }
        }
        Ok((None, None))
    }
}
