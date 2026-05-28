use crate::{Result, label_provider::LabelProvider};

pub mod elf_symbol_provider;
pub mod win_api_resolver;

pub fn init() -> Result<Vec<LabelProvider>> {
    Ok(vec![
        LabelProvider::WinApi(win_api_resolver::WinApiResolver::new()?),
        LabelProvider::ElfSymbol(elf_symbol_provider::ElfSymbolProvider::new()?),
    ])
}

#[derive(Debug, Clone)]
pub struct ApiEntry {
    pub referencing_addr: std::collections::HashSet<u64>,
    pub dll_name: Option<String>,
    pub api_name: Option<String>,
}
