use crate::{
    BinaryInfo, Result,
    error::Error,
    label_providers::{elf_symbol_provider::ElfSymbolProvider, win_api_resolver::WinApiResolver},
};

#[derive(Debug)]
pub enum LabelProvider {
    WinApi(WinApiResolver),
    ElfSymbol(ElfSymbolProvider),
}

impl LabelProvider {
    pub fn get_api(
        &self,
        to_addr: u64,
        absolute_addr: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        match self {
            LabelProvider::WinApi(w) => w.get_api(to_addr, absolute_addr),
            _ => Err(Error::InvalidRule(line!(), file!().to_string())),
        }
    }

    pub fn is_api_provider(&self) -> Result<bool> {
        match self {
            LabelProvider::WinApi(_) => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn is_symbol_provider(&self) -> Result<bool> {
        match self {
            LabelProvider::ElfSymbol(_) => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn get_functions_symbols(&self) -> Result<&std::collections::HashMap<u64, String>> {
        match self {
            LabelProvider::ElfSymbol(s) => s.get_functions_symbols(),
            _ => Err(Error::InvalidRule(line!(), file!().to_string())),
        }
    }

    pub fn get_symbol(&self, _address: u64) -> Result<String> {
        Err(Error::NotImplementedError)
    }

    pub fn update(&mut self, bin: &BinaryInfo) -> Result<()> {
        match self {
            LabelProvider::WinApi(w) => w.update(bin),
            LabelProvider::ElfSymbol(w) => w.update(bin),
        }
    }
}
