pub mod parser;

use crate::evm::EVMAddress;
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SOURCE_MAP_PROVIDER: SourceMapProvider = SourceMapProvider::default();
}

// Identical to SourceMapLocation
#[derive(Default, Clone, Debug)]
struct RawSourceMapInfo {
    file: Option<String>,
    file_idx: Option<usize>,
    offset: usize,
    length: usize,
}

#[derive(Debug)]
struct SourceMapItem {
    raw_info: RawSourceMapInfo,
    source_code: Option<String>,  // file_content[offset..offset + length]
}

#[derive(Debug)]
struct SourceMap {
    items: HashMap<usize, SourceMapItem>,  // pc -> SourceMapItem
}

#[derive(Debug, Default)]
pub struct SourceMapProvider {
    source_maps: HashMap<EVMAddress, SourceMap>,  // address -> SourceMap
}

impl SourceMapProvider {
    pub fn decode_instructions(&mut self, address: EVMAddress, bytecode: Vec<u8>, map: String, files: &Vec<String>, replacements: Option<&Vec<(String, String)>>) {
        let list_raw_infos = self.uncompress_srcmap_single(map, files, replacements);
        let bytecode_len = bytecode.len();

        let mut result = SourceMap::new();
        let mut pc = 0;
        let mut raw_info_idx = 0;

        loop {
            if pc >= bytecode_len {
                break;
            }

            let opcode = bytecode[pc];
            let raw_info = list_raw_infos.get(raw_info_idx);

            if let Some(info) = raw_info { 
                let source_map_item = SourceMapItem::new(info.clone(), None);
                result.insert_source_map_item(pc, source_map_item)
            }

            match opcode {
                // PUSH1..PUSH32
                0x60..=0x7f => {
                    pc += opcode as usize - 0x5e;
                }
                _ => {
                    pc += 1;
                }
            }

            raw_info_idx += 1;
        }

        self.source_maps.insert(address, result);
    }

    pub fn has_source_map(&self, address: EVMAddress) -> bool {
        self.source_maps.contains_key(&address)
    }

    pub fn get_source_code(&self, address: EVMAddress, pc: usize) -> Option<&String> {
        if self.has_source_map(address) {
            self.source_maps.get(&address).unwrap().get_source_map_item_by_pc(pc).unwrap().get_source_code()
        } else {
            None
        }
    }

    fn uncompress_srcmap_single(
        &self,
        map: String,
        files: &Vec<String>,
        replacements: Option<&Vec<(String, String)>>,
    ) -> Vec<RawSourceMapInfo> {
        let empty_replacement = vec![];
        let replacements = match replacements {
            Some(replacements) => replacements,
            None => &empty_replacement,
        };

        let mut results : Vec<RawSourceMapInfo> = vec![];
        let replacement_map = replacements
        .iter()
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect::<HashMap<String, String>>();

        for (counter, part) in map.split(';').enumerate() {
            let parts = part.split(':').collect::<Vec<&str>>();
            let parts_len = parts.len();
    
            let has_offset = parts_len > 0 && !parts[0].is_empty();
            let has_length = parts_len > 1 && !parts[1].is_empty();
            let has_file = parts_len > 2 && !parts[2].is_empty();
            let has_jump = parts_len > 3 && !parts[3].is_empty();
    
            let has_everything = has_offset && has_length && has_file && has_jump;
    
            if counter == 0 && !has_everything {
                results.push(RawSourceMapInfo::default());
            } else {
                let mut file_idx = if has_file {
                    let idx = parts[2].parse::<usize>().unwrap_or(usize::MAX);
                    if idx < files.len() {
                        Some(idx)
                    } else {
                        None
                    }
                } else {
                    results[counter - 1].file_idx
                };
                let mut file = if has_file {
                    let idx = parts[2].parse::<usize>().unwrap_or(usize::MAX);
                    if idx < files.len() {
                        Some(files[idx].clone())
                    } else {
                        None
                    }
                } else {
                    results[counter - 1].file.clone()
                };

                let mut offset = if has_offset && let Ok(res) = parts[0].parse::<usize>() {
                    res
                } else {
                    results[counter - 1].offset
                };

                let mut length = if has_length && let Ok(res) = parts[1].parse::<usize>() {
                    res
                } else {
                    results[counter - 1].length
                };

                if let Some(fidx) = file_idx {
                    if let Some(replacement) =
                        replacement_map.get(&format!("{}:{}:{}", offset, length, fidx))
                    {
                        let parts = replacement.split(':').collect::<Vec<&str>>();
                        if parts.len() == 3 {
                            file_idx = Some(parts[0].parse::<usize>().unwrap_or(usize::MAX));
                            if let Some(idx) = file_idx && idx < files.len() {
                                file = Some(files[idx].clone());
                            } else {
                                file = None;
                            }
                            offset = parts[1].parse::<usize>().unwrap_or(usize::MAX);
                            length = parts[2].parse::<usize>().unwrap_or(usize::MAX);
                        }
                    }
                }

                results.push(RawSourceMapInfo::new(file, file_idx, offset, length));
            }
        }
        results
    }
}

impl SourceMap {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }

    pub fn get_source_map_item_by_pc(&self, pc: usize) -> Option<&SourceMapItem> {
        self.items.get(&pc)
    }

    pub fn insert_source_map_item(&mut self, pc: usize, source_map_item: SourceMapItem) {
        self.items.insert(pc, source_map_item);
    }
}

impl SourceMapItem {
    pub fn new(raw_info: RawSourceMapInfo, source_code: Option<String>) -> Self {
        Self {
            raw_info,
            source_code,
        }
    }

    pub fn _set_source_code(&mut self, source_code: String) {
        self.source_code = Some(source_code);
    }

    pub fn get_source_code(&self) -> Option<&String> {
        self.source_code.as_ref()
    }

    pub fn _set_source_code_from_file(&mut self, filename: String) {
        let file_content = std::fs::read_to_string(filename).unwrap();

        // Source code is file_source_code[raw_info.offset..raw_info.offset + raw_info.length]
        let source_code = file_content[self.raw_info.offset..self.raw_info.offset + self.raw_info.length].to_string();
        self.source_code = Some(source_code);
    }
}

impl RawSourceMapInfo {
    pub fn new(file: Option<String>, file_idx: Option<usize>, offset: usize, length: usize) -> Self {
        Self {
            file,
            file_idx,
            offset,
            length,
        }
    }
}