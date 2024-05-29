use std::{collections::HashMap, sync::Mutex};

use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::evm::EVMAddress;

lazy_static! {
    pub static ref SOURCE_MAP_PROVIDER: Mutex<SourceMapProvider> = Mutex::new(SourceMapProvider::default());
    pub static ref MULTILINE_REGEX: Regex = Regex::new(r"^(library|contract|function)(.|\n)*\}$").unwrap();
}

pub enum SourceCodeResult {
    SourceCode(String),          // Normal source code
    SourceCodeNoPcMatch(String), // e.g. Multiline source code
    NoSourceCode,                // No source code for pc
    NoSourceMap,                 // No source map for address
}

// Identical to SourceMapLocation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RawSourceMapInfo {
    file: Option<String>,    // File name
    file_idx: Option<usize>, // File index in files
    offset: usize,
    length: usize,
}

#[derive(Debug)]
struct SourceMapItem {
    raw_info: RawSourceMapInfo,
    source_code: Option<String>, // file_content[offset..offset + length]
    pc_has_match: bool,          // false when 1. source_code is None 2. source_code is multiline
}

#[derive(Debug)]
struct SourceMap {
    items: HashMap<usize, SourceMapItem>, // pc -> SourceMapItem
}

#[derive(Debug, Default)]
pub struct SourceMapProvider {
    source_maps: HashMap<EVMAddress, SourceMap>, /* address -> SourceMap
                                                  * saved_filenames: HashSet<String>, */
    source_code: HashMap<EVMAddress, Vec<(String, String)>>, // filename -> file_content
}

impl SourceMapProvider {
    pub fn decode_instructions_for_address(
        &mut self,
        address: &EVMAddress,
        bytecode: Vec<u8>,
        map: String,
        files: &[(String, String)], // (filename, file_content)
        replacements: Option<&Vec<(String, String)>>,
    ) {
        debug!("adding source map for address: {}", address);
        self.source_code.insert(*address, files.iter().cloned().collect_vec());

        let filenames = files.iter().map(|(name, _)| (name.clone())).collect();
        let list_raw_infos = self.uncompress_srcmap_single(map, &filenames, replacements);
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
                // println!("info file is {:?} file index is {:?}", info.file, info.file_idx);
                let source_code = if let Some(file_idx) = info.file_idx {
                    let file_content = files[file_idx].1.clone();
                    // println!("file_content length is : {:?}", file_content.len());
                    // println!("file_content offset is : {:?}", info.offset);
                    Some(file_content[info.offset..info.offset + info.length].to_string())
                } else {
                    None
                };

                let source_map_item = SourceMapItem::new(info.clone(), source_code);
                result.insert_source_map_item(pc, source_map_item);
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

        self.source_maps.insert(*address, result);
    }

    pub fn has_source_map(&self, address: &EVMAddress) -> bool {
        self.source_maps.contains_key(address)
    }

    pub fn get_source_code(&self, address: &EVMAddress, pc: usize) -> SourceCodeResult {
        if self.has_source_map(address) {
            match self.source_maps.get(address).unwrap().get_source_map_item_by_pc(pc) {
                Some(source_map_item) => {
                    match source_map_item.source_code.as_ref() {
                        Some(source_code) => {
                            if source_map_item.pc_has_match {
                                // Normal source code
                                SourceCodeResult::SourceCode(source_code.clone())
                            } else {
                                // e.g. Multiline source code "library L { ... }"
                                SourceCodeResult::SourceCodeNoPcMatch(source_code.clone())
                            }
                        }
                        None => {
                            SourceCodeResult::NoSourceCode // No source code for
                                                           // pc.
                        }
                    }
                }
                None => SourceCodeResult::NoSourceCode, /* No source code for pc.
                                                         * usually occurs in the unavailable opcode before metadata */
            }
        } else {
            SourceCodeResult::NoSourceMap // No source map
        }
    }

    // This function should only be called for output use (e.g. blaz json output)
    // If you want to get source code/pc_has_match, please use get_source_code
    pub fn get_raw_source_map_info(&self, address: &EVMAddress, pc: usize) -> Option<RawSourceMapInfo> {
        if self.has_source_map(address) {
            self.source_maps
                .get(address)
                .unwrap()
                .get_source_map_item_by_pc(pc)
                .map(|source_map_item| source_map_item.raw_info.clone())
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

        let mut results: Vec<RawSourceMapInfo> = vec![];
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
                    if let Some(replacement) = replacement_map.get(&format!("{}:{}:{}", offset, length, fidx)) {
                        let parts = replacement.split(':').collect::<Vec<&str>>();
                        if parts.len() == 3 {
                            file_idx = Some(parts[0].parse::<usize>().unwrap_or(usize::MAX));
                            if let Some(idx) = file_idx &&
                                idx < files.len()
                            {
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

    pub fn all_sources(&self) -> HashMap<EVMAddress, Vec<(String, String)>> {
        self.source_code.clone()
    }
}

impl SourceMap {
    pub fn new() -> Self {
        Self { items: HashMap::new() }
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
        match source_code {
            Some(source_code) => {
                if MULTILINE_REGEX.is_match(&source_code) {
                    Self {
                        raw_info,
                        source_code: Some(source_code),
                        pc_has_match: false,
                    }
                } else {
                    Self {
                        raw_info,
                        source_code: Some(source_code),
                        pc_has_match: true,
                    }
                }
            }
            None => Self {
                raw_info,
                source_code: None,
                pc_has_match: false,
            },
        }
    }

    pub fn _set_source_code(&mut self, source_code: String) {
        self.source_code = Some(source_code);
    }

    pub fn _get_source_code(&self) -> Option<&String> {
        self.source_code.as_ref()
    }

    pub fn _set_source_code_from_file(&mut self, filename: String) {
        let file_content = std::fs::read_to_string(filename).unwrap();

        // Source code is file_source_code[raw_info.offset..raw_info.offset +
        // raw_info.length]
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
