use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;

pub trait Cache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>>;
    fn load(&self, key: &str) -> Result<String, Box<dyn Error>>;
}

#[derive(Clone, Debug)]
pub struct FileSystemCache {
    file_path: String,
}

impl FileSystemCache {
    pub fn new(file_path: &str) -> FileSystemCache {
        let path = Path::new(file_path);
        if !path.exists() {
            let dir = path.parent().unwrap();
            if !dir.exists() {
                fs::create_dir_all(dir).expect("Failed to create directory");
            }

            fs::File::create(&path).expect("Failed to create file");
        }

        FileSystemCache {
            file_path: file_path.to_string(),
        }
    }
}

impl Cache for FileSystemCache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut json_data: HashMap<String, String> = match serde_json::from_str(&contents) {
            Ok(data) => data,
            Err(_) => HashMap::new(),
        };

        json_data.insert(key.to_string(), value.to_string());
        let serialized_data = serde_json::to_string(&json_data)?;
        fs::write(&self.file_path, serialized_data)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<String, Box<dyn Error>> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let json_data: HashMap<String, String> = serde_json::from_str(&contents)?;
        match json_data.get(key) {
            Some(value) => Ok(value.clone()),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key not found",
            ))),
        }
    }
}
