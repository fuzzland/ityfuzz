use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub trait Cache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>>;
    fn load(&self, key: &str) -> Result<String, Box<dyn Error>>;
}

#[derive(Clone, Debug, Default)]
pub struct FileSystemCache {
    file_path: String,
}

impl FileSystemCache {
    pub fn new(file_path: &str) -> FileSystemCache {
        let path = Path::new(file_path);
        if !path.exists() {
            fs::create_dir_all(path).unwrap();
        }

        FileSystemCache {
            file_path: file_path.to_string(),
        }
    }
}

impl Cache for FileSystemCache {
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn Error>> {
        // write `value` to file `key`, create a new file if it doesn't exist
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.file_path.clone() + "/" + key)?;
        file.write_all(value.as_bytes())?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<String, Box<dyn Error>> {
        if !Path::exists(Path::new((self.file_path.clone() + "/" + key).as_str())) {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key not found",
            )));
        }

        let mut file = File::open(self.file_path.clone() + "/" + key)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
}
