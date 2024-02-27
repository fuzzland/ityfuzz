use std::{
    error::Error,
    fs::{self, File},
    io::prelude::*,
    path::Path,
};

use crate::utils;

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
        let path = if key.len() < 5 {
            format!("{}/{}", self.file_path, key)
        } else {
            format!("{}/{}/{}/{}", self.file_path, &key[0..2], &key[2..4], &key[4..])
        };

        let path_obj = Path::new(&path);
        if let Some(parent) = path_obj.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(utils::try_write_file(path, value, false)?)
    }

    fn load(&self, key: &str) -> Result<String, Box<dyn Error>> {
        let path = if key.len() < 5 {
            format!("{}/{}", self.file_path, key)
        } else {
            format!("{}/{}/{}/{}", self.file_path, &key[0..2], &key[2..4], &key[4..])
        };

        if !Path::new(&path).exists() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key not found",
            )));
        }

        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
}
