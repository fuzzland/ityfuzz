use std::{fs, io::Write, path::Path};

pub fn try_write_file(path: impl AsRef<Path>, data: &str, append: bool) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    let mut retry = 3;
    while retry > 0 {
        retry -= 1;

        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(path)
        {
            Ok(mut file) => match file.write_all(data.as_bytes()) {
                Ok(_) => {
                    let _ = file.flush();
                    return Ok(());
                }
                Err(e) => {
                    if retry <= 0 {
                        return Err(format!("Failed to write to file: {}", e));
                    }
                }
            },
            Err(e) => {
                if retry <= 0 {
                    return Err(format!("Failed to create or open file: {}", e));
                }
            }
        }
    }

    Ok(())
}
