//! Compare all privileged Mac payload files, without relying on a version constant.
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

fn same_file_bytes(a: &Path, b: &Path) -> io::Result<bool> {
    let a = File::open(a)?;
    let b = File::open(b)?;
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let mut a = BufReader::new(a);
    let mut b = BufReader::new(b);
    let mut left = [0u8; 64 * 1024];
    let mut right = [0u8; 64 * 1024];
    loop {
        let count = a.read(&mut left)?;
        if count == 0 {
            return Ok(true);
        }
        b.read_exact(&mut right[..count])?;
        if left[..count] != right[..count] {
            return Ok(false);
        }
    }
}

pub fn matches(bundled: &Path, installed: &Path) -> bool {
    ["offveil-core", "sing-box", "ciadpi"]
        .iter()
        .all(|name| same_file_bytes(&bundled.join(name), &installed.join(name)).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_missing_and_changed_sidecars_even_when_core_version_is_unchanged() {
        let root = std::env::temp_dir().join(format!("offveil-payload-{}", uuid::Uuid::new_v4()));
        let bundled = root.join("bundle");
        let installed = root.join("installed");
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&installed).unwrap();
        for name in ["offveil-core", "sing-box", "ciadpi"] {
            std::fs::write(bundled.join(name), b"current").unwrap();
            std::fs::write(installed.join(name), b"current").unwrap();
        }
        assert!(matches(&bundled, &installed));
        std::fs::write(installed.join("ciadpi"), b"oldcode").unwrap();
        assert!(!matches(&bundled, &installed));
        std::fs::write(installed.join("ciadpi"), b"current").unwrap();
        std::fs::remove_file(installed.join("sing-box")).unwrap();
        assert!(!matches(&bundled, &installed));
        std::fs::remove_dir_all(root).unwrap();
    }
}
