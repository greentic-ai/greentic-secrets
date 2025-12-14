use std::path::{Path, PathBuf};

pub fn user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("greentic").join("config.toml"))
}

pub fn default_project_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn project_config_path(root: &Path) -> PathBuf {
    root.join(".greentic").join("config.toml")
}

pub fn absolutize(path: PathBuf, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}
