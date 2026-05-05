use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn rerun_dir_files(dir: &Path, depth: u8) {
    if depth == 0 || !dir.is_dir() {
        return;
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            println!("cargo:rerun-if-changed={}", p.display());
            if p.is_dir() {
                rerun_dir_files(&p, depth - 1);
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=capabilities/default.json");
    println!("cargo:rerun-if-changed=entitlements/macos/production.entitlements.plist");
    println!("cargo:rerun-if-changed=Info.plist");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ext_dir = manifest_dir.join("resources/sqlite_extensions");
    if ext_dir.is_dir() {
        println!("cargo:rustc-env=CTI_SQLITE_EXTENSIONS_BUNDLE_SUBDIR=sqlite_extensions");
        rerun_dir_files(&ext_dir, 6);
    } else {
        println!("cargo:warning=resources/sqlite_extensions missing — create it to ship loadable SQLite extensions.");
    }

    let scripts = manifest_dir.join("resources/scripts");
    if scripts.is_dir() {
        // Tauri CLI watches this via additionalWatchFolders.
        // Do not emit cargo:rerun-if-changed for every file here, as large datasets (e.g. CVE JSON)
        // will cause Cargo to hang or crash with hundreds of thousands of lines.
        println!("cargo:rerun-if-changed=resources/scripts");
    }

    tauri_build::build();
}
