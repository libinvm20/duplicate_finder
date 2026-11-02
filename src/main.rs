use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about = "Find duplicate files by size and content hash")]
struct Args {
    /// Directory to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Minimum file size in bytes to consider (default: 1)
    #[arg(long, default_value_t = 1)]
    min_size: u64,

    /// Extensions to ignore (comma-separated, e.g. tmp,log)
    #[arg(long, value_delimiter = ',')]
    ignore_ext: Vec<String>,

    /// Actually delete duplicates (keeps one copy per group). Default is dry-run.
    #[arg(long)]
    delete: bool,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    output: String,
}

#[derive(Debug, Clone, Serialize)]
struct FileEntry {
    path: PathBuf,
    size: u64,
}

#[derive(Debug, Serialize)]
struct DuplicateGroup {
    /// First 16 hex chars of SHA-256 for display
    hash_short: String,
    /// Full SHA-256 hash
    hash: String,
    size: u64,
    files: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", args.path.display());
    }

    let ignore_exts: Vec<String> = args
        .ignore_ext
        .iter()
        .map(|e| e.trim().to_lowercase())
        .collect();

    println!("Scanning: {}", args.path.display());
    println!("Min size: {} bytes", args.min_size);
    if !ignore_exts.is_empty() {
        println!("Ignoring extensions: {:?}", ignore_exts);
    }

    // Phase 1: collect all files, group by size
    let files = collect_files(&args.path, args.min_size, &ignore_exts)?;
    println!("Indexed {} files", files.len());

    let mut size_groups: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for f in &files {
        size_groups.entry(f.size).or_default().push(f.path.clone());
    }

    // Only sizes with more than one file can be duplicates
    let candidate_groups: Vec<(u64, Vec<PathBuf>)> = size_groups
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();

    println!(
        "{} file sizes have potential duplicates",
        candidate_groups.len()
    );

    if candidate_groups.is_empty() {
        println!("No duplicates found.");
        return Ok(());
    }

    // Phase 2: hash candidate files in parallel
    let all_candidates: Vec<PathBuf> = candidate_groups
        .iter()
        .flat_map(|(_, paths)| paths.iter().cloned())
        .collect();

    let pb = ProgressBar::new(all_candidates.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files hashed ({msg})")
            .unwrap()
    );

    let hashed: Vec<(PathBuf, String, u64)> = all_candidates
        .par_iter()
        .map(|path| {
            let size = path
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0);
            let hash = hash_file(path).unwrap_or_default();
            pb.inc(1);
            pb.set_message(path.file_name().unwrap_or_default().to_string_lossy().to_string());
            (path.clone(), hash, size)
        })
        .collect();

    pb.finish_and_clear();

    // Phase 3: regroup by (size, full hash), keep only true duplicates
    let mut hash_groups: HashMap<(u64, String), Vec<PathBuf>> = HashMap::new();
    for (path, hash, size) in hashed {
        if hash.is_empty() {
            continue; // skip files that couldn't be read
        }
        hash_groups.entry((size, hash)).or_default().push(path);
    }

    let mut duplicate_groups: Vec<DuplicateGroup> = hash_groups
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|((size, hash), files)| {
            let mut files = files;
            files.sort();
            DuplicateGroup {
                hash_short: hash[..16.min(hash.len())].to_string(),
                hash,
                size,
                files,
            }
        })
        .collect();

    // Sort groups by size descending so biggest space-savers appear first
    duplicate_groups.sort_by(|a, b| b.size.cmp(&a.size));

    let total_dup_files: usize = duplicate_groups.iter().map(|g| g.files.len()).sum();
    let total_wasted: u64 = duplicate_groups.iter().map(|g| g.size * (g.files.len() as u64 - 1)).sum();

    println!("\nFound {} duplicate groups ({} files)", duplicate_groups.len(), total_dup_files);
    println!("Estimated space wasted by duplicates: {} bytes ({} MB)", total_wasted, total_wasted / 1_048_576);

    // Phase 4: report
    match args.output.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&duplicate_groups)?;
            println!("{}", json);
        }
        _ => {
            for group in &duplicate_groups {
                println!(
                    "\n=== Duplicate group: {} bytes, hash {}... ===",
                    group.size, group.hash_short
                );
                for f in &group.files {
                    println!("  {}", f.display());
                }
            }
        }
    }

    // Phase 5: optional deletion
    if args.delete {
        let mut deleted = 0u64;
        let mut freed = 0u64;
        for group in &duplicate_groups {
            // Keep the first file, delete the rest
            for f in &group.files[1..] {
                match fs::remove_file(f) {
                    Ok(()) => {
                        deleted += 1;
                        freed += group.size;
                    }
                    Err(e) => eprintln!("Failed to delete {}: {}", f.display(), e),
                }
            }
        }
        println!(
            "\nDeleted {} files, freed {} bytes ({} MB)",
            deleted,
            freed,
            freed / 1_048_576
        );
    } else {
        println!("\nDry-run complete. Pass --delete to remove duplicates (keeps one copy per group).");
    }

    Ok(())
}

/// Walk a directory and collect file paths + sizes.
fn collect_files(root: &Path, min_size: u64, ignore_exts: &[String]) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            // Skip symlinks to avoid processing the same file twice
            !e.file_type().is_symlink()
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ignore_exts.iter().any(|e| e == ext.as_ref()) {
            continue;
        }

        match path.metadata() {
            Ok(metadata) => {
                if metadata.len() >= min_size {
                    files.push(FileEntry {
                        path: path.to_path_buf(),
                        size: metadata.len(),
                    });
                }
            }
            Err(e) => {
                eprintln!("Skipping {} (metadata error): {}", path.display(), e);
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Compute SHA-256 hash of a file.
fn hash_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
