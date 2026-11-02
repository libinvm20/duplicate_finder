use eframe::egui;
use rfd::FileDialog;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
struct DuplicateGroup {
    hash_short: String,
    hash: String,
    size: u64,
    files: Vec<PathBuf>,
}

enum ScanMsg {
    Progress(usize, usize, String),
    Done(Vec<DuplicateGroup>),
    Error(String),
}

struct DuplicateFinderApp {
    folder: Option<PathBuf>,
    min_size: u64,
    ignore_exts: String,
    dry_run: bool,

    groups: Vec<DuplicateGroup>,
    selected_groups: HashSet<usize>,
    status: String,
    progress: (usize, usize),
    is_scanning: bool,

    scan_rx: Option<mpsc::Receiver<ScanMsg>>,
}

impl Default for DuplicateFinderApp {
    fn default() -> Self {
        Self {
            folder: None,
            min_size: 1,
            ignore_exts: "tmp,log".to_string(),
            dry_run: true,
            groups: Vec::new(),
            selected_groups: HashSet::new(),
            status: "Ready. Select a folder and click Scan.".to_string(),
            progress: (0, 0),
            is_scanning: false,
            scan_rx: None,
        }
    }
}

impl eframe::App for DuplicateFinderApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for scan results from background thread
        if let Some(rx) = &self.scan_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMsg::Progress(cur, total, msg) => {
                        self.progress = (cur, total);
                        self.status = msg;
                    }
                    ScanMsg::Done(groups) => {
                        self.groups = groups;
                        self.is_scanning = false;
                        let total_files: usize = self.groups.iter().map(|g| g.files.len()).sum();
                        self.status = format!(
                            "Found {} duplicate groups ({} files)",
                            self.groups.len(),
                            total_files
                        );
                        self.scan_rx = None;
                    }
                    ScanMsg::Error(e) => {
                        self.is_scanning = false;
                        self.status = format!("Error: {}", e);
                        self.scan_rx = None;
                    }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Duplicate File Finder");
            ui.separator();

            // ---- Folder selection ----
            ui.horizontal(|ui| {
                if ui.button("📁 Select Folder").clicked() {
                    if let Some(path) = FileDialog::new().pick_folder() {
                        self.folder = Some(path.clone());
                        self.status = format!("Selected: {}", path.display());
                    }
                }
                if let Some(p) = &self.folder {
                    ui.label(p.display().to_string());
                }
            });

            ui.separator();

            // ---- Settings ----
            ui.horizontal(|ui| {
                ui.label("Min size (bytes):");
                ui.add(
                    egui::DragValue::new(&mut self.min_size)
                        .clamp_range(1..=u64::MAX)
                        .speed(1024),
                );
                ui.label("Ignore extensions (comma-separated):");
                ui.text_edit_singleline(&mut self.ignore_exts);
                ui.checkbox(&mut self.dry_run, "Dry run (preview only, no deletion)");
            });

            ui.separator();

            // ---- Scan button ----
            let scan_enabled = self.folder.is_some() && !self.is_scanning;
            if ui.add_enabled(scan_enabled, egui::Button::new("🔍 Scan Duplicates")).clicked() {
                self.start_scan();
            }

            // ---- Progress / status ----
            if self.is_scanning {
                let pct = if self.progress.1 > 0 {
                    self.progress.0 as f32 / self.progress.1 as f32
                } else {
                    0.0
                };
                ui.add(
                    egui::ProgressBar::new(pct)
                        .text(format!("{} / {}", self.progress.0, self.progress.1))
                        .desired_width(ui.available_width()),
                );
                ui.label(&self.status);
            } else {
                ui.label(&self.status);
            }

            ui.separator();

            // ---- Results ----
            if !self.groups.is_empty() {
                ui.label(format!("Duplicate Groups ({})", self.groups.len()));

                let total_wasted: u64 = self
                    .groups
                    .iter()
                    .map(|g| g.size * (g.files.len() as u64 - 1))
                    .sum();
                ui.label(format!(
                    "Estimated space wasted: {} bytes ({} MB)",
                    total_wasted,
                    total_wasted / 1_048_576
                ));

                // Bulk select buttons
                ui.horizontal(|ui| {
                    if ui.button("Select All").clicked() {
                        self.selected_groups = (0..self.groups.len()).collect();
                    }
                    if ui.button("Select None").clicked() {
                        self.selected_groups.clear();
                    }
                    if ui.button("🗑️ Delete Selected").clicked() {
                        self.delete_selected();
                    }
                });

                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, group) in self.groups.iter().enumerate() {
                        egui::CollapsingHeader::new(format!(
                            "Duplicate group {} ({} bytes, {} files)",
                            i,
                            group.size,
                            group.files.len()
                        ))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let mut selected = self.selected_groups.contains(&i);
                                if ui.checkbox(&mut selected, "").changed() {
                                    if selected {
                                        self.selected_groups.insert(i);
                                    } else {
                                        self.selected_groups.remove(&i);
                                    }
                                }
                                ui.label(format!(
                                    "{} bytes | {} files | hash: {}...",
                                    group.size,
                                    group.files.len(),
                                    &group.hash_short
                                ));
                            });
                            for f in &group.files {
                                ui.label(f.display().to_string());
                            }
                        });
                    }
                });
            }
        });

        // Keep repainting while scanning so the progress bar moves
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

impl DuplicateFinderApp {
    fn start_scan(&mut self) {
        let folder = self.folder.clone().unwrap();
        let min_size = self.min_size;
        let ignore_exts: Vec<String> = self
            .ignore_exts
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);
        self.is_scanning = true;
        self.groups.clear();
        self.selected_groups.clear();
        self.progress = (0, 0);
        self.status = "Scanning...".to_string();

        let tx_err = tx.clone();
        thread::spawn(move || {
            if let Err(e) = run_scan(folder, min_size, ignore_exts, tx) {
                let _ = tx_err.send(ScanMsg::Error(e.to_string()));
            }
        });
    }

    fn delete_selected(&mut self) {
        let mut deleted = 0u64;
        let mut freed = 0u64;
        let mut remove_indices = Vec::new();

        for (i, group) in self.groups.iter().enumerate() {
            if !self.selected_groups.contains(&i) {
                continue;
            }

            // Keep the first file, delete the rest
            for f in &group.files[1..] {
                if self.dry_run {
                    deleted += 1;
                    freed += group.size;
                } else {
                    match fs::remove_file(f) {
                        Ok(()) => {
                            deleted += 1;
                            freed += group.size;
                        }
                        Err(e) => {
                            self.status =
                                format!("Failed to delete {}: {}", f.display(), e);
                        }
                    }
                }
            }

            if !self.dry_run {
                remove_indices.push(i);
            }
        }

        if self.dry_run {
            self.status = format!(
                "Dry run: would delete {} files, free {} bytes ({} MB)",
                deleted,
                freed,
                freed / 1_048_576
            );
        } else {
            // Remove groups from the list (descending so indices stay valid)
            for i in remove_indices.into_iter().rev() {
                self.groups.remove(i);
            }
            self.selected_groups.clear();
            self.status = format!(
                "Deleted {} files, freed {} bytes ({} MB)",
                deleted,
                freed,
                freed / 1_048_576
            );
        }
    }
}

/// Walk the directory, hash candidate files, and return true duplicate groups.
fn run_scan(
    root: PathBuf,
    min_size: u64,
    ignore_exts: Vec<String>,
    tx: mpsc::Sender<ScanMsg>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = tx.send(ScanMsg::Progress(0, 0, "Indexing files...".to_string()));

    // Phase 1: collect all files, grouped by size
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_entry(|e| !e.file_type().is_symlink())
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
        if ignore_exts.contains(&ext) {
            continue;
        }

        if let Ok(metadata) = path.metadata() {
            if metadata.len() >= min_size {
                files.push((path.to_path_buf(), metadata.len()));
            }
        }
    }

    let _ = tx.send(ScanMsg::Progress(
        0,
        files.len(),
        format!("Indexed {} files", files.len()),
    ));

    // Only sizes with more than one file can be duplicates
    let mut size_groups: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    for (path, size) in &files {
        size_groups.entry(*size).or_default().push(path.clone());
    }

    let candidate_groups: Vec<(u64, Vec<PathBuf>)> = size_groups
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();

    let all_candidates: Vec<PathBuf> = candidate_groups
        .iter()
        .flat_map(|(_, paths)| paths.iter().cloned())
        .collect();

    let total = all_candidates.len();

    // Phase 2: hash candidate files
    let mut hashed: Vec<(PathBuf, String, u64)> = Vec::with_capacity(total);
    for (i, path) in all_candidates.iter().enumerate() {
        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        let hash = hash_file(path).unwrap_or_default();
        hashed.push((path.clone(), hash, size));

        if i % 10 == 0 || i == total - 1 {
            let _ = tx.send(ScanMsg::Progress(
                i + 1,
                total,
                format!("Hashing {}...", path.file_name().unwrap_or_default().to_string_lossy()),
            ));
        }
    }

    // Phase 3: regroup by (size, full hash), keep only true duplicates
    let mut hash_groups: HashMap<(u64, String), Vec<PathBuf>> = HashMap::new();
    for (path, hash, size) in hashed {
        if hash.is_empty() {
            continue;
        }
        hash_groups.entry((size, hash)).or_default().push(path);
    }

    let mut groups: Vec<DuplicateGroup> = hash_groups
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|((size, hash), mut files)| {
            files.sort();
            DuplicateGroup {
                hash_short: hash[..16.min(hash.len())].to_string(),
                hash,
                size,
                files,
            }
        })
        .collect();

    // Sort by size descending so biggest space-savers appear first
    groups.sort_by(|a, b| b.size.cmp(&a.size));

    let _ = tx.send(ScanMsg::Done(groups));
    Ok(())
}

/// Compute SHA-256 hash of a file.
fn hash_file(path: &Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let file = fs::File::open(path)?;
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

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Duplicate File Finder",
        options,
        Box::new(|_cc| Box::new(DuplicateFinderApp::default())),
    )
}
