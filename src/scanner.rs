use std::fs;
use std::path::Path;
use std::io::{self, Read};
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use walkdir::WalkDir;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use rayon::prelude::*;

use crate::{FileInfo, TreeNode, ScanError};

/// Progress callback type for reporting scan progress
pub type ProgressCallback = Arc<dyn Fn(f32, String) + Send + Sync>;

/// Core directory scanner with configurable options
#[derive(Debug, Clone)]
pub struct DirectoryScanner {
    pub include_hidden: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub calculate_sha256: bool,
    pub calculate_md5: bool,
}

impl Default for DirectoryScanner {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_depth: None,
            follow_symlinks: false,
            calculate_sha256: true,
            calculate_md5: false,
        }
    }
}

impl DirectoryScanner {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }
    
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }
    
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }
    
    pub fn calculate_sha256(mut self, calculate: bool) -> Self {
        self.calculate_sha256 = calculate;
        self
    }
    
    pub fn calculate_md5(mut self, calculate: bool) -> Self {
        self.calculate_md5 = calculate;
        self
    }
    
    /// Scan directory and return detailed file information
    pub fn scan_detailed(&self, path: &Path) -> Result<Vec<FileInfo>, ScanError> {
        self.scan_detailed_with_progress(path, None)
    }
    
    /// Scan directory with progress reporting
    pub fn scan_detailed_with_progress(
        &self, 
        path: &Path, 
        progress_callback: Option<ProgressCallback>
    ) -> Result<Vec<FileInfo>, ScanError> {
        validate_path(path)?;
        
        let mut walker = WalkDir::new(path).follow_links(self.follow_symlinks);
        
        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }
        
        // Collect all file paths first (sequential traversal)
        let files: Vec<_> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| self.should_include_entry(e.path()))
            .collect();
        
        let total_files = files.len();
        
        if total_files == 0 {
            if let Some(ref callback) = progress_callback {
                callback(1.0, "No files found".to_string());
            }
            return Ok(Vec::new());
        }
        
        // Sort files by depth (directory level) first, then by path
        // This helps with disk locality
        let mut file_paths: Vec<_> = files.iter()
            .map(|e| e.path().to_path_buf())
            .collect();
        
        file_paths.sort_by(|a, b| {
            let depth_a = a.components().count();
            let depth_b = b.components().count();
            
            match depth_a.cmp(&depth_b) {
                std::cmp::Ordering::Equal => a.cmp(b),
                other => other
            }
        });
        
        // Atomic counter for progress tracking
        let processed = Arc::new(AtomicUsize::new(0));
        let processed_clone = processed.clone();
        
        // Process files in parallel
        let calculate_sha256 = self.calculate_sha256;
        let calculate_md5 = self.calculate_md5;
        
        let file_infos: Vec<FileInfo> = file_paths
            .par_iter()
            .filter_map(|path| {
                // Process the file
                let result = process_file_with_hash_options(path, calculate_sha256, calculate_md5);
                
                // Update progress (with throttling to avoid callback spam)
                if let Some(ref callback) = progress_callback {
                    let current = processed_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    
                    // Only update progress every 10 files or on last file to reduce overhead
                    if current % 10 == 0 || current == total_files {
                        let progress = current as f32 / total_files as f32;
                        let status = format!("Processing: {} of {} files", current, total_files);
                        callback(progress, status);
                    }
                }
                
                match result {
                    Ok(info) => Some(info),
                    Err(e) => {
                        eprintln!("Error processing file '{}': {}", path.display(), e);
                        None
                    }
                }
            })
            .collect();
        
        if let Some(ref callback) = progress_callback {
            callback(1.0, format!("Scan completed: {} files processed", total_files));
        }
        
        Ok(file_infos)
    }
    
    /// Scan directory and return tree structure
    pub fn scan_tree(&self, path: &Path) -> Result<TreeNode, ScanError> {
        self.scan_tree_with_progress(path, None)
    }
    
    /// Scan directory tree with progress reporting
    pub fn scan_tree_with_progress(
        &self, 
        path: &Path,
        progress_callback: Option<ProgressCallback>
    ) -> Result<TreeNode, ScanError> {
        validate_path(path)?;
        
        if let Some(ref callback) = progress_callback {
            callback(0.0, format!("Scanning: {}", path.display()));
        }
        
        let result = self.build_tree_node(path, 0, &progress_callback);
        
        if let Some(ref callback) = progress_callback {
            callback(1.0, "Tree scan completed".to_string());
        }
        
        result
    }
    
    /// Get directory statistics without building full structures
    pub fn scan_stats(&self, path: &Path) -> Result<DirectoryStats, ScanError> {
        self.scan_stats_with_progress(path, None)
    }
    
    /// Get directory statistics with progress reporting
    pub fn scan_stats_with_progress(
        &self, 
        path: &Path,
        progress_callback: Option<ProgressCallback>
    ) -> Result<DirectoryStats, ScanError> {
        validate_path(path)?;
        
        let mut stats = DirectoryStats::default();
        let mut walker = WalkDir::new(path).follow_links(self.follow_symlinks);
        
        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }
        
        let entries: Vec<_> = walker.into_iter().filter_map(|e| e.ok()).collect();
        let total = entries.len();
        
        for (i, entry) in entries.iter().enumerate() {
            if let Some(ref callback) = progress_callback {
                let progress = (i + 1) as f32 / total as f32;
                callback(progress, format!("Analyzing: {}", entry.path().display()));
            }
            
            if !self.should_include_entry(entry.path()) {
                continue;
            }
            
            if entry.file_type().is_dir() {
                stats.directory_count += 1;
            } else if entry.file_type().is_file() {
                stats.file_count += 1;
                if let Ok(metadata) = entry.metadata() {
                    stats.total_size += metadata.len();
                }
            }
        }
        
        if let Some(ref callback) = progress_callback {
            callback(1.0, "Analysis completed".to_string());
        }
        
        Ok(stats)
    }
    
    /// Process a file with scanner options
    fn process_file_with_options(&self, path: &Path) -> io::Result<FileInfo> {
        process_file_with_hash_options(path, self.calculate_sha256, self.calculate_md5)
    }
    
    /// Check if a file/directory should be included based on scanner settings
    fn should_include_entry(&self, path: &Path) -> bool {
        if !self.include_hidden {
            if let Some(name) = path.file_name() {
                if name.to_string_lossy().starts_with('.') {
                    return false;
                }
            }
        }
        true
    }
    
    /// Recursively build tree structure
    fn build_tree_node(
        &self, 
        path: &Path, 
        current_depth: usize,
        progress_callback: &Option<ProgressCallback>
    ) -> Result<TreeNode, ScanError> {
        let name = path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .to_string();
        
        if let Some(ref callback) = progress_callback {
            callback(0.0, format!("Processing: {}", path.display()));
        }
        
        let mut children = Vec::new();
        
        if path.is_dir() && (self.max_depth.is_none() || current_depth < self.max_depth.unwrap()) {
            let entries = fs::read_dir(path)?;
            let mut child_paths = Vec::new();
            
            for entry in entries {
                let entry = entry?;
                let child_path = entry.path();
                
                if self.should_include_entry(&child_path) {
                    child_paths.push(child_path);
                }
            }
            
            // Sort children alphabetically (case-insensitive)
            child_paths.sort_by(|a, b| {
                let name_a = a.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                let name_b = b.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                name_a.cmp(&name_b)
            });
            
            for child_path in child_paths {
                match self.build_tree_node(&child_path, current_depth + 1, progress_callback) {
                    Ok(child_node) => children.push(child_node),
                    Err(e) => eprintln!("Error building tree for '{}': {}", child_path.display(), e),
                }
            }
        }
        
        Ok(TreeNode {
            name,
            path: path.to_path_buf(),
            is_directory: path.is_dir(),
            children,
        })
    }
}

/// Statistics about a directory scan
#[derive(Debug, Default, Clone)]
pub struct DirectoryStats {
    pub file_count: usize,
    pub directory_count: usize,
    pub total_size: u64,
}

impl DirectoryStats {
    pub fn total_items(&self) -> usize {
        self.file_count + self.directory_count
    }
    
    pub fn format_size(&self) -> String {
        format_file_size(self.total_size)
    }
}

/// Validate that the path exists and is a directory
pub fn validate_path(path: &Path) -> Result<(), ScanError> {
    if !path.exists() {
        return Err(ScanError::PathNotFound);
    }
    
    if !path.is_dir() {
        return Err(ScanError::NotADirectory);
    }
    
    Ok(())
}

/// Process a single file and extract its information (with SHA256)
pub fn process_file(path: &Path) -> io::Result<FileInfo> {
    process_file_with_hash_options(path, true, false)
}

/// Process a single file without calculating SHA256 (faster)
pub fn process_file_no_hash(path: &Path) -> io::Result<FileInfo> {
    process_file_with_hash_options(path, false, false)
}

/// Process a file with configurable hash options
pub fn process_file_with_hash_options(path: &Path, calculate_sha256: bool, calculate_md5: bool) -> io::Result<FileInfo> {
    let metadata = fs::metadata(path)?;
    
    let name = path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    
    let full_path = path.to_string_lossy().to_string();
    
    // Get directory path (without filename)
    let directory_path = path.parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| String::new());
    
    let size = metadata.len();
    
    let created = metadata.created()
        .ok()
        .and_then(|time| format_time_optional(time))
        .unwrap_or_else(|| "N/A".to_string());
    
    let last_modified = format_modified_time(metadata.modified()?);
    
    let last_accessed = metadata.accessed()
        .ok()
        .and_then(|time| format_time_optional(time))
        .unwrap_or_else(|| "N/A".to_string());
    
    let (md5, sha256) = if calculate_sha256 || calculate_md5 {
        calculate_file_hashes(path, calculate_sha256, calculate_md5)?
    } else {
        (String::from("Not calculated"), String::from("Not calculated"))
    };
    
    Ok(FileInfo {
        name,
        full_path,
        directory_path,
        size,
        created,
        last_modified,
        last_accessed,
        md5,
        sha256,
    })
}

/// Calculate SHA256 hash of a file
pub fn calculate_sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

/// Calculate MD5 hash of a file
pub fn calculate_md5(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0; 8192];
    let mut context = md5::Context::new();
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        context.consume(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", context.compute()))
}

/// Calculate both MD5 and SHA256 hashes efficiently in a single pass
pub fn calculate_file_hashes(path: &Path, calc_sha256: bool, calc_md5: bool) -> io::Result<(String, String)> {
    if !calc_sha256 && !calc_md5 {
        return Ok((String::from("Not calculated"), String::from("Not calculated")));
    }
    
    let mut file = fs::File::open(path)?;
    let mut sha256_hasher = if calc_sha256 { Some(Sha256::new()) } else { None };
    let mut md5_context = if calc_md5 { Some(md5::Context::new()) } else { None };
    let mut buffer = [0; 8192];
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        if let Some(ref mut hasher) = sha256_hasher {
            Digest::update(hasher, &buffer[..bytes_read]);
        }
        
        if let Some(ref mut context) = md5_context {
            context.consume(&buffer[..bytes_read]);
        }
    }
    
    let md5 = if let Some(context) = md5_context {
        format!("{:x}", context.compute())
    } else {
        String::from("Not calculated")
    };
    
    let sha256 = if let Some(hasher) = sha256_hasher {
        format!("{:x}", hasher.finalize())
    } else {
        String::from("Not calculated")
    };
    
    Ok((md5, sha256))
}

/// Format a SystemTime as a readable string
fn format_modified_time(time: SystemTime) -> String {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| {
            let datetime = chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                .unwrap_or_default();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_else(|_| "Unknown".to_string())
}

/// Format a SystemTime as Option<String> (returns None on error)
fn format_time_optional(time: SystemTime) -> Option<String> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| {
            chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                .map(|datetime| datetime.format("%Y-%m-%d %H:%M:%S").to_string())
        })
}

/// Format file size in human-readable form
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;
    
    if size < THRESHOLD {
        return format!("{} B", size);
    }
    
    let mut size_f = size as f64;
    let mut unit_index = 0;
    
    while size_f >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size_f /= THRESHOLD as f64;
        unit_index += 1;
    }
    
    format!("{:.1} {}", size_f, UNITS[unit_index])
}

/// Quick directory count (non-recursive, immediate children only)
pub fn quick_directory_count(path: &Path) -> io::Result<(usize, usize)> {
    let entries = fs::read_dir(path)?;
    let mut file_count = 0;
    let mut dir_count = 0;
    
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dir_count += 1;
        } else if entry.file_type()?.is_file() {
            file_count += 1;
        }
    }
    
    Ok((file_count, dir_count))
}
