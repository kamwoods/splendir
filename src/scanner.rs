use std::fs;
use std::path::Path;
use std::io::{self, Read};
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

use crate::{FileInfo, TreeNode, ScanError};

/// Core directory scanner with configurable options
#[derive(Debug, Clone)]
pub struct DirectoryScanner {
    pub include_hidden: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub calculate_hashes: bool,
}

impl Default for DirectoryScanner {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_depth: None,
            follow_symlinks: false,
            calculate_hashes: true,
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
    
    pub fn calculate_hashes(mut self, calculate: bool) -> Self {
        self.calculate_hashes = calculate;
        self
    }
    
    /// Scan directory and return detailed file information
    pub fn scan_detailed(&self, path: &Path) -> Result<Vec<FileInfo>, ScanError> {
        validate_path(path)?;
        
        let mut walker = WalkDir::new(path).follow_links(self.follow_symlinks);
        
        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }
        
        let mut files: Vec<_> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| self.should_include_entry(e.path()))
            .collect();
        
        // Sort files by depth (directory level) first, then by path
        files.sort_by(|a, b| {
            let depth_a = a.path().components().count();
            let depth_b = b.path().components().count();
            
            match depth_a.cmp(&depth_b) {
                std::cmp::Ordering::Equal => a.path().cmp(b.path()),
                other => other
            }
        });
        
        let mut file_infos = Vec::new();
        
        for entry in files {
            match self.process_file_with_options(entry.path()) {
                Ok(file_info) => file_infos.push(file_info),
                Err(e) => eprintln!("Error processing file '{}': {}", entry.path().display(), e),
            }
        }
        
        Ok(file_infos)
    }
    
    /// Scan directory and return tree structure
    pub fn scan_tree(&self, path: &Path) -> Result<TreeNode, ScanError> {
        validate_path(path)?;
        self.build_tree_node(path, 0)
    }
    
    /// Get directory statistics without building full structures
    pub fn scan_stats(&self, path: &Path) -> Result<DirectoryStats, ScanError> {
        validate_path(path)?;
        
        let mut stats = DirectoryStats::default();
        let mut walker = WalkDir::new(path).follow_links(self.follow_symlinks);
        
        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }
        
        for entry in walker.into_iter().filter_map(|e| e.ok()) {
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
        
        Ok(stats)
    }
    
    /// Process a file with scanner options
    fn process_file_with_options(&self, path: &Path) -> io::Result<FileInfo> {
        if self.calculate_hashes {
            process_file(path)
        } else {
            process_file_no_hash(path)
        }
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
    fn build_tree_node(&self, path: &Path, current_depth: usize) -> Result<TreeNode, ScanError> {
        let name = path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .to_string();
        
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
                match self.build_tree_node(&child_path, current_depth + 1) {
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
    let metadata = fs::metadata(path)?;
    
    let name = path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    
    let full_path = path.to_string_lossy().to_string();
    let size = metadata.len();
    
    let last_modified = format_modified_time(metadata.modified()?);
    let sha256 = calculate_sha256(path)?;
    
    Ok(FileInfo {
        name,
        full_path,
        size,
        last_modified,
        sha256,
    })
}

/// Process a single file without calculating SHA256 (faster)
pub fn process_file_no_hash(path: &Path) -> io::Result<FileInfo> {
    let metadata = fs::metadata(path)?;
    
    let name = path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    
    let full_path = path.to_string_lossy().to_string();
    let size = metadata.len();
    
    let last_modified = format_modified_time(metadata.modified()?);
    
    Ok(FileInfo {
        name,
        full_path,
        size,
        last_modified,
        sha256: "Not calculated".to_string(),
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
