use std::fs;
use std::path::Path;
use std::io::{self, Read};
use std::time::SystemTime;
use sha2::{Sha256, Sha512, Digest};
use walkdir::WalkDir;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use rayon::prelude::*;

use crate::{FileInfo, TreeNode, ScanError};

/// Progress callback type for reporting scan progress
pub type ProgressCallback = Arc<dyn Fn(f32, String) + Send + Sync>;

/// Core directory scanner with configurable options
#[derive(Clone)]
pub struct DirectoryScanner {
    pub include_hidden: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub calculate_sha256: bool,
    pub calculate_sha512: bool,
    pub calculate_md5: bool,
    pub calculate_format: bool,
    pub calculate_mime: bool,
    pub cancellation_flag: Option<Arc<AtomicBool>>,
}

impl std::fmt::Debug for DirectoryScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryScanner")
            .field("include_hidden", &self.include_hidden)
            .field("max_depth", &self.max_depth)
            .field("follow_symlinks", &self.follow_symlinks)
            .field("calculate_sha256", &self.calculate_sha256)
            .field("calculate_sha512", &self.calculate_sha512)
            .field("calculate_md5", &self.calculate_md5)
            .field("calculate_format", &self.calculate_format)
            .field("calculate_mime", &self.calculate_mime)
            .field("cancellation_flag", &"<Arc<AtomicBool>>")
            .finish()
    }
}

impl Default for DirectoryScanner {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_depth: None,
            follow_symlinks: false,
            calculate_sha256: true,
            calculate_sha512: false,
            calculate_md5: false,
            calculate_format: false,
            calculate_mime: false,
            cancellation_flag: None,
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
    
    pub fn calculate_sha512(mut self, calculate: bool) -> Self {
        self.calculate_sha512 = calculate;
        self
    }
    
    pub fn calculate_md5(mut self, calculate: bool) -> Self {
        self.calculate_md5 = calculate;
        self
    }
    
    pub fn calculate_format(mut self, calculate: bool) -> Self {
        self.calculate_format = calculate;
        self
    }
    
    pub fn calculate_mime(mut self, calculate: bool) -> Self {
        self.calculate_mime = calculate;
        self
    }
    
    pub fn cancellation_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancellation_flag = Some(flag);
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
            .filter(|e| {
                // Check cancellation before processing each entry
                if let Some(ref flag) = self.cancellation_flag {
                    if flag.load(Ordering::Relaxed) {
                        return false;
                    }
                }
                e.file_type().is_file()
            })
            .filter(|e| self.should_include_entry(e.path()))
            .collect();
        
        // Check cancellation after collection
        if let Some(ref flag) = self.cancellation_flag {
            if flag.load(Ordering::Relaxed) {
                return Err(ScanError::Cancelled);
            }
        }
        
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
        let calculate_sha512 = self.calculate_sha512;
        let calculate_md5 = self.calculate_md5;
        let calculate_format = self.calculate_format;
        let calculate_mime = self.calculate_mime;
        let cancellation_flag = self.cancellation_flag.clone();
        
        let file_infos: Vec<FileInfo> = file_paths
            .par_iter()
            .filter_map(|path| {
                // Check cancellation before processing each file
                if let Some(ref flag) = cancellation_flag {
                    if flag.load(Ordering::Relaxed) {
                        return None;
                    }
                }
                
                // Process the file
                let result = process_file_with_hash_options(path, calculate_sha256, calculate_sha512, calculate_md5, calculate_format, calculate_mime);
                
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
        
        // Check cancellation after processing
        if let Some(ref flag) = self.cancellation_flag {
            if flag.load(Ordering::Relaxed) {
                return Err(ScanError::Cancelled);
            }
        }
        
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
            // Check cancellation
            if let Some(ref flag) = self.cancellation_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err(ScanError::Cancelled);
                }
            }
            
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
                    let size = metadata.len();
                    stats.total_size += size;
                    stats.size_distribution.add_file(size);
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
        process_file_with_hash_options(path, self.calculate_sha256, self.calculate_sha512, self.calculate_md5, self.calculate_format, self.calculate_mime)
    }
    
    /// Check if a file/directory should be included based on scanner settings
    fn should_include_entry(&self, path: &Path) -> bool {
        if !self.include_hidden {
            // Check all components in the path for hidden directories
            for component in path.components() {
                if let std::path::Component::Normal(name) = component {
                    if name.to_string_lossy().starts_with('.') {
                        return false;
                    }
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
        // Check cancellation at the start of each node
        if let Some(ref flag) = self.cancellation_flag {
            if flag.load(Ordering::Relaxed) {
                return Err(ScanError::Cancelled);
            }
        }
        
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
                // Check cancellation in directory read loop
                if let Some(ref flag) = self.cancellation_flag {
                    if flag.load(Ordering::Relaxed) {
                        return Err(ScanError::Cancelled);
                    }
                }
                
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
                // Check cancellation before processing each child
                if let Some(ref flag) = self.cancellation_flag {
                    if flag.load(Ordering::Relaxed) {
                        return Err(ScanError::Cancelled);
                    }
                }
                
                match self.build_tree_node(&child_path, current_depth + 1, progress_callback) {
                    Ok(child_node) => children.push(child_node),
                    Err(ScanError::Cancelled) => return Err(ScanError::Cancelled),
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
    /// File size distribution counts
    pub size_distribution: FileSizeDistribution,
}

/// Distribution of files by size ranges
#[derive(Debug, Default, Clone)]
pub struct FileSizeDistribution {
    /// Empty files (0 bytes)
    pub empty: usize,
    /// 1 byte to 9 bytes
    pub tiny: usize,
    /// 10 bytes to 99 bytes
    pub very_small: usize,
    /// 100 bytes to 999 bytes
    pub small: usize,
    /// 1 KB to 9.99 KB
    pub small_kb: usize,
    /// 10 KB to 99.99 KB
    pub medium_kb: usize,
    /// 100 KB to 999.99 KB
    pub large_kb: usize,
    /// 1 MB to 9.99 MB
    pub small_mb: usize,
    /// 10 MB to 99.99 MB
    pub medium_mb: usize,
    /// 100 MB to 999.99 MB
    pub large_mb: usize,
    /// 1 GB to 9.99 GB
    pub small_gb: usize,
    /// 10 GB to 99.99 GB
    pub medium_gb: usize,
    /// 100 GB and above
    pub huge: usize,
}

impl FileSizeDistribution {
    /// Categorize a file size and increment the appropriate counter
    pub fn add_file(&mut self, size: u64) {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;
        
        match size {
            0 => self.empty += 1,
            1..=9 => self.tiny += 1,
            10..=99 => self.very_small += 1,
            100..=999 => self.small += 1,
            s if s < 10 * KB => self.small_kb += 1,
            s if s < 100 * KB => self.medium_kb += 1,
            s if s < MB => self.large_kb += 1,
            s if s < 10 * MB => self.small_mb += 1,
            s if s < 100 * MB => self.medium_mb += 1,
            s if s < GB => self.large_mb += 1,
            s if s < 10 * GB => self.small_gb += 1,
            s if s < 100 * GB => self.medium_gb += 1,
            _ => self.huge += 1,
        }
    }
    
    /// Get a formatted summary of the distribution
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        
        // Only include non-zero buckets for cleaner output
        let buckets = [
            ("Empty (0 bytes)", self.empty),
            ("1 B – 9 B", self.tiny),
            ("10 B – 99 B", self.very_small),
            ("100 B – 999 B", self.small),
            ("1 KB – 9.99 KB", self.small_kb),
            ("10 KB – 99.99 KB", self.medium_kb),
            ("100 KB – 999.99 KB", self.large_kb),
            ("1 MB – 9.99 MB", self.small_mb),
            ("10 MB – 99.99 MB", self.medium_mb),
            ("100 MB – 999.99 MB", self.large_mb),
            ("1 GB – 9.99 GB", self.small_gb),
            ("10 GB – 99.99 GB", self.medium_gb),
            ("100 GB+", self.huge),
        ];
        
        for (label, count) in buckets {
            if count > 0 {
                lines.push(format!("  {}: {}", label, count));
            }
        }
        
        if lines.is_empty() {
            "  No files".to_string()
        } else {
            lines.join("\n")
        }
    }
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
    process_file_with_hash_options(path, true, false, false, false, false)
}

/// Process a single file without calculating SHA256 (faster)
pub fn process_file_no_hash(path: &Path) -> io::Result<FileInfo> {
    process_file_with_hash_options(path, false, false, false, false, false)
}

/// Process a file with configurable hash options
pub fn process_file_with_hash_options(path: &Path, calculate_sha256: bool, calculate_sha512: bool, calculate_md5: bool, calculate_format: bool, calculate_mime: bool) -> io::Result<FileInfo> {
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
    
    let (md5, sha256, sha512) = if calculate_sha256 || calculate_sha512 || calculate_md5 {
        calculate_file_hashes(path, calculate_sha256, calculate_sha512, calculate_md5)?
    } else {
        (String::from("Not calculated"), String::from("Not calculated"), String::from("Not calculated"))
    };
    
    let format = if calculate_format {
        identify_format(path).unwrap_or_else(|| "Unknown".to_string())
    } else {
        String::from("Not calculated")
    };
    
    let mime_type = if calculate_mime {
        identify_mime_type(path).unwrap_or_else(|| "application/octet-stream".to_string())
    } else {
        String::from("Not calculated")
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
        sha512,
        format,
        mime_type,
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

/// Calculate MD5, SHA256, and SHA512 hashes efficiently in a single pass
pub fn calculate_file_hashes(path: &Path, calc_sha256: bool, calc_sha512: bool, calc_md5: bool) -> io::Result<(String, String, String)> {
    if !calc_sha256 && !calc_sha512 && !calc_md5 {
        return Ok((String::from("Not calculated"), String::from("Not calculated"), String::from("Not calculated")));
    }
    
    let mut file = fs::File::open(path)?;
    let mut sha256_hasher = if calc_sha256 { Some(Sha256::new()) } else { None };
    let mut sha512_hasher = if calc_sha512 { Some(Sha512::new()) } else { None };
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
        
        if let Some(ref mut hasher) = sha512_hasher {
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
    
    let sha512 = if let Some(hasher) = sha512_hasher {
        format!("{:x}", hasher.finalize())
    } else {
        String::from("Not calculated")
    };
    
    Ok((md5, sha256, sha512))
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

/// Identify file format using file-format crate
fn identify_format(path: &Path) -> Option<String> {
    let format = file_format::FileFormat::from_file(path).ok()?;
    Some(format.name().to_string())
}

/// Identify MIME type using file-format crate with fallback to mime_guess
fn identify_mime_type(path: &Path) -> Option<String> {
    // Try content-based detection first using file-format's built-in media_type
    if let Ok(format) = file_format::FileFormat::from_file(path) {
        return Some(format.media_type().to_string());
    }
    
    // Fall back to extension-based detection
    Some(mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string())
}
