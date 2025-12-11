use std::fs;
use std::path::Path;
use std::io::{self, Read};
use std::time::SystemTime;
use sha2::{Sha256, Sha512, Digest};
use walkdir::WalkDir;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use rayon::prelude::*;
use std::collections::HashSet;

use crate::{FileInfo, TreeNode, ScanError};

/// Progress callback type for reporting scan progress
pub type ProgressCallback = Arc<dyn Fn(f32, String) + Send + Sync>;

/// Virtual/pseudo filesystem types that should typically be skipped
const VIRTUAL_FS_TYPES: &[&str] = &[
    "proc", "sysfs", "devfs", "devtmpfs", "tmpfs", "cgroup", "cgroup2",
    "debugfs", "securityfs", "fusectl", "configfs", "pstore", "efivarfs",
    "bpf", "tracefs", "hugetlbfs", "mqueue", "devpts", "autofs",
    "binfmt_misc", "rpc_pipefs", "nfsd", "fuse.gvfsd-fuse", "fuse.portal",
];

/// Paths that should always be skipped when scanning from root
/// These are used as a fallback when filesystem type detection isn't available
const VIRTUAL_PATHS_LINUX: &[&str] = &[
    "/proc", "/sys", "/dev", "/run", "/snap", "/tmp",
];

#[cfg(target_os = "macos")]
const VIRTUAL_PATHS_MACOS: &[&str] = &[
    "/dev", "/System/Volumes/Data/.Spotlight-V100",
    "/System/Volumes/Data/.fseventsd",
    "/private/var/vm", "/cores",
];

/// Core directory scanner with configurable options
#[derive(Clone)]
pub struct DirectoryScanner {
    pub include_dotfiles: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub calculate_sha256: bool,
    pub calculate_sha512: bool,
    pub calculate_md5: bool,
    pub calculate_format: bool,
    pub calculate_mime: bool,
    pub cancellation_flag: Option<Arc<AtomicBool>>,
    /// Skip known virtual/pseudo filesystems (proc, sysfs, devfs, etc.)
    pub skip_virtual_filesystems: bool,
    /// Stay on the same filesystem (don't cross mount boundaries)
    pub stay_on_filesystem: bool,
}

impl std::fmt::Debug for DirectoryScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryScanner")
            .field("include_dotfiles", &self.include_dotfiles)
            .field("max_depth", &self.max_depth)
            .field("follow_symlinks", &self.follow_symlinks)
            .field("calculate_sha256", &self.calculate_sha256)
            .field("calculate_sha512", &self.calculate_sha512)
            .field("calculate_md5", &self.calculate_md5)
            .field("calculate_format", &self.calculate_format)
            .field("calculate_mime", &self.calculate_mime)
            .field("skip_virtual_filesystems", &self.skip_virtual_filesystems)
            .field("stay_on_filesystem", &self.stay_on_filesystem)
            .field("cancellation_flag", &"<Arc<AtomicBool>>")
            .finish()
    }
}

impl Default for DirectoryScanner {
    fn default() -> Self {
        Self {
            include_dotfiles: false,
            max_depth: None,
            follow_symlinks: false,
            calculate_sha256: true,
            calculate_sha512: false,
            calculate_md5: false,
            calculate_format: false,
            calculate_mime: false,
            cancellation_flag: None,
            skip_virtual_filesystems: true,  // Safe default
            stay_on_filesystem: false,
        }
    }
}

impl DirectoryScanner {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn include_dotfiles(mut self, include: bool) -> Self {
        self.include_dotfiles = include;
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
    
    pub fn skip_virtual_filesystems(mut self, skip: bool) -> Self {
        self.skip_virtual_filesystems = skip;
        self
    }
    
    pub fn stay_on_filesystem(mut self, stay: bool) -> Self {
        self.stay_on_filesystem = stay;
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
        
        // Build mount info for virtual filesystem detection
        let mount_info = if self.skip_virtual_filesystems || self.stay_on_filesystem {
            Some(MountInfo::new(path)?)
        } else {
            None
        };
        
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
            .filter(|e| self.should_include_entry(e.path(), &mount_info))
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
        
        // Build mount info for virtual filesystem detection
        let mount_info = if self.skip_virtual_filesystems || self.stay_on_filesystem {
            Some(MountInfo::new(path)?)
        } else {
            None
        };
        
        if let Some(ref callback) = progress_callback {
            callback(0.0, format!("Scanning: {}", path.display()));
        }
        
        let result = self.build_tree_node(path, 0, &progress_callback, &mount_info);
        
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
        
        // Build mount info for virtual filesystem detection
        let mount_info = if self.skip_virtual_filesystems || self.stay_on_filesystem {
            Some(MountInfo::new(path)?)
        } else {
            None
        };
        
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
            
            if !self.should_include_entry(entry.path(), &mount_info) {
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
    fn should_include_entry(&self, path: &Path, mount_info: &Option<MountInfo>) -> bool {
        // Check dotfiles filter
        if !self.include_dotfiles {
            // Check all components in the path for dotfiles/directories (starting with '.')
            for component in path.components() {
                if let std::path::Component::Normal(name) = component {
                    if name.to_string_lossy().starts_with('.') {
                        return false;
                    }
                }
            }
        }
        
        // Check virtual filesystem and mount boundary filters
        if let Some(ref info) = mount_info {
            if !info.should_include_path(path, self.skip_virtual_filesystems, self.stay_on_filesystem) {
                return false;
            }
        }
        
        true
    }
    
    /// Recursively build tree structure
    fn build_tree_node(
        &self, 
        path: &Path, 
        current_depth: usize,
        progress_callback: &Option<ProgressCallback>,
        mount_info: &Option<MountInfo>,
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
                
                if self.should_include_entry(&child_path, mount_info) {
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
                
                match self.build_tree_node(&child_path, current_depth + 1, progress_callback, mount_info) {
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

// ============================================================================
// Mount information for virtual filesystem detection
// ============================================================================

/// Information about mount points used for filtering virtual filesystems
pub struct MountInfo {
    /// Device ID of the starting path (for stay_on_filesystem)
    start_device_id: u64,
    /// Set of mount points that are virtual filesystems
    virtual_mount_points: HashSet<std::path::PathBuf>,
    /// Fallback paths to skip (used when mount detection fails)
    fallback_skip_paths: Vec<&'static str>,
    /// Paths that were actually encountered and skipped during scanning
    skipped_paths: std::sync::Mutex<HashSet<std::path::PathBuf>>,
}

impl Clone for MountInfo {
    fn clone(&self) -> Self {
        Self {
            start_device_id: self.start_device_id,
            virtual_mount_points: self.virtual_mount_points.clone(),
            fallback_skip_paths: self.fallback_skip_paths.clone(),
            skipped_paths: std::sync::Mutex::new(
                self.skipped_paths.lock().map(|g| g.clone()).unwrap_or_default()
            ),
        }
    }
}

impl MountInfo {
    /// Create mount info for a given starting path
    pub fn new(start_path: &Path) -> Result<Self, ScanError> {
        let start_device_id = get_device_id(start_path).unwrap_or(0);
        let virtual_mount_points = detect_virtual_mounts();
        
        // Platform-specific fallback paths
        #[cfg(target_os = "linux")]
        let fallback_skip_paths = VIRTUAL_PATHS_LINUX.to_vec();
        
        #[cfg(target_os = "macos")]
        let fallback_skip_paths = VIRTUAL_PATHS_MACOS.to_vec();
        
        #[cfg(windows)]
        let fallback_skip_paths = Vec::new();
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let fallback_skip_paths = Vec::new();
        
        Ok(Self {
            start_device_id,
            virtual_mount_points,
            fallback_skip_paths,
            skipped_paths: std::sync::Mutex::new(HashSet::new()),
        })
    }
    
    /// Check if a path should be included based on mount filters
    /// Records skipped virtual filesystem paths for later reporting
    pub fn should_include_path(&self, path: &Path, skip_virtual: bool, stay_on_fs: bool) -> bool {
        // Check stay_on_filesystem
        if stay_on_fs && self.start_device_id != 0 {
            if let Some(device_id) = get_device_id(path) {
                if device_id != self.start_device_id {
                    return false;
                }
            }
        }
        
        // Check virtual filesystem mounts
        if skip_virtual {
            // Check if path starts with any virtual mount point
            for mount_point in &self.virtual_mount_points {
                if path.starts_with(mount_point) {
                    // Record this skip (use the mount point, not the full path)
                    if let Ok(mut skipped) = self.skipped_paths.lock() {
                        skipped.insert(mount_point.clone());
                    }
                    return false;
                }
            }
            
            // Check fallback paths
            let path_str = path.to_string_lossy();
            for skip_path in &self.fallback_skip_paths {
                if path_str.starts_with(skip_path) {
                    // Record this skip
                    if let Ok(mut skipped) = self.skipped_paths.lock() {
                        skipped.insert(std::path::PathBuf::from(skip_path));
                    }
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Get the list of virtual filesystem paths that were skipped during scanning
    pub fn get_skipped_paths(&self) -> Vec<std::path::PathBuf> {
        if let Ok(skipped) = self.skipped_paths.lock() {
            let mut paths: Vec<_> = skipped.iter().cloned().collect();
            paths.sort();
            paths
        } else {
            Vec::new()
        }
    }
    
    /// Get all virtual mount points that would be skipped when scanning from a given path
    /// This includes both detected mount points and fallback paths
    pub fn get_virtual_mounts_under(&self, scan_path: &Path) -> Vec<std::path::PathBuf> {
        let mut result = Vec::new();
        
        // Add detected virtual mount points that are under the scan path
        for mount_point in &self.virtual_mount_points {
            if mount_point.starts_with(scan_path) {
                result.push(mount_point.clone());
            }
        }
        
        // Add fallback paths that are under the scan path
        for fallback in &self.fallback_skip_paths {
            let fallback_path = std::path::PathBuf::from(fallback);
            if fallback_path.starts_with(scan_path) && !result.contains(&fallback_path) {
                // Only add if the path exists
                if fallback_path.exists() {
                    result.push(fallback_path);
                }
            }
        }
        
        result.sort();
        result
    }
}

/// Get the device ID for a path (used for stay_on_filesystem)
#[cfg(unix)]
fn get_device_id(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.dev())
}

#[cfg(windows)]
fn get_device_id(path: &Path) -> Option<u64> {
    // On Windows, we could use GetVolumeInformationW to get volume serial number
    // For simplicity, we'll use the drive letter as a pseudo device ID
    path.to_string_lossy()
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u64)
}

#[cfg(not(any(unix, windows)))]
fn get_device_id(_path: &Path) -> Option<u64> {
    None
}

/// Detect virtual filesystem mount points
#[cfg(target_os = "linux")]
fn detect_virtual_mounts() -> HashSet<std::path::PathBuf> {
    let mut virtual_mounts = HashSet::new();
    
    // Parse /proc/mounts to find virtual filesystems
    if let Ok(contents) = fs::read_to_string("/proc/mounts") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let mount_point = parts[1];
                let fs_type = parts[2];
                
                // Check if this is a virtual filesystem type
                if VIRTUAL_FS_TYPES.contains(&fs_type) {
                    virtual_mounts.insert(std::path::PathBuf::from(mount_point));
                }
            }
        }
    }
    
    virtual_mounts
}

#[cfg(target_os = "macos")]
fn detect_virtual_mounts() -> HashSet<std::path::PathBuf> {
    use std::process::Command;
    
    let mut virtual_mounts = HashSet::new();
    
    // Use mount command to get filesystem info
    if let Ok(output) = Command::new("mount").output() {
        if let Ok(mount_output) = String::from_utf8(output.stdout) {
            for line in mount_output.lines() {
                // Parse lines like: devfs on /dev (devfs, local, nobrowse)
                if let Some(on_pos) = line.find(" on ") {
                    let after_on = &line[on_pos + 4..];
                    if let Some(paren_pos) = after_on.find(" (") {
                        let mount_point = &after_on[..paren_pos];
                        let fs_info = &after_on[paren_pos + 2..];
                        
                        // Check filesystem type (first item in parentheses)
                        if let Some(fs_type) = fs_info.split(',').next() {
                            let fs_type = fs_type.trim();
                            if fs_type == "devfs" || fs_type == "autofs" {
                                virtual_mounts.insert(std::path::PathBuf::from(mount_point));
                            }
                        }
                    }
                }
            }
        }
    }
    
    virtual_mounts
}

#[cfg(windows)]
fn detect_virtual_mounts() -> HashSet<std::path::PathBuf> {
    // Windows doesn't have virtual filesystems in the same way as Unix
    // Return empty set - we rely on other mechanisms on Windows
    HashSet::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn detect_virtual_mounts() -> HashSet<std::path::PathBuf> {
    HashSet::new()
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
