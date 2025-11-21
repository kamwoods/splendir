use std::path::{Path, PathBuf};
use std::io;
use std::sync::Arc;

// Re-export modules for external use
pub mod scanner;
pub mod tree;

// Re-export commonly used types and functions for convenience
pub use scanner::{DirectoryScanner, DirectoryStats, validate_path, process_file, calculate_sha256, calculate_md5, format_file_size, ProgressCallback};
pub use tree::{TreeFormatter, TreeFormatOptions, TreeLine, FileType, get_file_color, filter_tree_by_type, count_files_by_type};

// Core data structures
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub full_path: String,
    pub directory_path: String,
    pub size: u64,
    pub created: String,
    pub last_modified: String,
    pub last_accessed: String,
    pub md5: String,
    pub sha256: String,
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub name: String,
    pub path: PathBuf,
    pub is_directory: bool,
    pub children: Vec<TreeNode>,
}

// Error handling
#[derive(Debug)]
pub enum ScanError {
    Io(io::Error),
    PathNotFound,
    NotADirectory,
    PermissionDenied,
    Cancelled,
}

impl From<io::Error> for ScanError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => ScanError::PathNotFound,
            io::ErrorKind::PermissionDenied => ScanError::PermissionDenied,
            _ => ScanError::Io(error),
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Io(e) => write!(f, "IO error: {}", e),
            ScanError::PathNotFound => write!(f, "Path not found"),
            ScanError::NotADirectory => write!(f, "Path is not a directory"),
            ScanError::PermissionDenied => write!(f, "Permission denied"),
            ScanError::Cancelled => write!(f, "Operation cancelled"),
        }
    }
}

impl std::error::Error for ScanError {}

// High-level convenience functions for common use cases

/// Scan a directory and return detailed file information using default settings
pub fn scan_directory_detailed(path: &Path) -> Result<Vec<FileInfo>, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_detailed(path)
}

/// Scan a directory with progress reporting
pub fn scan_directory_detailed_with_progress(
    path: &Path, 
    progress_callback: ProgressCallback
) -> Result<Vec<FileInfo>, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_detailed_with_progress(path, Some(progress_callback))
}

/// Scan a directory and return a tree structure using default settings
pub fn scan_directory_tree(path: &Path) -> Result<TreeNode, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_tree(path)
}

/// Scan a directory tree with progress reporting
pub fn scan_directory_tree_with_progress(
    path: &Path,
    progress_callback: ProgressCallback
) -> Result<TreeNode, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_tree_with_progress(path, Some(progress_callback))
}

/// Quick scan without SHA256 calculation for faster results
pub fn scan_directory_quick(path: &Path) -> Result<Vec<FileInfo>, ScanError> {
    let scanner = DirectoryScanner::new().calculate_sha256(false);
    scanner.scan_detailed(path)
}

/// Quick scan with progress reporting
pub fn scan_directory_quick_with_progress(
    path: &Path,
    progress_callback: ProgressCallback
) -> Result<Vec<FileInfo>, ScanError> {
    let scanner = DirectoryScanner::new().calculate_sha256(false);
    scanner.scan_detailed_with_progress(path, Some(progress_callback))
}

/// Get directory statistics without full file processing
pub fn scan_directory_stats(path: &Path) -> Result<DirectoryStats, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_stats(path)
}

/// Get directory statistics with progress reporting
pub fn scan_directory_stats_with_progress(
    path: &Path,
    progress_callback: ProgressCallback
) -> Result<DirectoryStats, ScanError> {
    let scanner = DirectoryScanner::new();
    scanner.scan_stats_with_progress(path, Some(progress_callback))
}

/// Scan with custom scanner configuration
pub fn scan_with_options(path: &Path, scanner: DirectoryScanner) -> Result<Vec<FileInfo>, ScanError> {
    scanner.scan_detailed(path)
}

/// Scan with custom scanner configuration and progress reporting
pub fn scan_with_options_and_progress(
    path: &Path, 
    scanner: DirectoryScanner,
    progress_callback: ProgressCallback
) -> Result<Vec<FileInfo>, ScanError> {
    scanner.scan_detailed_with_progress(path, Some(progress_callback))
}

/// Generate a formatted tree string output using default formatting
pub fn format_tree_output(tree: &TreeNode, colorize: bool) -> String {
    let options = TreeFormatOptions::new().colorize(colorize);
    let formatter = TreeFormatter::new(options);
    formatter.format_tree(tree)
}

/// Generate tree lines for GUI display
pub fn format_tree_lines(tree: &TreeNode, colorize: bool) -> Vec<TreeLine> {
    let options = TreeFormatOptions::new().colorize(colorize);
    let formatter = TreeFormatter::new(options);
    formatter.format_tree_lines(tree)
}

/// Comprehensive directory analysis
pub fn analyze_directory(path: &Path, include_hidden: bool, max_depth: Option<usize>) -> Result<DirectoryAnalysis, ScanError> {
    let scanner = DirectoryScanner::new()
        .include_hidden(include_hidden)
        .max_depth(max_depth.unwrap_or(50)); // Reasonable default max depth
    
    let stats = scanner.scan_stats(path)?;
    let tree = scanner.scan_tree(path)?;
    let file_type_counts = count_files_by_type(&tree);
    
    Ok(DirectoryAnalysis {
        stats,
        tree,
        file_type_counts,
        path: path.to_path_buf(),
    })
}

/// Comprehensive directory analysis with progress reporting
pub fn analyze_directory_with_progress(
    path: &Path, 
    include_hidden: bool, 
    max_depth: Option<usize>,
    progress_callback: ProgressCallback
) -> Result<DirectoryAnalysis, ScanError> {
    let scanner = DirectoryScanner::new()
        .include_hidden(include_hidden)
        .max_depth(max_depth.unwrap_or(50));
    
    // For analysis, we'll divide progress into three phases
    let stats_callback = {
        let callback = progress_callback.clone();
        Arc::new(move |p: f32, s: String| {
            callback(p * 0.33, format!("Phase 1/3: {}", s));
        })
    };
    
    let tree_callback = {
        let callback = progress_callback.clone();
        Arc::new(move |p: f32, s: String| {
            callback(0.33 + p * 0.33, format!("Phase 2/3: {}", s));
        })
    };
    
    progress_callback(0.0, "Starting analysis...".to_string());
    
    let stats = scanner.scan_stats_with_progress(path, Some(stats_callback))?;
    let tree = scanner.scan_tree_with_progress(path, Some(tree_callback))?;
    
    progress_callback(0.66, "Phase 3/3: Counting file types...".to_string());
    let file_type_counts = count_files_by_type(&tree);
    
    progress_callback(1.0, "Analysis completed".to_string());
    
    Ok(DirectoryAnalysis {
        stats,
        tree,
        file_type_counts,
        path: path.to_path_buf(),
    })
}

/// Comprehensive analysis result
#[derive(Debug)]
pub struct DirectoryAnalysis {
    pub stats: DirectoryStats,
    pub tree: TreeNode,
    pub file_type_counts: std::collections::HashMap<FileType, usize>,
    pub path: PathBuf,
}

impl DirectoryAnalysis {
    /// Get a summary of the analysis
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "Directory: {}\n",
            self.path.display()
        );
        
        summary.push_str(&format!(
            "Total: {} files, {} directories\n",
            self.stats.file_count,
            self.stats.directory_count
        ));
        
        summary.push_str(&format!(
            "Total size: {}\n\n",
            self.stats.format_size()
        ));
        
        summary.push_str("File types:\n");
        let mut sorted_types: Vec<_> = self.file_type_counts.iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
        
        for (file_type, count) in sorted_types {
            if *file_type != FileType::Directory {
                summary.push_str(&format!("  {}: {}\n", file_type.description(), count));
            }
        }
        
        summary
    }
    
    /// Export tree as formatted string
    pub fn export_tree(&self, colorize: bool) -> String {
        format_tree_output(&self.tree, colorize)
    }
    
    /// Get files of a specific type
    pub fn files_by_type(&self, file_type: FileType) -> Vec<&TreeNode> {
        let mut files = Vec::new();
        collect_files_by_type(&self.tree, file_type, &mut files);
        files
    }
}

// Helper function to collect files by type
fn collect_files_by_type<'a>(node: &'a TreeNode, target_type: FileType, files: &mut Vec<&'a TreeNode>) {
    let (_, file_type) = get_file_color(&node.path, &node.name, node.is_directory);
    
    if file_type == target_type {
        files.push(node);
    }
    
    for child in &node.children {
        collect_files_by_type(child, target_type, files);
    }
}

// Preset scanner configurations for common use cases
pub struct ScannerPresets;

impl ScannerPresets {
    /// Minimal scan for large directories (no hashes, minimal file info)
    pub fn minimal() -> DirectoryScanner {
        DirectoryScanner::new()
            .calculate_md5(false)
            .calculate_sha256(false)
            // .max_depth(3)
    }
    
    /// Complete scan with all features enabled
    pub fn complete() -> DirectoryScanner {
        DirectoryScanner::new()
            .include_hidden(true)
            .follow_symlinks(true)
            .calculate_md5(true)
            .calculate_sha256(true)
    }
   
    /// Default scan with MD5 enabled
    pub fn defaultmd5() -> DirectoryScanner {
        DirectoryScanner::new()
            .include_hidden(false)
            .follow_symlinks(false)
            .calculate_md5(true)
            .calculate_sha256(false)
    }

    /// Default scan with SHA256 enabled
    pub fn defaultsha256() -> DirectoryScanner {
        DirectoryScanner::new()
            .include_hidden(false)
            .follow_symlinks(false)
            .calculate_md5(false)
            .calculate_sha256(true)
    }
}
