use std::path::Path;
use crate::TreeNode;

/// Tree formatting options
#[derive(Debug, Clone)]
pub struct TreeFormatOptions {
    pub colorize: bool,
    pub show_dotfiles: bool,
    pub use_unicode: bool,
    pub show_file_sizes: bool,
    pub show_permissions: bool,
}

impl Default for TreeFormatOptions {
    fn default() -> Self {
        Self {
            colorize: false,
            show_dotfiles: false,
            use_unicode: true,
            show_file_sizes: false,
            show_permissions: false,
        }
    }
}

impl TreeFormatOptions {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn colorize(mut self, colorize: bool) -> Self {
        self.colorize = colorize;
        self
    }
    
    pub fn show_dotfiles(mut self, show: bool) -> Self {
        self.show_dotfiles = show;
        self
    }
    
    pub fn use_unicode(mut self, unicode: bool) -> Self {
        self.use_unicode = unicode;
        self
    }
    
    pub fn show_file_sizes(mut self, show: bool) -> Self {
        self.show_file_sizes = show;
        self
    }
    
    pub fn show_permissions(mut self, show: bool) -> Self {
        self.show_permissions = show;
        self
    }
}

/// Tree character sets for different display modes
pub struct TreeChars {
    pub branch: &'static str,
    pub last_branch: &'static str,
    pub vertical: &'static str,
    pub horizontal: &'static str,
    pub space: &'static str,
}

impl TreeChars {
    pub fn unicode() -> Self {
        Self {
            branch: "├",
            last_branch: "└",
            vertical: "│",
            horizontal: "───",
            space: "   ",
        }
    }
    
    pub fn ascii() -> Self {
        Self {
            branch: "|",
            last_branch: "`",
            vertical: "|",
            horizontal: "---",
            space: "   ",
        }
    }
}

/// Tree formatter for converting TreeNode structures to formatted strings
pub struct TreeFormatter {
    options: TreeFormatOptions,
    chars: TreeChars,
}

impl TreeFormatter {
    pub fn new(options: TreeFormatOptions) -> Self {
        let chars = if options.use_unicode {
            TreeChars::unicode()
        } else {
            TreeChars::ascii()
        };
        
        Self { options, chars }
    }
    
    /// Format a tree structure as a string
    pub fn format_tree(&self, tree: &TreeNode) -> String {
        let mut output = String::new();
        
        // Format root node
        if self.options.colorize {
            let (colored_name, _) = get_file_color(&tree.path, &tree.name, tree.is_directory);
            output.push_str(&format!("{}\n", colored_name));
        } else {
            output.push_str(&format!("{}\n", tree.name));
        }
        
        // Format children
        self.format_tree_recursive(tree, "", true, &mut output);
        output
    }
    
    /// Format tree as lines (useful for GUI list widgets)
    pub fn format_tree_lines(&self, tree: &TreeNode) -> Vec<TreeLine> {
        let mut lines = Vec::new();
        
        // Add root
        lines.push(TreeLine {
            content: tree.name.clone(),
            depth: 0,
            is_directory: tree.is_directory,
            path: tree.path.clone(),
            prefix: String::new(),
        });
        
        self.format_tree_lines_recursive(tree, "", true, 1, &mut lines);
        lines
    }
    
    fn format_tree_recursive(&self, node: &TreeNode, prefix: &str, _is_last: bool, output: &mut String) {
        for (i, child) in node.children.iter().enumerate() {
            let is_last_child = i == node.children.len() - 1;
            let connector = if is_last_child { 
                self.chars.last_branch 
            } else { 
                self.chars.branch 
            };
            
            if self.options.colorize {
                let (colored_name, _) = get_file_color(&child.path, &child.name, child.is_directory);
                output.push_str(&format!(
                    "\x1b[37m{}{}\x1b[0m{} {}\n", 
                    prefix, 
                    connector, 
                    self.chars.horizontal,
                    colored_name
                ));
            } else {
                output.push_str(&format!(
                    "{}{}{} {}\n", 
                    prefix, 
                    connector, 
                    self.chars.horizontal,
                    child.name
                ));
            }
            
            if child.is_directory && !child.children.is_empty() {
                let new_prefix = if is_last_child {
                    format!("{}    ", prefix)
                } else {
                    format!("{}{}   ", prefix, self.chars.vertical)
                };
                
                self.format_tree_recursive(child, &new_prefix, is_last_child, output);
            }
        }
    }
    
    fn format_tree_lines_recursive(
        &self, 
        node: &TreeNode, 
        prefix: &str, 
        _is_last: bool, 
        depth: usize,
        lines: &mut Vec<TreeLine>
    ) {
        for (i, child) in node.children.iter().enumerate() {
            let is_last_child = i == node.children.len() - 1;
            let connector = if is_last_child { 
                self.chars.last_branch 
            } else { 
                self.chars.branch 
            };
            
            let line_prefix = format!("{}{}{} ", prefix, connector, self.chars.horizontal);
            
            lines.push(TreeLine {
                content: child.name.clone(),
                depth,
                is_directory: child.is_directory,
                path: child.path.clone(),
                prefix: line_prefix,
            });
            
            if child.is_directory && !child.children.is_empty() {
                let new_prefix = if is_last_child {
                    format!("{}    ", prefix)
                } else {
                    format!("{}{}   ", prefix, self.chars.vertical)
                };
                
                self.format_tree_lines_recursive(child, &new_prefix, is_last_child, depth + 1, lines);
            }
        }
    }
}

/// Represents a single line in a tree display (useful for GUIs)
#[derive(Debug, Clone)]
pub struct TreeLine {
    pub content: String,
    pub depth: usize,
    pub is_directory: bool,
    pub path: std::path::PathBuf,
    pub prefix: String,
}

/// Get color information for a file based on its extension and type
pub fn get_file_color(path: &Path, name: &str, is_directory: bool) -> (String, FileType) {
    if is_directory {
        (format!("\x1b[1;34m{}\x1b[0m", name), FileType::Directory)
    } else if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        let (color_code, file_type) = match ext_str.as_str() {
            "exe" | "bin" | "run" | "sh" | "bat" | "cmd" => ("\x1b[1;32m", FileType::Executable),
            "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => ("\x1b[1;31m", FileType::Archive),
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "webp" | "ico" => ("\x1b[1;35m", FileType::Image),
            "txt" | "md" | "pdf" | "doc" | "docx" | "rtf" | "odt" => ("\x1b[36m", FileType::Document),
            "rs" | "c" | "cpp" | "h" | "hpp" | "py" | "js" | "ts" | "java" | "go" | "rb" | "php" => ("\x1b[33m", FileType::SourceCode),
            "toml" | "yaml" | "yml" | "json" | "xml" | "ini" | "conf" | "cfg" | "env" => ("\x1b[1;33m", FileType::Config),
            "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => ("\x1b[95m", FileType::Audio),
            "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" => ("\x1b[96m", FileType::Video),
            _ => ("\x1b[37m", FileType::Other),
        };
        (format!("{}{}\x1b[0m", color_code, name), file_type)
    } else {
        (format!("\x1b[37m{}\x1b[0m", name), FileType::Other)
    }
}

/// File type classification for styling and filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Directory,
    Executable,
    Archive,
    Image,
    Document,
    SourceCode,
    Config,
    Audio,
    Video,
    Other,
}

impl FileType {
    /// Get a human-readable description of the file type
    pub fn description(&self) -> &'static str {
        match self {
            FileType::Directory => "Directory",
            FileType::Executable => "Executable",
            FileType::Archive => "Archive",
            FileType::Image => "Image",
            FileType::Document => "Document",
            FileType::SourceCode => "Source Code",
            FileType::Config => "Configuration",
            FileType::Audio => "Audio",
            FileType::Video => "Video",
            FileType::Other => "File",
        }
    }
    
    /// Get the color code for this file type
    pub fn color_code(&self) -> &'static str {
        match self {
            FileType::Directory => "\x1b[1;34m",      // Bold blue
            FileType::Executable => "\x1b[1;32m",    // Bold green
            FileType::Archive => "\x1b[1;31m",       // Bold red
            FileType::Image => "\x1b[1;35m",         // Bold magenta
            FileType::Document => "\x1b[36m",        // Cyan
            FileType::SourceCode => "\x1b[33m",      // Yellow
            FileType::Config => "\x1b[1;33m",        // Bright yellow
            FileType::Audio => "\x1b[95m",           // Bright magenta
            FileType::Video => "\x1b[96m",           // Bright cyan
            FileType::Other => "\x1b[37m",           // White
        }
    }
}

/// Utility functions for tree operations

/// Filter tree nodes based on criteria
pub fn filter_tree_by_type(tree: &TreeNode, allowed_types: &[FileType]) -> TreeNode {
    let mut filtered_children = Vec::new();
    
    for child in &tree.children {
        let (_, file_type) = get_file_color(&child.path, &child.name, child.is_directory);
        
        if allowed_types.contains(&file_type) || child.is_directory {
            let filtered_child = if child.is_directory {
                filter_tree_by_type(child, allowed_types)
            } else {
                child.clone()
            };
            filtered_children.push(filtered_child);
        }
    }
    
    TreeNode {
        name: tree.name.clone(),
        path: tree.path.clone(),
        is_directory: tree.is_directory,
        children: filtered_children,
    }
}

/// Count files by type in a tree
pub fn count_files_by_type(tree: &TreeNode) -> std::collections::HashMap<FileType, usize> {
    let mut counts = std::collections::HashMap::new();
    count_files_recursive(tree, &mut counts);
    counts
}

fn count_files_recursive(node: &TreeNode, counts: &mut std::collections::HashMap<FileType, usize>) {
    let (_, file_type) = get_file_color(&node.path, &node.name, node.is_directory);
    *counts.entry(file_type).or_insert(0) += 1;
    
    for child in &node.children {
        count_files_recursive(child, counts);
    }
}
