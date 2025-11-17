use std::env;
use std::path::Path;
use std::process;
use std::io::{self, Write};
use std::sync::Arc;

// Import from our library - now much simpler!
use directory_scanner::{
    scan_directory_detailed, 
    scan_directory_detailed_with_progress,
    scan_directory_tree,
    scan_directory_tree_with_progress, 
    format_tree_output,
    analyze_directory,
    analyze_directory_with_progress,
    ScannerPresets,
    scan_with_options,
    scan_with_options_and_progress,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    // Parse arguments - options first, then directory path
    let mut tree_mode = false;
    let mut colorize = false;
    let mut fast_mode = false;
    let mut analysis_mode = false;
    let mut directory_path: Option<String> = None;
    
    // Skip program name (args[0]) and parse remaining arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tree" => tree_mode = true,
            "-C" => colorize = true,
            "--fast" => fast_mode = true,
            "--analyze" => analysis_mode = true,
            "--help" | "-h" => {
                print_help(&args[0]);
                process::exit(0);
            }
            arg => {
                // If it starts with '-', it's an unknown flag
                if arg.starts_with('-') {
                    eprintln!("Unknown flag: {}", arg);
                    print_usage(&args[0]);
                    process::exit(1);
                } else {
                    // This should be the directory path
                    if directory_path.is_some() {
                        eprintln!("Error: Multiple directory paths specified. Only one directory can be scanned at a time.");
                        print_usage(&args[0]);
                        process::exit(1);
                    }
                    directory_path = Some(arg.to_string());
                }
            }
        }
        i += 1;
    }
    
    // Ensure we have a directory path
    let path_str = match directory_path {
        Some(path) => path,
        None => {
            eprintln!("Error: No directory path specified.");
            print_usage(&args[0]);
            process::exit(1);
        }
    };
    
    let path_obj = Path::new(&path_str);
    
    // Validate conflicting options
    if tree_mode && analysis_mode {
        eprintln!("Error: Cannot use --tree and --analyze together");
        process::exit(1);
    }
    
    // Execute based on mode
    match (tree_mode, analysis_mode) {
        (true, false) => print_tree_mode(path_obj, colorize, fast_mode),
        (false, true) => print_analysis_mode(path_obj),
        (false, false) => print_detailed_mode(path_obj, fast_mode),
        (true, true) => unreachable!(), // Already handled above
    }
}

fn print_tree_mode(path: &Path, colorize: bool, fast_mode: bool) {
    println!("Directory tree for: {}", path.display());
    
    let progress_callback = create_progress_callback();
    
    let tree_result = if fast_mode {
        let scanner = ScannerPresets::minimal();
        scanner.scan_tree_with_progress(path, Some(progress_callback))
    } else {
        scan_directory_tree_with_progress(path, progress_callback)
    };
    
    match tree_result {
        Ok(tree) => {
            let output = format_tree_output(&tree, colorize);
            print!("{}", output);
        }
        Err(e) => {
            eprintln!("Error scanning directory: {}", e);
            process::exit(1);
        }
    }
}

fn print_detailed_mode(path: &Path, fast_mode: bool) {
    println!("Directory scan results for: {}", path.display());
    println!("{:-<100}", "");
    
    if fast_mode {
        println!("{:<30} {:<50} {:<12} {:<25} {:<20}", 
                 "File Name", "Full Path", "Size (bytes)", "Last Modified", "SHA256");
    } else {
        println!("{:<30} {:<50} {:<12} {:<25} {:<64}", 
                 "File Name", "Full Path", "Size (bytes)", "Last Modified", "SHA256");
    }
    println!("{:-<100}", "");
    
    let progress_callback = create_progress_callback();
    
    let files_result = if fast_mode {
        let scanner = ScannerPresets::minimal();
        scan_with_options_and_progress(path, scanner, progress_callback)
    } else {
        scan_directory_detailed_with_progress(path, progress_callback)
    };
    
    match files_result {
        Ok(files) => {
            for file_info in files {
                let sha256_display = if fast_mode && file_info.sha256 == "Not calculated" {
                    "Not calculated".to_string()
                } else {
                    file_info.sha256
                };
                
                if fast_mode {
                    println!("{:<30} {:<50} {:<12} {:<25} {:<20}", 
                             truncate_string(&file_info.name, 29),
                             truncate_string(&file_info.full_path, 49),
                             file_info.size, 
                             file_info.last_modified,
                             truncate_string(&sha256_display, 19));
                } else {
                    println!("{:<30} {:<50} {:<12} {:<25} {:<64}", 
                             truncate_string(&file_info.name, 29),
                             truncate_string(&file_info.full_path, 49),
                             file_info.size, 
                             file_info.last_modified,
                             sha256_display);
                }
            }
        }
        Err(e) => {
            eprintln!("Error scanning directory: {}", e);
            process::exit(1);
        }
    }
}

fn print_analysis_mode(path: &Path) {
    println!("Analyzing directory: {}", path.display());
    
    let progress_callback = create_progress_callback();
    
    match analyze_directory_with_progress(path, false, Some(20), progress_callback) {
        Ok(analysis) => {
            println!("{}", analysis.summary());
            
            // Show largest file types
            if !analysis.file_type_counts.is_empty() {
                println!("Detailed breakdown by file type:");
                let mut sorted_types: Vec<_> = analysis.file_type_counts.iter().collect();
                sorted_types.sort_by(|a, b| b.1.cmp(a.1));
                
                for (file_type, count) in sorted_types.iter().take(10) {
                    println!("  {:12}: {:6} files", file_type.description(), count);
                }
                
                if sorted_types.len() > 10 {
                    println!("  ... and {} more types", sorted_types.len() - 10);
                }
            }
        }
        Err(e) => {
            eprintln!("Error analyzing directory: {}", e);
            process::exit(1);
        }
    }
}

/// Create a CLI progress callback that shows a progress bar
fn create_progress_callback() -> Arc<dyn Fn(f32, String) + Send + Sync> {
    Arc::new(|progress: f32, status: String| {
        // Clear the line
        print!("\r");
        
        // Create progress bar
        let width = 40;
        let filled = (width as f32 * progress) as usize;
        let empty = width - filled;
        let bar = "█".repeat(filled) + &"░".repeat(empty);
        
        // Print progress
        print!("[{}] {:>3.0}% {}", bar, progress * 100.0, status);
        
        // Flush to ensure immediate display
        io::stdout().flush().unwrap();
        
        // If complete, print newline
        if progress >= 1.0 {
            println!();
        }
    })
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <directory_path>", program_name);
    eprintln!("Try '{} --help' for more information.", program_name);
}

fn print_help(program_name: &str) {
    println!("Splendir - Recursively scan directories and display file information");
    println!();
    println!("USAGE:");
    println!("    {} [OPTIONS] <directory_path>", program_name);
    println!();
    println!("ARGUMENTS:");
    println!("    <directory_path>    Path to the directory to scan");
    println!();
    println!("OPTIONS:");
    println!("    --tree              Display results as a tree structure");
    println!("    -C                  Colorize the tree output (only works with --tree)");
    println!("    --fast              Fast mode - skip SHA256 calculation and limit depth");
    println!("    --analyze           Comprehensive directory analysis with statistics");
    println!("    -h, --help          Print this help information");
    println!();
    println!("EXAMPLES:");
    println!("    {} /home/user                    # Detailed file listing", program_name);
    println!("    {} --tree /home/user             # Tree view", program_name);
    println!("    {} --tree -C /home/user          # Colorized tree view", program_name);
    println!("    {} --fast /home/user             # Fast scan without SHA256", program_name);
    println!("    {} --analyze /home/user          # Comprehensive analysis", program_name);
    println!("    {} --help                        # Show this help message", program_name);
    println!();
    println!("MODES:");
    println!("    Default    : Shows detailed file information including SHA256 hashes");
    println!("    Tree       : Shows directory structure as a visual tree");
    println!("    Fast       : Quick scan without SHA256 calculation (faster for large dirs)");
    println!("    Analysis   : Comprehensive statistics and file type breakdown");
}
