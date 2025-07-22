use std::env;
use std::path::Path;
use std::process;

// Import from our library - now much simpler!
use directory_scanner::{
    scan_directory_detailed, 
    scan_directory_tree, 
    format_tree_output,
    analyze_directory,
    ScannerPresets,
    scan_with_options
};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let path = &args[1];
    let mut tree_mode = false;
    let mut colorize = false;
    let mut fast_mode = false;
    let mut analysis_mode = false;
    
    // Parse flags
    for arg in &args[2..] {
        match arg.as_str() {
            "--tree" => tree_mode = true,
            "-C" => colorize = true,
            "--fast" => fast_mode = true,
            "--analyze" => analysis_mode = true,
            "--help" | "-h" => {
                print_help(&args[0]);
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown flag: {}", arg);
                print_usage(&args[0]);
                process::exit(1);
            }
        }
    }
    
    let path_obj = Path::new(path);
    
    // Execute based on mode
    match (tree_mode, analysis_mode) {
        (true, false) => print_tree_mode(path_obj, colorize, fast_mode),
        (false, true) => print_analysis_mode(path_obj),
        (false, false) => print_detailed_mode(path_obj, fast_mode),
        (true, true) => {
            eprintln!("Error: Cannot use --tree and --analyze together");
            process::exit(1);
        }
    }
}

fn print_tree_mode(path: &Path, colorize: bool, fast_mode: bool) {
    println!("Directory tree for: {}", path.display());
    println!();
    
    let tree_result = if fast_mode {
        let scanner = ScannerPresets::fast();
        scanner.scan_tree(path)
    } else {
        scan_directory_tree(path)
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
    
    let files_result = if fast_mode {
        let scanner = ScannerPresets::fast();
        scan_with_options(path, scanner)
    } else {
        scan_directory_detailed(path)
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
    println!("Please wait...");
    println!();
    
    match analyze_directory(path, false, Some(20)) {
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

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <directory_path> [OPTIONS]", program_name);
    eprintln!("Try '{} --help' for more information.", program_name);
}

fn print_help(program_name: &str) {
    println!("Splendir - Recursively scan directories and display file information");
    println!();
    println!("USAGE:");
    println!("    {} <directory_path> [OPTIONS]", program_name);
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
    println!("    {} /home/user --tree             # Tree view", program_name);
    println!("    {} /home/user --tree -C          # Colorized tree view", program_name);
    println!("    {} /home/user --fast             # Fast scan without SHA256", program_name);
    println!("    {} /home/user --analyze          # Comprehensive analysis", program_name);
    println!();
    println!("MODES:");
    println!("    Default    : Shows detailed file information including SHA256 hashes");
    println!("    Tree       : Shows directory structure as a visual tree");
    println!("    Fast       : Quick scan without SHA256 calculation (faster for large dirs)");
    println!("    Analysis   : Comprehensive statistics and file type breakdown");
}
