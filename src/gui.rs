use iced::{
    widget::{button, checkbox, column, container, horizontal_space, pick_list, progress_bar, row, scrollable, text, text_input, Column},
    Alignment, Element, Length, Theme, Task, Font, time,
};
use rfd::FileDialog;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};

use directory_scanner::{
    analyze_directory_with_progress, format_tree_output, scan_directory_tree_with_progress,
    DirectoryScanner, FileInfo, ProgressCallback,
};

pub fn run() -> iced::Result {
    iced::application("Splendir - Directory Scanner", update, view)
        .theme(|_| Theme::Dark)
        .subscription(subscription)
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Detailed,
    Tree,
    Analysis,
}

impl ScanMode {
    const ALL: [ScanMode; 3] = [ScanMode::Detailed, ScanMode::Tree, ScanMode::Analysis];
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Detailed => write!(f, "Detailed File List"),
            ScanMode::Tree => write!(f, "Tree View"),
            ScanMode::Analysis => write!(f, "Directory Analysis"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanPreset {
    Default,
    Fast,
    Complete,
    Security,
}

impl ScanPreset {
    const ALL: [ScanPreset; 4] = [
        ScanPreset::Default,
        ScanPreset::Fast,
        ScanPreset::Complete,
        ScanPreset::Security,
    ];
}

impl std::fmt::Display for ScanPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPreset::Default => write!(f, "Default"),
            ScanPreset::Fast => write!(f, "Fast (No hashes)"),
            ScanPreset::Complete => write!(f, "Complete (All features)"),
            ScanPreset::Security => write!(f, "Security (With hashes)"),
        }
    }
}

// Shared progress state for communication between threads
type ProgressState = Arc<Mutex<Option<(f32, String)>>>;

#[derive(Default)]
struct SplendirGui {
    // UI State
    selected_path: String,
    scan_mode: ScanMode,
    scan_preset: ScanPreset,
    include_hidden: bool,
    follow_symlinks: bool,
    calculate_hashes: bool,
    colorize_output: bool,
    max_depth: String,
    
    // Scan State
    is_scanning: bool,
    scan_progress: f32,
    scan_status: String,
    
    // Results
    scan_results: ScanResults,
    
    // Error state
    error_message: Option<String>,
    
    // Progress tracking
    progress_state: Option<ProgressState>,
}

impl Default for ScanMode {
    fn default() -> Self {
        ScanMode::Detailed
    }
}

impl Default for ScanPreset {
    fn default() -> Self {
        ScanPreset::Default
    }
}

#[derive(Debug, Clone, Default)]
struct ScanResults {
    detailed_files: Vec<FileInfo>,
    tree_output: String,
    analysis_output: String,
    scan_time: Option<f32>,
}

#[derive(Debug, Clone)]
enum Message {
    // UI Events
    PathChanged(String),
    BrowsePressed,
    PathSelected(Option<PathBuf>),
    ScanModeSelected(ScanMode),
    PresetSelected(ScanPreset),
    IncludeHiddenToggled(bool),
    FollowSymlinksToggled(bool),
    CalculateHashesToggled(bool),
    ColorizeOutputToggled(bool),
    MaxDepthChanged(String),
    
    // Scan Events
    StartScan,
    UpdateProgress,
    ScanComplete(ScanResults),
    ScanError(String),
    
    // Export Events
    ExportResults,
    ExportComplete(Result<String, String>),
}

fn update(state: &mut SplendirGui, message: Message) -> Task<Message> {
    match message {
        Message::PathChanged(path) => {
            state.selected_path = path;
            state.error_message = None;
        }
        Message::BrowsePressed => {
            return Task::perform(
                async {
                    FileDialog::new()
                        .set_title("Select Directory to Scan")
                        .pick_folder()
                },
                Message::PathSelected,
            );
        }
        Message::PathSelected(path) => {
            if let Some(path) = path {
                state.selected_path = path.to_string_lossy().to_string();
                state.error_message = None;
            }
        }
        Message::ScanModeSelected(mode) => {
            state.scan_mode = mode;
        }
        Message::PresetSelected(preset) => {
            state.scan_preset = preset.clone();
            // Update options based on preset
            match preset {
                ScanPreset::Fast => {
                    state.calculate_hashes = false;
                    state.max_depth = "3".to_string();
                }
                ScanPreset::Complete => {
                    state.include_hidden = true;
                    state.follow_symlinks = true;
                    state.calculate_hashes = true;
                    state.max_depth = String::new();
                }
                ScanPreset::Security => {
                    state.include_hidden = true;
                    state.follow_symlinks = false;
                    state.calculate_hashes = true;
                    state.max_depth = String::new();
                }
                ScanPreset::Default => {
                    state.include_hidden = false;
                    state.follow_symlinks = false;
                    state.calculate_hashes = true;
                    state.max_depth = String::new();
                }
            }
        }
        Message::IncludeHiddenToggled(value) => {
            state.include_hidden = value;
        }
        Message::FollowSymlinksToggled(value) => {
            state.follow_symlinks = value;
        }
        Message::CalculateHashesToggled(value) => {
            state.calculate_hashes = value;
        }
        Message::ColorizeOutputToggled(value) => {
            state.colorize_output = value;
        }
        Message::MaxDepthChanged(value) => {
            state.max_depth = value;
        }
        Message::StartScan => {
            if state.selected_path.is_empty() {
                state.error_message = Some("Please select a directory to scan".to_string());
                return Task::none();
            }
            
            let path = PathBuf::from(&state.selected_path);
            if !path.exists() {
                state.error_message = Some("Selected path does not exist".to_string());
                return Task::none();
            }
            
            if !path.is_dir() {
                state.error_message = Some("Selected path is not a directory".to_string());
                return Task::none();
            }
            
            state.is_scanning = true;
            state.scan_progress = 0.0;
            state.scan_status = "Starting scan...".to_string();
            state.error_message = None;
            
            // Create progress state for communication
            let progress_state = Arc::new(Mutex::new(None));
            state.progress_state = Some(progress_state.clone());
            
            let scanner = create_scanner(state);
            let scan_mode = state.scan_mode.clone();
            let colorize = state.colorize_output;
            
            return Task::perform(
                perform_scan_with_progress(path, scanner, scan_mode, colorize, progress_state),
                |result| match result {
                    Ok(results) => Message::ScanComplete(results),
                    Err(err) => Message::ScanError(err),
                },
            );
        }
        Message::UpdateProgress => {
            if let Some(ref progress_state) = state.progress_state {
                if let Ok(guard) = progress_state.lock() {
                    if let Some((progress, status)) = &*guard {
                        state.scan_progress = *progress;
                        state.scan_status = status.clone();
                    }
                }
            }
        }
        Message::ScanComplete(results) => {
            state.is_scanning = false;
            state.scan_results = results;
            state.scan_status = format!(
                "Scan completed in {:.2}s",
                state.scan_results.scan_time.unwrap_or(0.0)
            );
            state.progress_state = None;
        }
        Message::ScanError(error) => {
            state.is_scanning = false;
            state.error_message = Some(error);
            state.scan_status = "Scan failed".to_string();
            state.progress_state = None;
        }
        Message::ExportResults => {
            if state.scan_results.detailed_files.is_empty() 
                && state.scan_results.tree_output.is_empty() 
                && state.scan_results.analysis_output.is_empty() {
                state.error_message = Some("No results to export".to_string());
                return Task::none();
            }
            
            let results = state.scan_results.clone();
            let mode = state.scan_mode.clone();
            
            return Task::perform(
                async move {
                    let file_dialog = FileDialog::new()
                        .set_title("Export Scan Results")
                        .add_filter("Text files", &["txt"])
                        .add_filter("CSV files", &["csv"])
                        .save_file();
                    
                    if let Some(path) = file_dialog {
                        export_results(path, results, mode).await
                    } else {
                        Err("Export cancelled".to_string())
                    }
                },
                Message::ExportComplete,
            );
        }
        Message::ExportComplete(result) => {
            match result {
                Ok(path) => {
                    state.scan_status = format!("Results exported to: {}", path);
                }
                Err(error) => {
                    state.error_message = Some(format!("Export failed: {}", error));
                }
            }
        }
    }
    
    Task::none()
}

fn view(state: &SplendirGui) -> Element<Message> {
    let header = view_header(state);
    let options = view_options(state);
    let results = view_results(state);
    
    let content = column![
        header,
        container(options).padding(20),
        if state.is_scanning {
            container(view_progress(state)).padding(20)
        } else if let Some(error) = &state.error_message {
            container(
                text(error)
                    .size(16)
                    .color(iced::Color::from_rgb(0.8, 0.2, 0.2))
            ).padding(20)
        } else {
            container(results).padding(20)
        }
    ]
    .spacing(10);
    
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(20)
        .into()
}

fn subscription(state: &SplendirGui) -> iced::Subscription<Message> {
    if state.is_scanning {
        time::every(Duration::from_millis(100))
            .map(|_| Message::UpdateProgress)
    } else {
        iced::Subscription::none()
    }
}

fn create_scanner(state: &SplendirGui) -> DirectoryScanner {
    let mut scanner = DirectoryScanner::new()
        .include_hidden(state.include_hidden)
        .follow_symlinks(state.follow_symlinks)
        .calculate_hashes(state.calculate_hashes);
    
    if let Ok(depth) = state.max_depth.parse::<usize>() {
        scanner = scanner.max_depth(depth);
    }
    
    scanner
}

fn view_header(state: &SplendirGui) -> Element<Message> {
    let title = text("Splendir Directory Scanner")
        .size(28)
        .color(iced::Color::from_rgb(0.2, 0.6, 0.8));
    
    let path_input = text_input("Select a directory to scan...", &state.selected_path)
        .on_input(Message::PathChanged)
        .padding(10)
        .size(16);
    
    let browse_button = button("Browse...")
        .on_press(Message::BrowsePressed)
        .padding([10, 20]);
    
    let scan_button = button("Start Scan")
        .on_press_maybe(if !state.is_scanning { Some(Message::StartScan) } else { None })
        .padding([10, 20]);
    
    column![
        container(title).width(Length::Fill).center_x(Length::Fill),
        row![
            path_input,
            browse_button,
            scan_button,
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    ]
    .spacing(20)
    .into()
}

fn view_options(state: &SplendirGui) -> Element<Message> {
    let mode_picker = pick_list(
        &ScanMode::ALL[..],
        Some(state.scan_mode.clone()),
        Message::ScanModeSelected,
    )
    .placeholder("Select scan mode");
    
    let preset_picker = pick_list(
        &ScanPreset::ALL[..],
        Some(state.scan_preset.clone()),
        Message::PresetSelected,
    )
    .placeholder("Select preset");
    
    let depth_input = text_input("Max depth", &state.max_depth)
        .on_input(Message::MaxDepthChanged)
        .width(Length::Fixed(100.0))
        .padding(8);
    
    let options_row1 = row![
        text("Mode:").size(16),
        mode_picker,
        horizontal_space(),
        text("Preset:").size(16),
        preset_picker,
        horizontal_space(),
        text("Max Depth:").size(16),
        depth_input,
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    
    let options_row2 = row![
        checkbox("Include hidden files", state.include_hidden).on_toggle(Message::IncludeHiddenToggled),
        horizontal_space().width(20),
        checkbox("Follow symlinks", state.follow_symlinks).on_toggle(Message::FollowSymlinksToggled),
        horizontal_space().width(20),
        checkbox("Calculate SHA256", state.calculate_hashes).on_toggle(Message::CalculateHashesToggled),
        horizontal_space().width(20),
        checkbox("Colorize output", state.colorize_output).on_toggle(Message::ColorizeOutputToggled),
    ]
    .spacing(5)
    .align_y(Alignment::Center);
    
    column![options_row1, options_row2]
        .spacing(15)
        .into()
}

fn view_progress(state: &SplendirGui) -> Element<Message> {
    column![
        text(&state.scan_status).size(18),
        progress_bar(0.0..=1.0, state.scan_progress),
    ]
    .spacing(10)
    .into()
}

fn view_results(state: &SplendirGui) -> Element<Message> {
    if state.scan_results.detailed_files.is_empty() 
        && state.scan_results.tree_output.is_empty() 
        && state.scan_results.analysis_output.is_empty() {
        return container(
            text("No scan results yet. Select a directory and click 'Start Scan'.")
                .size(16)
                .color(iced::Color::from_rgb(0.5, 0.5, 0.5))
        )
        .into();
    }
    
    let status_row = row![
        text(&state.scan_status).size(16),
        horizontal_space(),
        button("Export Results")
            .on_press(Message::ExportResults)
            .padding([8, 16]),
    ]
    .align_y(Alignment::Center);
    
    let results_content = match state.scan_mode {
        ScanMode::Detailed => view_detailed_results(state),
        ScanMode::Tree => view_tree_results(state),
        ScanMode::Analysis => view_analysis_results(state),
    };
    
    column![
        status_row,
        container(results_content)
            .width(Length::Fill)
            .height(Length::Fill)
    ]
    .spacing(10)
    .into()
}

fn view_detailed_results(state: &SplendirGui) -> Element<Message> {
    if state.scan_results.detailed_files.is_empty() {
        return text("No files found").into();
    }
    
    let total_files = state.scan_results.detailed_files.len();
    let file_count_text = text(format!("Total files: {}", total_files)).size(14);
    
    let header = row![
        text("Name").width(Length::FillPortion(3)),
        text("Size").width(Length::FillPortion(1)),
        text("Modified").width(Length::FillPortion(2)),
        text("SHA256").width(Length::FillPortion(3)),
    ]
    .spacing(10)
    .padding([10, 0]);
    
    // Limit displayed files to improve performance
    const MAX_DISPLAYED_FILES: usize = 1000;
    let displayed_files = if state.scan_results.detailed_files.len() > MAX_DISPLAYED_FILES {
        &state.scan_results.detailed_files[..MAX_DISPLAYED_FILES]
    } else {
        &state.scan_results.detailed_files
    };
    
    let mut file_rows = Column::new().spacing(2);
    
    for file in displayed_files {
        let row = row![
            text(&file.name).width(Length::FillPortion(3)).size(14),
            text(format_size(file.size)).width(Length::FillPortion(1)).size(14),
            text(&file.last_modified).width(Length::FillPortion(2)).size(14),
            text(if file.sha256.len() > 20 { 
                format!("{}...", &file.sha256[..20]) 
            } else { 
                file.sha256.clone() 
            }).width(Length::FillPortion(3)).size(14),
        ]
        .spacing(10)
        .padding([2, 0]);
        
        file_rows = file_rows.push(row);
    }
    
    let warning = if state.scan_results.detailed_files.len() > MAX_DISPLAYED_FILES {
        Some(text(format!(
            "Showing first {} of {} files. Export to file for complete list.", 
            MAX_DISPLAYED_FILES, 
            total_files
        ))
        .size(14)
        .color(iced::Color::from_rgb(0.8, 0.6, 0.2)))
    } else {
        None
    };
    
    let mut content = vec![
        file_count_text.into(),
        header.into(),
        scrollable(file_rows).height(Length::Fill).into(),
    ];
    
    if let Some(warning_text) = warning {
        content.push(warning_text.into());
    }
    
    Column::with_children(content)
        .spacing(10)
        .into()
}

fn view_tree_results(state: &SplendirGui) -> Element<Message> {
    if state.scan_results.tree_output.is_empty() {
        return text("No tree data available").into();
    }
    
    // Limit tree output for performance
    const MAX_TREE_CHARS: usize = 100_000;
    let display_output = if state.scan_results.tree_output.len() > MAX_TREE_CHARS {
        format!(
            "{}...\n\n[Tree output truncated - {} total characters. Export to file for complete output.]",
            &state.scan_results.tree_output[..MAX_TREE_CHARS],
            state.scan_results.tree_output.len()
        )
    } else {
        state.scan_results.tree_output.clone()
    };
    
    column![
        text(format!("Tree output ({} characters)", state.scan_results.tree_output.len()))
            .size(14),
        scrollable(
            text(display_output)
                .size(14)
                .font(Font::MONOSPACE)
        )
        .height(Length::Fill)
    ]
    .spacing(10)
    .into()
}

fn view_analysis_results(state: &SplendirGui) -> Element<Message> {
    if state.scan_results.analysis_output.is_empty() {
        return text("No analysis data available").into();
    }
    
    scrollable(
        text(&state.scan_results.analysis_output)
            .size(16)
    )
    .height(Length::Fill)
    .into()
}

async fn perform_scan_with_progress(
    path: PathBuf,
    scanner: DirectoryScanner,
    mode: ScanMode,
    colorize: bool,
    progress_state: ProgressState,
) -> Result<ScanResults, String> {
    let start_time = Instant::now();
    
    let result = tokio::task::spawn_blocking(move || {
        let mut results = ScanResults::default();
        
        // Create progress callback that updates the shared state
        let progress_callback: ProgressCallback = Arc::new(move |progress, status| {
            if let Ok(mut guard) = progress_state.lock() {
                *guard = Some((progress, status));
            }
        });
        
        match mode {
            ScanMode::Detailed => {
                match scanner.scan_detailed_with_progress(&path, Some(progress_callback)) {
                    Ok(files) => results.detailed_files = files,
                    Err(e) => return Err(format!("Scan failed: {}", e)),
                }
            }
            ScanMode::Tree => {
                match scan_directory_tree_with_progress(&path, progress_callback) {
                    Ok(tree) => {
                        results.tree_output = format_tree_output(&tree, colorize);
                    }
                    Err(e) => return Err(format!("Tree scan failed: {}", e)),
                }
            }
            ScanMode::Analysis => {
                match analyze_directory_with_progress(&path, scanner.include_hidden, scanner.max_depth, progress_callback) {
                    Ok(analysis) => {
                        results.analysis_output = analysis.summary();
                    }
                    Err(e) => return Err(format!("Analysis failed: {}", e)),
                }
            }
        }
        
        Ok(results)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?;
    
    match result {
        Ok(mut results) => {
            results.scan_time = Some(start_time.elapsed().as_secs_f32());
            Ok(results)
        }
        Err(e) => Err(e),
    }
}

fn format_size(size: u64) -> String {
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

async fn export_results(path: PathBuf, results: ScanResults, mode: ScanMode) -> Result<String, String> {
    use std::fs::File;
    use std::io::Write;
    
    tokio::task::spawn_blocking(move || {
        let mut file = File::create(&path)
            .map_err(|e| format!("Failed to create file: {}", e))?;
        
        match mode {
            ScanMode::Detailed => {
                // Export as CSV for detailed mode
                writeln!(file, "Name,Full Path,Size (bytes),Last Modified,SHA256")
                    .map_err(|e| format!("Failed to write header: {}", e))?;
                
                for file_info in &results.detailed_files {
                    writeln!(
                        file,
                        "\"{}\",\"{}\",{},\"{}\",\"{}\"",
                        file_info.name.replace("\"", "\"\""),
                        file_info.full_path.replace("\"", "\"\""),
                        file_info.size,
                        file_info.last_modified,
                        file_info.sha256
                    )
                    .map_err(|e| format!("Failed to write data: {}", e))?;
                }
            }
            ScanMode::Tree => {
                // Export tree as text
                write!(file, "{}", results.tree_output)
                    .map_err(|e| format!("Failed to write tree: {}", e))?;
            }
            ScanMode::Analysis => {
                // Export analysis as text
                write!(file, "{}", results.analysis_output)
                    .map_err(|e| format!("Failed to write analysis: {}", e))?;
            }
        }
        
        Ok(path.to_string_lossy().to_string())
    })
    .await
    .map_err(|e| format!("Export task failed: {}", e))?
}
