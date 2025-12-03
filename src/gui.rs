use iced::{
    widget::{button, checkbox, column, container, horizontal_space, pick_list, progress_bar, radio, row, scrollable, stack, text, text_input, Column, Space},
    Alignment, Element, Length, Theme, Task, Font, time,
};
use iced::window;
use rfd::FileDialog;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use directory_scanner::{
    analyze_directory_with_progress, format_tree_output, scan_directory_tree_with_progress,
    DirectoryScanner, FileInfo, ProgressCallback, TreeNode,
};

/// Version string read from Cargo.toml at compile time
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Generate an appropriate application title
const APP_TITLE: &str = concat!("Splendir v", env!("CARGO_PKG_VERSION"));

pub fn run() -> iced::Result {
    iced::application(APP_TITLE, update, view)
        .window(window::Settings {
            size: iced::Size::new(1150.0, 770.0),
            min_size: Some(iced::Size::new(900.0, 700.0)),
            ..Default::default()
        })
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
    DefaultMD5,
    DefaultSHA256,
    Minimal,
    Complete,
}

impl ScanPreset {
    const ALL: [ScanPreset; 5] = [
        ScanPreset::Default,
        ScanPreset::DefaultMD5,
        ScanPreset::DefaultSHA256,
        ScanPreset::Minimal,
        ScanPreset::Complete,
    ];
}

impl std::fmt::Display for ScanPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPreset::Default => write!(f, "Default"),
            ScanPreset::DefaultMD5 => write!(f, "Default+MD5"),
            ScanPreset::DefaultSHA256 => write!(f, "Default+SHA256"),
            ScanPreset::Minimal => write!(f, "Minimal"),
            ScanPreset::Complete => write!(f, "Complete"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortBy {
    TreeDefault,
    FileName,
    Size,
    Created,
    Accessed,
    Modified,
}

impl SortBy {
    const ALL: [SortBy; 6] = [
        SortBy::TreeDefault,
        SortBy::FileName,
        SortBy::Size,
        SortBy::Created,
        SortBy::Accessed,
        SortBy::Modified,
    ];
}

impl std::fmt::Display for SortBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortBy::TreeDefault => write!(f, "Default"),
            SortBy::FileName => write!(f, "File Name"),
            SortBy::Size => write!(f, "Size"),
            SortBy::Created => write!(f, "Created"),
            SortBy::Accessed => write!(f, "Accessed"),
            SortBy::Modified => write!(f, "Modified"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortOrder {
    Ascending,
    Descending,
}

impl std::fmt::Display for SortOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortOrder::Ascending => write!(f, "Ascending"),
            SortOrder::Descending => write!(f, "Descending"),
        }
    }
}

// Shared progress state for communication between threads
type ProgressState = Arc<Mutex<Option<(f32, String)>>>;

#[derive(Debug, Clone)]
struct ColumnVisibility {
    show_filename: bool,
    show_path: bool,
    show_path_name: bool,
    show_size: bool,
    show_created: bool,
    show_modified: bool,
    show_accessed: bool,
    show_format: bool,
    calculate_md5: bool,
    calculate_sha256: bool,
    calculate_sha512: bool,
    calculate_mime: bool,
}

struct SplendirGui {
    // UI State
    selected_path: String,
    scan_mode: ScanMode,
    scan_preset: ScanPreset,
    include_hidden: bool,
    follow_symlinks: bool,
    calculate_md5: bool,
    calculate_sha256: bool,
    calculate_sha512: bool,
    colorize_output: bool,
    max_depth: String,
    
    // Column visibility
    show_filename: bool,
    show_path: bool,
    show_path_name: bool,
    show_size: bool,
    show_created: bool,
    show_modified: bool,
    show_accessed: bool,
    show_format: bool,
    calculate_format: bool,
    calculate_mime: bool,
    
    // Sort options
    sort_by: SortBy,
    sort_order: SortOrder,
    
    // Scan State
    is_scanning: bool,
    scan_progress: f32,
    scan_status: String,
    
    // Results
    scan_results: ScanResults,
    
    // Error state
    error_message: Option<String>,
    
    // System messages (for non-critical info like export status)
    system_message: Option<String>,
    
    // Progress tracking
    progress_state: Option<ProgressState>,
    
    // Cancellation flag
    cancellation_flag: Option<Arc<AtomicBool>>,
    
    // Virtual scrolling state
    tree_scroll_offset: f32,
    tree_flattened_cache: Vec<FlatTreeNode>,
    detail_scroll_offset: f32,
    
    // Dialog state
    show_about: bool,
    
    // Column expansion state
    columns_expanded: bool,
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

impl Default for SplendirGui {
    fn default() -> Self {
        Self {
            selected_path: String::new(),
            scan_mode: ScanMode::default(),
            scan_preset: ScanPreset::default(),
            include_hidden: false,
            follow_symlinks: false,
            calculate_md5: false,
            calculate_sha256: false,
            calculate_sha512: false,
            colorize_output: false,
            max_depth: String::new(),
            
            // Default column visibility: File Name, Path, Size, Modified
            show_filename: true,
            show_path: true,
            show_path_name: false,
            show_size: true,
            show_created: false,
            show_modified: true,
            show_accessed: false,
            show_format: false,
            calculate_format: false,
            calculate_mime: false,
            
            // Sort options
            sort_by: SortBy::TreeDefault,
            sort_order: SortOrder::Ascending,
            
            is_scanning: false,
            scan_progress: 0.0,
            scan_status: String::new(),
            scan_results: ScanResults::default(),
            error_message: None,
            system_message: None,
            progress_state: None,
            cancellation_flag: None,
            tree_scroll_offset: 0.0,
            tree_flattened_cache: Vec::new(),
            detail_scroll_offset: 0.0,
            show_about: false,
            columns_expanded: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ScanResults {
    detailed_files: Vec<FileInfo>,
    original_order: Vec<FileInfo>, // Preserve original scan order
    tree_node: Option<TreeNode>,
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
    CalculateSHA256Toggled(bool),
    CalculateSHA512Toggled(bool),
    CalculateMD5Toggled(bool),
    ColorizeOutputToggled(bool),
    MaxDepthChanged(String),
    
    // Column visibility toggles
    ShowFilenameToggled(bool),
    ShowPathToggled(bool),
    ShowPathNameToggled(bool),
    ShowSizeToggled(bool),
    ShowCreatedToggled(bool),
    ShowModifiedToggled(bool),
    ShowAccessedToggled(bool),
    ShowFormatToggled(bool),
    CalculateMimeToggled(bool),
    
    // Sort options
    SortBySelected(SortBy),
    SortOrderSelected(SortOrder),
    
    // Scan Events
    StartScan,
    CancelScan,
    UpdateProgress,
    ScanComplete(ScanResults),
    ScanError(String),
    
    // Export Events
    ExportResults,
    ExportComplete(Result<String, String>),
    
    // Column expansion
    ToggleColumnExpansion,
    
    // Scrolling Events
    TreeScrolled(f32),
    DetailScrolled(f32),
    
    // Application Events
    ShowAbout,
    CloseAbout,
    Exit,
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
            
            // Update tree cache when switching to tree mode (if we have tree data)
            if mode == ScanMode::Tree && state.tree_flattened_cache.is_empty() {
                if let Some(ref tree_node) = state.scan_results.tree_node {
                    state.tree_flattened_cache = flatten_tree(tree_node, 0);
                }
            }
        }
        Message::PresetSelected(preset) => {
            state.scan_preset = preset.clone();
            // Update options based on preset
            match preset {
                ScanPreset::Minimal => {
                    state.calculate_md5 = false;
                    state.calculate_sha256 = false;
                    state.calculate_sha512 = false;
                    // state.max_depth = "3".to_string();
                    state.max_depth = String::new();
                    state.colorize_output = false;
                    // Minimal: minimal columns
                    state.show_filename = true;
                    state.show_path = true;
                    state.show_path_name = false;
                    state.show_size = true;
                    state.show_created = false;
                    state.show_modified = false;
                    state.show_accessed = false;
                    state.show_format = false;
                    state.calculate_mime = false;
                }
                ScanPreset::Complete => {
                    state.include_hidden = true;
                    state.follow_symlinks = true;
                    state.calculate_md5 = true;
                    state.calculate_sha256 = true;
                    state.calculate_sha512 = true;
                    state.max_depth = String::new();
                    state.colorize_output = false;
                    // Complete: all columns
                    state.show_filename = true;
                    state.show_path = true;
                    state.show_path_name = true;
                    state.show_size = true;
                    state.show_created = true;
                    state.show_modified = true;
                    state.show_accessed = true;
                    state.show_format = true;
                    state.calculate_format = true;
                    state.calculate_mime = true;
                }
                ScanPreset::Default => {
                    state.include_hidden = false;
                    state.follow_symlinks = false;
                    state.calculate_md5 = false;
                    state.calculate_sha256 = false;
                    state.calculate_sha512 = false;
                    state.max_depth = String::new();
                    state.colorize_output = false;
                    // Default: File Name, Path, Size, Modified
                    state.show_filename = true;
                    state.show_path = true;
                    state.show_path_name = false;
                    state.show_size = true;
                    state.show_created = false;
                    state.show_modified = true;
                    state.show_accessed = false;
                    state.show_format = false;
                    state.calculate_format = false;
                    state.calculate_mime = false;
                }
                ScanPreset::DefaultMD5 => {
                    state.include_hidden = false;
                    state.follow_symlinks = false;
                    state.calculate_md5 = true;
                    state.calculate_sha256 = false;
                    state.calculate_sha512 = false;
                    state.max_depth = String::new();
                    state.colorize_output = false;
                    // Default: File Name, Path, Size, Modified
                    state.show_filename = true;
                    state.show_path = true;
                    state.show_path_name = false;
                    state.show_size = true;
                    state.show_created = false;
                    state.show_modified = true;
                    state.show_accessed = false;
                    state.show_format = false;
                    state.calculate_format = false;
                    state.calculate_mime = false;
                }
                ScanPreset::DefaultSHA256 => {
                    state.include_hidden = false;
                    state.follow_symlinks = false;
                    state.calculate_md5 = false;
                    state.calculate_sha256 = true;
                    state.calculate_sha512 = false;
                    state.max_depth = String::new();
                    state.colorize_output = false;
                    // Default: File Name, Path, Size, Modified
                    state.show_filename = true;
                    state.show_path = true;
                    state.show_path_name = false;
                    state.show_size = true;
                    state.show_created = false;
                    state.show_modified = true;
                    state.show_accessed = false;
                    state.show_format = false;
                    state.calculate_format = false;
                    state.calculate_mime = false;
                }
            }
        }
        Message::IncludeHiddenToggled(value) => {
            state.include_hidden = value;
        }
        Message::FollowSymlinksToggled(value) => {
            state.follow_symlinks = value;
        }
        Message::CalculateMD5Toggled(value) => {
            state.calculate_md5 = value;
        }
        Message::CalculateSHA256Toggled(value) => {
            state.calculate_sha256 = value;
        }
        Message::CalculateSHA512Toggled(value) => {
            state.calculate_sha512 = value;
        }
        Message::ColorizeOutputToggled(value) => {
            state.colorize_output = value;
        }
        Message::MaxDepthChanged(value) => {
            state.max_depth = value;
        }
        Message::ShowFilenameToggled(value) => {
            state.show_filename = value;
        }
        Message::ShowPathToggled(value) => {
            state.show_path = value;
        }
        Message::ShowPathNameToggled(value) => {
            state.show_path_name = value;
        }
        Message::ShowSizeToggled(value) => {
            state.show_size = value;
        }
        Message::ShowCreatedToggled(value) => {
            state.show_created = value;
        }
        Message::ShowModifiedToggled(value) => {
            state.show_modified = value;
        }
        Message::ShowAccessedToggled(value) => {
            state.show_accessed = value;
        }
        Message::ShowFormatToggled(value) => {
            state.show_format = value;
            state.calculate_format = value;
        }
        Message::CalculateMimeToggled(value) => {
            state.calculate_mime = value;
        }
        Message::SortBySelected(sort_by) => {
            state.sort_by = sort_by;
            // Re-sort existing results if we have them
            if !state.scan_results.detailed_files.is_empty() {
                sort_files(
                    &mut state.scan_results.detailed_files, 
                    &state.scan_results.original_order,
                    state.sort_by, 
                    state.sort_order
                );
            }
        }
        Message::SortOrderSelected(sort_order) => {
            state.sort_order = sort_order;
            // Re-sort existing results if we have them
            if !state.scan_results.detailed_files.is_empty() {
                sort_files(
                    &mut state.scan_results.detailed_files, 
                    &state.scan_results.original_order,
                    state.sort_by, 
                    state.sort_order
                );
            }
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
            
            // Reset scroll positions
            state.tree_scroll_offset = 0.0;
            state.detail_scroll_offset = 0.0;
            state.tree_flattened_cache.clear();
            
            // Create progress state for communication
            let progress_state = Arc::new(Mutex::new(None));
            state.progress_state = Some(progress_state.clone());
            
            // Create cancellation flag
            let cancellation_flag = Arc::new(AtomicBool::new(false));
            state.cancellation_flag = Some(cancellation_flag.clone());
            
            let scanner = create_scanner(state).cancellation_flag(cancellation_flag);
            let colorize = state.colorize_output;
            
            // Note: we no longer pass scan_mode since we scan all modes
            return Task::perform(
                perform_scan_with_progress(path, scanner, ScanMode::Detailed, colorize, progress_state),
                |result| match result {
                    Ok(results) => Message::ScanComplete(results),
                    Err(err) => Message::ScanError(err),
                },
            );
        }
        Message::CancelScan => {
            if let Some(ref flag) = state.cancellation_flag {
                flag.store(true, Ordering::Relaxed);
                state.scan_status = "Cancelling scan...".to_string();
            }
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
        Message::ScanComplete(mut results) => {
            state.is_scanning = false;
            state.cancellation_flag = None;
            
            // Save original order before any sorting
            results.original_order = results.detailed_files.clone();
            
            // Sort files if we're not using tree default
            sort_files(&mut results.detailed_files, &results.original_order, state.sort_by, state.sort_order);
            
            // Update tree cache regardless of current mode (since we now have tree data)
            if let Some(ref tree_node) = results.tree_node {
                state.tree_flattened_cache = flatten_tree(tree_node, 0);
            }
            
            state.scan_results = results;
            state.scan_status = format!(
                "All scans completed in {:.2}s",
                state.scan_results.scan_time.unwrap_or(0.0)
            );
            state.progress_state = None;
        }
        Message::ScanError(error) => {
            state.is_scanning = false;
            state.cancellation_flag = None;
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
            let columns = ColumnVisibility {
                show_filename: state.show_filename,
                show_path: state.show_path,
                show_path_name: state.show_path_name,
                show_size: state.show_size,
                show_created: state.show_created,
                show_modified: state.show_modified,
                show_accessed: state.show_accessed,
                show_format: state.show_format,
                calculate_md5: state.calculate_md5,
                calculate_sha256: state.calculate_sha256,
                calculate_sha512: state.calculate_sha512,
                calculate_mime: state.calculate_mime,
            };
            
            return Task::perform(
                async move {
                    let file_dialog = FileDialog::new()
                        .set_title("Export Scan Results")
                        .add_filter("Text files", &["txt"])
                        .add_filter("CSV files", &["csv"])
                        .save_file();
                    
                    if let Some(path) = file_dialog {
                        export_results(path, results, mode, columns).await
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
                    state.system_message = Some(format!("Results exported to: {}", path));
                }
                Err(error) => {
                    // Don't show "Export cancelled" as an error
                    if error != "Export cancelled" {
                        state.system_message = Some(format!("Export failed: {}", error));
                    }
                }
            }
        }
        Message::ToggleColumnExpansion => {
            state.columns_expanded = !state.columns_expanded;
            
            // Restore scroll position after toggling
            let offset = state.detail_scroll_offset;
            return scrollable::snap_to(
                scrollable::Id::new("detailed_results_scroll"),
                scrollable::RelativeOffset { x: 0.0, y: offset }
            );
        }
        Message::TreeScrolled(offset) => {
            state.tree_scroll_offset = offset;
        }
        Message::DetailScrolled(offset) => {
            state.detail_scroll_offset = offset;
        }
        Message::ShowAbout => {
            state.show_about = true;
        }
        Message::CloseAbout => {
            state.show_about = false;
        }
        Message::Exit => {
            // Cancel any running scan before exiting
            if let Some(ref flag) = state.cancellation_flag {
                flag.store(true, Ordering::Relaxed);
            }
            return window::get_latest().and_then(window::close);
        }
    }
    
    Task::none()
}

fn view(state: &SplendirGui) -> Element<'_, Message> {
    let header = view_header(state);
    let options = view_options(state);
    let results = view_results(state);
    
    // Options sidebar and main content area side by side
    let main_row = row![
        container(options).padding(20),
        iced::widget::vertical_rule(1),
        container(
            if state.is_scanning {
                container(view_progress(state)).padding(20)
            } else if let Some(error) = &state.error_message {
                container(
                    text(error)
                        .size(14)
                        .color(iced::Color::from_rgb(0.8, 0.2, 0.2))
                ).padding(20)
            } else {
                container(results).padding(20)
            }
        )
        .width(Length::Fill)
    ]
    .spacing(0);
    
    let content = column![
        header,
        main_row,
    ]
    .spacing(10);
    
    // Bottom row with system messages on left and version on right
    let message_text = if let Some(ref msg) = state.system_message {
        format!("Messages: {}", msg)
    } else {
        "Messages:".to_string()
    };
    
    let bottom_row = row![
        text(message_text)
            .size(12)
            .color(iced::Color::from_rgb(0.7, 0.7, 0.7)),
        horizontal_space(),
        text(format!("Splendir v{}", VERSION))
            .size(12)
            .color(iced::Color::from_rgb(0.5, 0.5, 0.5)),
        Space::with_width(Length::Fixed(20.0)),
        button(text("About").size(14))
            .on_press(Message::ShowAbout)
            .padding([5, 10]),
        Space::with_width(Length::Fixed(10.0)),
        button(text("Exit").size(14))
            .on_press(Message::Exit)
            .padding([5, 10]),
    ]
    .padding(10)
    .align_y(Alignment::Center);
    
    // Main content with bottom row
    let main_content = column![
        content,
        bottom_row,
    ]
    .spacing(0);
    
    let base_view = container(main_content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(15);
    
    // If showing about dialog, overlay it on top
    if state.show_about {
        iced::widget::stack![
            base_view,
            view_about_dialog()
        ]
        .into()
    } else {
        base_view.into()
    }
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
        .calculate_sha256(state.calculate_sha256)
        .calculate_sha512(state.calculate_sha512)
        .calculate_md5(state.calculate_md5)
        .calculate_format(state.calculate_format)
        .calculate_mime(state.calculate_mime);
    
    if let Ok(depth) = state.max_depth.parse::<usize>() {
        scanner = scanner.max_depth(depth);
    }
    
    scanner
}

fn view_header(state: &SplendirGui) -> Element<'_, Message> {
    let path_input = text_input("Select a directory to scan...", &state.selected_path)
        .on_input(Message::PathChanged)
        .padding(10)
        .size(14);
    
    let browse_button = button("Browse...")
        .on_press(Message::BrowsePressed)
        .padding([10, 20]);
    
    let scan_button = button("Start Scan")
        .on_press_maybe(if !state.is_scanning { Some(Message::StartScan) } else { None })
        .padding([10, 20]);
    
    let cancel_button = button("Cancel")
        .on_press_maybe(if state.is_scanning { Some(Message::CancelScan) } else { None })
        .padding([10, 20]);
    
    row![
        path_input,
        browse_button,
        scan_button,
        cancel_button,
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .into()
}

fn view_options(state: &SplendirGui) -> Element<'_, Message> {
    // Settings section
    let settings_section = column![
        text("Settings").size(16).font(Font { weight: iced::font::Weight::Bold, ..Font::default() }).color(iced::Color::from_rgb(0.9, 0.9, 0.9)),
        column![
            row![text("Mode:").width(80), pick_list(
                &ScanMode::ALL[..],
                Some(state.scan_mode.clone()),
                Message::ScanModeSelected,
            )].spacing(10),
            row![text("Preset:").width(80), pick_list(
                &ScanPreset::ALL[..],
                Some(state.scan_preset.clone()),
                Message::PresetSelected,
            )].spacing(10),
        ].spacing(10)
    ]
    .spacing(10);
    
    // Traversal Options section
    let traversal_section = column![
        text("Traversal Options").size(16).font(Font { weight: iced::font::Weight::Bold, ..Font::default() }).color(iced::Color::from_rgb(0.9, 0.9, 0.9)),
        column![
            checkbox("Include hidden files", state.include_hidden).on_toggle(Message::IncludeHiddenToggled),
            checkbox("Follow symlinks", state.follow_symlinks).on_toggle(Message::FollowSymlinksToggled),
            row![text("Max Depth:").width(80), text_input("", &state.max_depth)
                .on_input(Message::MaxDepthChanged)
                .width(Length::Fixed(100.0))
                .padding(8)
            ].spacing(10),
        ].spacing(8)
    ]
    .spacing(10);
    
    // File Options section - two column layout
    let file_options_col1 = column![
        checkbox("File Name", state.show_filename).on_toggle(Message::ShowFilenameToggled),
        checkbox("Path", state.show_path).on_toggle(Message::ShowPathToggled),
        checkbox("Path + Name", state.show_path_name).on_toggle(Message::ShowPathNameToggled),
        checkbox("Size", state.show_size).on_toggle(Message::ShowSizeToggled),
        checkbox("Created", state.show_created).on_toggle(Message::ShowCreatedToggled),
        checkbox("Modified", state.show_modified).on_toggle(Message::ShowModifiedToggled),
        checkbox("Accessed", state.show_accessed).on_toggle(Message::ShowAccessedToggled),
    ].spacing(8);
    
    let file_options_col2 = column![
        checkbox("Format", state.show_format).on_toggle(Message::ShowFormatToggled),
        checkbox("MIME Type", state.calculate_mime).on_toggle(Message::CalculateMimeToggled),
        checkbox("MD5", state.calculate_md5).on_toggle(Message::CalculateMD5Toggled),
        checkbox("SHA256", state.calculate_sha256).on_toggle(Message::CalculateSHA256Toggled),
        checkbox("SHA512", state.calculate_sha512).on_toggle(Message::CalculateSHA512Toggled),
    ].spacing(8);
    
    let file_options_section = column![
        text("File Options").size(16).font(Font { weight: iced::font::Weight::Bold, ..Font::default() }).color(iced::Color::from_rgb(0.9, 0.9, 0.9)),
        row![
            file_options_col1,
            file_options_col2,
        ].spacing(15)
    ]
    .spacing(10);
    
    // Sort Options section
    let sort_options_section = column![
        text("Sort Options").size(16).font(Font { weight: iced::font::Weight::Bold, ..Font::default() }).color(iced::Color::from_rgb(0.9, 0.9, 0.9)),
        row![
            pick_list(
                &SortBy::ALL[..],
                Some(state.sort_by),
                Message::SortBySelected
            ),
            column![
                iced::widget::radio(
                    "Ascending",
                    SortOrder::Ascending,
                    Some(state.sort_order),
                    Message::SortOrderSelected
                ),
                iced::widget::radio(
                    "Descending",
                    SortOrder::Descending,
                    Some(state.sort_order),
                    Message::SortOrderSelected
                ),
            ].spacing(5)
        ].spacing(10)
    ]
    .spacing(10);
    
    // Left sidebar with all options and horizontal separators - make scrollable
    scrollable(
        column![
            settings_section,
            iced::widget::horizontal_rule(1),
            traversal_section,
            iced::widget::horizontal_rule(1),
            file_options_section,
            iced::widget::horizontal_rule(1),
            sort_options_section,
        ]
        .spacing(10)
    )
    .width(Length::Fixed(285.0))
    .into()
}

fn view_progress(state: &SplendirGui) -> Element<'_, Message> {
    column![
        text(&state.scan_status).size(18),
        progress_bar(0.0..=1.0, state.scan_progress),
    ]
    .spacing(10)
    .into()
}

fn view_results(state: &SplendirGui) -> Element<'_, Message> {
    if state.scan_results.detailed_files.is_empty() 
        && state.scan_results.tree_node.is_none()
        && state.scan_results.analysis_output.is_empty() {
        return container(
            text("No scan results yet. Select a directory and click 'Start Scan'.")
                .size(14)
                .color(iced::Color::from_rgb(0.5, 0.5, 0.5))
        )
        .into();
    }
    
    let mut status_row = row![
        text(&state.scan_status).size(14),
        horizontal_space(),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    
    // Only show Expand/Collapse Columns button in Detailed mode
    if state.scan_mode == ScanMode::Detailed {
        status_row = status_row.push(
            button(if state.columns_expanded { "Collapse Columns" } else { "Expand Columns" })
                .on_press(Message::ToggleColumnExpansion)
                .padding([8, 16])
        );
    }
    
    status_row = status_row.push(
        button("Export Results")
            .on_press(Message::ExportResults)
            .padding([8, 16])
    );
    
    let results_content = match state.scan_mode {
        ScanMode::Detailed => view_detailed_results_virtual(state),
        ScanMode::Tree => view_tree_results_virtual(state),
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

// Virtual scrolling for detailed results with conditional sticky header
fn view_detailed_results_virtual(state: &SplendirGui) -> Element<'_, Message> {
    if state.scan_results.detailed_files.is_empty() {
        return text("No files found").into();
    }
    
    const ROW_HEIGHT: f32 = 25.0;
    const VIEWPORT_HEIGHT: f32 = 2000.0; // Larger default to handle maximized windows
    const VISIBLE_ROWS: usize = (VIEWPORT_HEIGHT / ROW_HEIGHT) as usize + 2;
    
    let total_files = state.scan_results.detailed_files.len();
    
    let file_count_text = text(format!("Total files: {}", total_files)).size(14);
    
    // Calculate actual widths based on content when expanded
    let (filename_width, path_width, fullpath_width, standard_width, size_width) = if state.columns_expanded {
        let max_filename_len = state.scan_results.detailed_files.iter()
            .map(|f| f.name.chars().count())
            .max()
            .unwrap_or(10);
        let max_path_len = state.scan_results.detailed_files.iter()
            .map(|f| f.directory_path.chars().count())
            .max()
            .unwrap_or(20);
        let max_fullpath_len = state.scan_results.detailed_files.iter()
            .map(|f| f.full_path.chars().count())
            .max()
            .unwrap_or(30);
        
        // Character width and padding
        let char_width = 7.0;
        let padding = 10.0;
        
        let fn_width = Length::Fixed((max_filename_len as f32 * char_width + padding).max(150.0));
        let p_width = Length::Fixed((max_path_len as f32 * char_width + padding).max(200.0));
        let fp_width = Length::Fixed((max_fullpath_len as f32 * char_width + padding).max(250.0));
        let std_width = Length::Fixed(200.0);
        let sz_width = Length::Fixed(100.0);
        
        (fn_width, p_width, fp_width, std_width, sz_width)
    } else {
        (
            Length::FillPortion(2),
            Length::FillPortion(3),
            Length::FillPortion(3),
            Length::FillPortion(2),
            Length::FillPortion(1),
        )
    };
    
    // Build header row
    let mut header_row = row![].spacing(10).padding([0, 10]).height(Length::Fixed(30.0)).align_y(Alignment::Center);
    
    if state.show_filename {
        header_row = header_row.push(text("File").width(filename_width).size(15));
    }
    if state.show_path {
        header_row = header_row.push(text("Path").width(path_width).size(15));
    }
    if state.show_path_name {
        header_row = header_row.push(text("Path + Name").width(fullpath_width).size(15));
    }
    if state.show_size {
        header_row = header_row.push(text("Size").width(size_width).size(15));
    }
    if state.show_created {
        header_row = header_row.push(text("Created").width(standard_width).size(15));
    }
    if state.show_modified {
        header_row = header_row.push(text("Modified").width(standard_width).size(15));
    }
    if state.show_accessed {
        header_row = header_row.push(text("Accessed").width(standard_width).size(15));
    }
    if state.show_format {
        header_row = header_row.push(text("Format").width(standard_width).size(15));
    }
    if state.calculate_mime {
        header_row = header_row.push(text("MIME Type").width(standard_width).size(15));
    }
    if state.calculate_md5 {
        header_row = header_row.push(text("MD5").width(standard_width).size(15));
    }
    if state.calculate_sha256 {
        header_row = header_row.push(text("SHA256").width(standard_width).size(15));
    }
    if state.calculate_sha512 {
        header_row = header_row.push(text("SHA512").width(standard_width).size(15));
    }
    
    // Calculate visible range for virtual scrolling
    let scroll_offset = state.detail_scroll_offset.max(0.0);
    let start_index = (scroll_offset / ROW_HEIGHT) as usize;
    let end_index = (start_index + VISIBLE_ROWS).min(total_files);
    
    // Calculate total content width when expanded
    let total_content_width = if state.columns_expanded {
        let mut width = 0.0;
        if state.show_filename { if let Length::Fixed(w) = filename_width { width += w; } }
        if state.show_path { if let Length::Fixed(w) = path_width { width += w; } }
        if state.show_path_name { if let Length::Fixed(w) = fullpath_width { width += w; } }
        if state.show_size { if let Length::Fixed(w) = size_width { width += w; } }
        if state.show_created { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.show_modified { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.show_accessed { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.show_format { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.calculate_mime { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.calculate_md5 { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.calculate_sha256 { if let Length::Fixed(w) = standard_width { width += w; } }
        if state.calculate_sha512 { if let Length::Fixed(w) = standard_width { width += w; } }
        
        // Add spacing between columns (10px per gap)
        let visible_columns = [
            state.show_filename, state.show_path, state.show_path_name, state.show_size,
            state.show_created, state.show_modified, state.show_accessed, state.show_format,
            state.calculate_mime, state.calculate_md5, state.calculate_sha256, state.calculate_sha512
        ].iter().filter(|&&x| x).count();
        width += (visible_columns.saturating_sub(1) * 10) as f32;
        
        // Add padding
        width += 20.0;
        
        Some(width)
    } else {
        None
    };
    
    // Build rows based on whether columns are expanded
    let table_view: Element<'_, Message> = if state.columns_expanded {
        // EXPANDED MODE: Header scrolls with content (no sticky), single scrollable with Both direction
        let mut viewport = Column::new().spacing(0).width(Length::Fixed(total_content_width.unwrap()));
        
        // Add header to viewport
        viewport = viewport.push(header_row);
        
        // Add spacer for items above viewport
        if start_index > 0 {
            viewport = viewport.push(Space::new(Length::Fill, start_index as f32 * ROW_HEIGHT));
        }
        
        // Add visible rows
        for i in start_index..end_index {
            if let Some(file) = state.scan_results.detailed_files.get(i) {
                let mut data_row = row![].spacing(10).padding([0, 10]).height(ROW_HEIGHT).align_y(Alignment::Center);
                
                if state.show_filename {
                    data_row = data_row.push(text(&file.name).width(filename_width).size(14));
                }
                if state.show_path {
                    data_row = data_row.push(text(&file.directory_path).width(path_width).size(14));
                }
                if state.show_path_name {
                    data_row = data_row.push(text(&file.full_path).width(fullpath_width).size(14));
                }
                if state.show_size {
                    data_row = data_row.push(text(format_size(file.size)).width(size_width).size(14));
                }
                if state.show_created {
                    data_row = data_row.push(text(&file.created).width(standard_width).size(14));
                }
                if state.show_modified {
                    data_row = data_row.push(text(&file.last_modified).width(standard_width).size(14));
                }
                if state.show_accessed {
                    data_row = data_row.push(text(&file.last_accessed).width(standard_width).size(14));
                }
                if state.show_format {
                    data_row = data_row.push(text(&file.format).width(standard_width).size(14));
                }
                if state.calculate_mime {
                    data_row = data_row.push(text(&file.mime_type).width(standard_width).size(14));
                }
                if state.calculate_md5 {
                    let md5_text = if state.columns_expanded {
                        file.md5.clone()
                    } else if file.md5.len() > 12 {
                        format!("{}...", &file.md5[..12])
                    } else {
                        file.md5.clone()
                    };
                    data_row = data_row.push(text(md5_text).width(standard_width).size(14));
                }
                if state.calculate_sha256 {
                    let sha256_text = if state.columns_expanded {
                        file.sha256.clone()
                    } else if file.sha256.len() > 12 {
                        format!("{}...", &file.sha256[..12])
                    } else {
                        file.sha256.clone()
                    };
                    data_row = data_row.push(text(sha256_text).width(standard_width).size(14));
                }
                if state.calculate_sha512 {
                    let sha512_text = if state.columns_expanded {
                        file.sha512.clone()
                    } else if file.sha512.len() > 12 {
                        format!("{}...", &file.sha512[..12])
                    } else {
                        file.sha512.clone()
                    };
                    data_row = data_row.push(text(sha512_text).width(standard_width).size(14));
                }
                
                viewport = viewport.push(data_row);
            }
        }
        
        // Add spacer for items below viewport
        let remaining_items = total_files.saturating_sub(end_index);
        if remaining_items > 0 {
            viewport = viewport.push(Space::new(Length::Fill, remaining_items as f32 * ROW_HEIGHT));
        }
        
        scrollable(viewport)
            .id(scrollable::Id::new("detailed_results_scroll"))
            .height(Length::Fill)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Scrollbar::default(),
                horizontal: scrollable::Scrollbar::default(),
            })
            .on_scroll(|viewport| {
                Message::DetailScrolled(viewport.absolute_offset().y)
            })
            .into()
    } else {
        // COLLAPSED MODE: Sticky header with nested scrollables
        let mut body_rows = Column::new().spacing(0);
        
        // Add spacer for items above viewport
        if start_index > 0 {
            body_rows = body_rows.push(Space::new(Length::Fill, start_index as f32 * ROW_HEIGHT));
        }
        
        // Add visible rows
        for i in start_index..end_index {
            if let Some(file) = state.scan_results.detailed_files.get(i) {
                let mut data_row = row![].spacing(10).padding([0, 10]).height(ROW_HEIGHT).align_y(Alignment::Center);
                
                if state.show_filename {
                    data_row = data_row.push(text(&file.name).width(filename_width).size(14));
                }
                if state.show_path {
                    data_row = data_row.push(text(&file.directory_path).width(path_width).size(14));
                }
                if state.show_path_name {
                    data_row = data_row.push(text(&file.full_path).width(fullpath_width).size(14));
                }
                if state.show_size {
                    data_row = data_row.push(text(format_size(file.size)).width(size_width).size(14));
                }
                if state.show_created {
                    data_row = data_row.push(text(&file.created).width(standard_width).size(14));
                }
                if state.show_modified {
                    data_row = data_row.push(text(&file.last_modified).width(standard_width).size(14));
                }
                if state.show_accessed {
                    data_row = data_row.push(text(&file.last_accessed).width(standard_width).size(14));
                }
                if state.show_format {
                    data_row = data_row.push(text(&file.format).width(standard_width).size(14));
                }
                if state.calculate_mime {
                    data_row = data_row.push(text(&file.mime_type).width(standard_width).size(14));
                }
                if state.calculate_md5 {
                    let md5_text = if file.md5.len() > 12 {
                        format!("{}...", &file.md5[..12])
                    } else {
                        file.md5.clone()
                    };
                    data_row = data_row.push(text(md5_text).width(standard_width).size(14));
                }
                if state.calculate_sha256 {
                    let sha256_text = if file.sha256.len() > 12 {
                        format!("{}...", &file.sha256[..12])
                    } else {
                        file.sha256.clone()
                    };
                    data_row = data_row.push(text(sha256_text).width(standard_width).size(14));
                }
                if state.calculate_sha512 {
                    let sha512_text = if file.sha512.len() > 12 {
                        format!("{}...", &file.sha512[..12])
                    } else {
                        file.sha512.clone()
                    };
                    data_row = data_row.push(text(sha512_text).width(standard_width).size(14));
                }
                
                body_rows = body_rows.push(data_row);
            }
        }
        
        // Add spacer for items below viewport
        let remaining_items = total_files.saturating_sub(end_index);
        if remaining_items > 0 {
            body_rows = body_rows.push(Space::new(Length::Fill, remaining_items as f32 * ROW_HEIGHT));
        }
        
        // Vertical scrollable for body with same ID as expanded mode
        let vertical_scrollable = scrollable(body_rows)
            .id(scrollable::Id::new("detailed_results_scroll"))
            .height(Length::Fill)
            .on_scroll(|viewport| {
                Message::DetailScrolled(viewport.absolute_offset().y)
            });
        
        // Sticky header above scrollable body
        column![
            header_row,
            vertical_scrollable
        ]
        .spacing(0)
        .into()
    };
    
    column![
        file_count_text,
        container(table_view)
            .height(Length::Fill)
    ]
    .spacing(10)
    .into()
}

// Virtual scrolling for tree view
fn view_tree_results_virtual(state: &SplendirGui) -> Element<'_, Message> {
    if state.tree_flattened_cache.is_empty() {
        if state.scan_results.tree_node.is_none() {
            return text("No tree data available").into();
        }
        // Should have been populated during scan complete, but just in case
        return text("Processing tree data...").into();
    }
    
    const ROW_HEIGHT: f32 = 20.0;
    const VIEWPORT_HEIGHT: f32 = 2000.0; // Larger default to handle maximized windows
    const VISIBLE_ROWS: usize = (VIEWPORT_HEIGHT / ROW_HEIGHT) as usize + 2;
    
    let total_nodes = state.tree_flattened_cache.len();
    
    // Calculate visible range
    // Don't constrain scroll_offset since we're using Length::Fill - let it scroll freely
    let scroll_offset = state.tree_scroll_offset.max(0.0);
    let start_index = (scroll_offset / ROW_HEIGHT) as usize;
    let end_index = (start_index + VISIBLE_ROWS).min(total_nodes);
    
    // Create virtual viewport
    let mut viewport = Column::new().spacing(0);
    
    // Add spacer for items above viewport
    if start_index > 0 {
        viewport = viewport.push(Space::new(Length::Fill, start_index as f32 * ROW_HEIGHT));
    }
    
    // Add visible nodes
    for i in start_index..end_index {
        if let Some(node) = state.tree_flattened_cache.get(i) {
            let indent = "  ".repeat(node.depth);
            let prefix = if node.is_last { "└─ " } else { "├─ " };
            
            let node_text = if state.colorize_output && node.is_directory {
                format!("{}{}📁 {}", indent, prefix, node.name)
            } else if state.colorize_output {
                format!("{}{}📄 {}", indent, prefix, node.name)
            } else {
                format!("{}{}{}", indent, prefix, node.name)
            };
            
            viewport = viewport.push(
                container(
                    text(node_text)
                        .size(14)
                        .font(Font::MONOSPACE)
                )
                .height(ROW_HEIGHT)
            );
        }
    }
    
    // Add spacer for items below viewport
    let remaining_items = total_nodes.saturating_sub(end_index);
    if remaining_items > 0 {
        viewport = viewport.push(Space::new(Length::Fill, remaining_items as f32 * ROW_HEIGHT));
    }
    
    column![
        text(format!("Tree view ({} nodes)", total_nodes)).size(14),
        container(
            scrollable(viewport)
                .height(Length::Fill)
                .on_scroll(|viewport| {
                    Message::TreeScrolled(viewport.absolute_offset().y)
                })
        )
        .height(Length::Fill)
    ]
    .spacing(10)
    .into()
}

fn view_analysis_results(state: &SplendirGui) -> Element<'_, Message> {
    if state.scan_results.analysis_output.is_empty() {
        return text("No analysis data available").into();
    }
    
    scrollable(
        text(&state.scan_results.analysis_output)
            .size(14)
    )
    .height(Length::Fill)
    .into()
}

fn view_about_dialog() -> Element<'static, Message> {
    let about_text = format!(
        "Splendir v{}\n\n\
        A high-performance directory scanner with a GUI interface.\n\n\
        Features:\n\
        • Detailed file lists with format ID and hash calculations\n\
        • Tree view visualization of directory structures\n\
        • Comprehensive directory analysis with statistics\n\
        • Parallel processing for fast scans\n\
        • Multiple scan presets for different use cases\n\
        • Export results to CSV or text files\n\
        • Virtual scrolling for live views of millions of files\n\n\
        Developed by Kam Woods\n\
        Licensed under MIT\n\n\
        GitHub: https://github.com/kamwoods/splendir",
        VERSION
    );
    
    // Semi-transparent dark overlay
    let overlay = container(
        container(
            column![
                text("About Splendir")
                    .size(24)
                    .color(iced::Color::WHITE),
                Space::with_height(Length::Fixed(20.0)),
                scrollable(
                    text(about_text)
                        .size(14)
                        .color(iced::Color::from_rgb(0.9, 0.9, 0.9))
                )
                .height(Length::Fixed(400.0)),
                Space::with_height(Length::Fixed(20.0)),
                button(text("Close").size(14))
                    .on_press(Message::CloseAbout)
                    .padding([8, 16]),
            ]
            .spacing(10)
            .align_x(Alignment::Center)
            .width(Length::Fixed(600.0))
        )
        .padding(20)
        .style(|_theme| {
            container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgb(0.15, 0.15, 0.15))),
                border: iced::Border {
                    color: iced::Color::from_rgb(0.4, 0.4, 0.4),
                    width: 2.0,
                    radius: 10.0.into(),
                },
                ..Default::default()
            }
        })
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center(Length::Fill)
    .style(|_theme| {
        container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(0.0, 0.0, 0.0, 0.7))),
            ..Default::default()
        }
    });
    
    overlay.into()
}

// Flatten tree structure for efficient rendering
#[derive(Clone)]
struct FlatTreeNode {
    name: String,
    depth: usize,
    is_directory: bool,
    is_last: bool,
}

fn flatten_tree(node: &TreeNode, depth: usize) -> Vec<FlatTreeNode> {
    let mut result = Vec::new();
    
    // Add current node
    result.push(FlatTreeNode {
        name: node.name.clone(),
        depth,
        is_directory: node.is_directory,
        is_last: false,
    });
    
    // Add children
    for (i, child) in node.children.iter().enumerate() {
        let is_last = i == node.children.len() - 1;
        let mut child_nodes = flatten_tree_recursive(child, depth + 1, is_last);
        result.append(&mut child_nodes);
    }
    
    result
}

fn flatten_tree_recursive(node: &TreeNode, depth: usize, is_last: bool) -> Vec<FlatTreeNode> {
    let mut result = Vec::new();
    
    // Add current node
    result.push(FlatTreeNode {
        name: node.name.clone(),
        depth,
        is_directory: node.is_directory,
        is_last,
    });
    
    // Add children
    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1;
        let mut child_nodes = flatten_tree_recursive(child, depth + 1, child_is_last);
        result.append(&mut child_nodes);
    }
    
    result
}

async fn perform_scan_with_progress(
    path: PathBuf,
    scanner: DirectoryScanner,
    _mode: ScanMode,  // No longer needed - we scan all modes
    colorize: bool,
    progress_state: ProgressState,
) -> Result<ScanResults, String> {
    let start_time = Instant::now();
    
    let result = tokio::task::spawn_blocking(move || {
        let mut results = ScanResults::default();
        
        // Phase 1: Detailed file scan (slowest, with hashes)
        // This is the most comprehensive scan and will populate the OS file cache
        {
            let progress_state_clone = progress_state.clone();
            let progress_callback: ProgressCallback = Arc::new(move |progress, status| {
                if let Ok(mut guard) = progress_state_clone.lock() {
                    *guard = Some((progress * 0.4, format!("Phase 1/3: {}", status)));
                }
            });
            
            match scanner.scan_detailed_with_progress(&path, Some(progress_callback)) {
                Ok(files) => results.detailed_files = files,
                Err(e) => return Err(format!("Detailed scan failed: {}", e)),
            }
        }
        
        // Phase 2: Tree structure scan (fast, uses cached file system data)
        {
            let progress_state_clone = progress_state.clone();
            let progress_callback: ProgressCallback = Arc::new(move |progress, status| {
                if let Ok(mut guard) = progress_state_clone.lock() {
                    *guard = Some((0.4 + progress * 0.3, format!("Phase 2/3: {}", status)));
                }
            });
            
            match scanner.scan_tree_with_progress(&path, Some(progress_callback)) {
                Ok(tree) => {
                    results.tree_output = format_tree_output(&tree, colorize);
                    results.tree_node = Some(tree);
                }
                Err(e) => return Err(format!("Tree scan failed: {}", e)),
            }
        }
        
        // Phase 3: Directory analysis (fast, uses cached data)
        {
            let progress_state_clone = progress_state.clone();
            let progress_callback: ProgressCallback = Arc::new(move |progress, status| {
                if let Ok(mut guard) = progress_state_clone.lock() {
                    *guard = Some((0.7 + progress * 0.3, format!("Phase 3/3: {}", status)));
                }
            });
            
            match analyze_directory_with_progress(&path, scanner.include_hidden, scanner.max_depth, progress_callback) {
                Ok(analysis) => {
                    results.analysis_output = analysis.summary();
                }
                Err(e) => return Err(format!("Analysis failed: {}", e)),
            }
        }
        
        // Final progress update
        if let Ok(mut guard) = progress_state.lock() {
            *guard = Some((1.0, "All scans completed".to_string()));
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

async fn export_results(path: PathBuf, results: ScanResults, mode: ScanMode, columns: ColumnVisibility) -> Result<String, String> {
    use std::fs::File;
    use std::io::Write;
    
    tokio::task::spawn_blocking(move || {
        let mut file = File::create(&path)
            .map_err(|e| format!("Failed to create file: {}", e))?;
        
        match mode {
            ScanMode::Detailed => {
                // Build CSV header dynamically based on selected columns
                let mut headers = Vec::new();
                if columns.show_filename { headers.push("Name"); }
                if columns.show_path { headers.push("Path"); }
                if columns.show_path_name { headers.push("Full Path"); }
                if columns.show_size { headers.push("Size (bytes)"); }
                if columns.show_created { headers.push("Created"); }
                if columns.show_modified { headers.push("Modified"); }
                if columns.show_accessed { headers.push("Accessed"); }
                if columns.show_format { headers.push("Format"); }
                if columns.calculate_mime { headers.push("MIME Type"); }
                if columns.calculate_md5 { headers.push("MD5"); }
                if columns.calculate_sha256 { headers.push("SHA256"); }
                if columns.calculate_sha512 { headers.push("SHA512"); }
                
                writeln!(file, "{}", headers.join(","))
                    .map_err(|e| format!("Failed to write header: {}", e))?;
                
                // Write data rows with only selected columns
                for file_info in &results.detailed_files {
                    let mut values = Vec::new();
                    if columns.show_filename {
                        values.push(format!("\"{}\"", file_info.name.replace("\"", "\"\"")));
                    }
                    if columns.show_path {
                        values.push(format!("\"{}\"", file_info.directory_path.replace("\"", "\"\"")));
                    }
                    if columns.show_path_name {
                        values.push(format!("\"{}\"", file_info.full_path.replace("\"", "\"\"")));
                    }
                    if columns.show_size {
                        values.push(file_info.size.to_string());
                    }
                    if columns.show_created {
                        values.push(format!("\"{}\"", file_info.created));
                    }
                    if columns.show_modified {
                        values.push(format!("\"{}\"", file_info.last_modified));
                    }
                    if columns.show_accessed {
                        values.push(format!("\"{}\"", file_info.last_accessed));
                    }
                    if columns.show_format {
                        values.push(format!("\"{}\"", file_info.format));
                    }
                    if columns.calculate_mime {
                        values.push(format!("\"{}\"", file_info.mime_type));
                    }
                    if columns.calculate_md5 {
                        values.push(format!("\"{}\"", file_info.md5));
                    }
                    if columns.calculate_sha256 {
                        values.push(format!("\"{}\"", file_info.sha256));
                    }
                    if columns.calculate_sha512 {
                        values.push(format!("\"{}\"", file_info.sha512));
                    }
                    
                    writeln!(file, "{}", values.join(","))
                        .map_err(|e| format!("Failed to write data: {}", e))?;
                }
            }
            ScanMode::Tree => {
                // Export tree as text
                let tree_text = if !results.tree_output.is_empty() {
                    results.tree_output
                } else if let Some(ref tree_node) = results.tree_node {
                    format_tree_output(tree_node, false)
                } else {
                    String::from("No tree data available")
                };
                
                write!(file, "{}", tree_text)
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

/// Sort files based on sort criteria
fn sort_files(files: &mut Vec<FileInfo>, original_order: &[FileInfo], sort_by: SortBy, sort_order: SortOrder) {
    // Restore original order if using tree default
    if sort_by == SortBy::TreeDefault {
        *files = original_order.to_vec();
        // Reverse if descending
        if sort_order == SortOrder::Descending {
            files.reverse();
        }
        return;
    }
    
    files.sort_by(|a, b| {
        let cmp = match sort_by {
            SortBy::TreeDefault => std::cmp::Ordering::Equal, // Already handled above
            SortBy::FileName => a.name.cmp(&b.name),
            SortBy::Size => a.size.cmp(&b.size),
            SortBy::Created => a.created.cmp(&b.created),
            SortBy::Accessed => a.last_accessed.cmp(&b.last_accessed),
            SortBy::Modified => a.last_modified.cmp(&b.last_modified),
        };
        
        match sort_order {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });
}
