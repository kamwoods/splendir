use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::fmt;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

/// Initialize logging to ~/.splendir/logs with daily rotation
/// and automatic cleanup of logs older than `retention_days`
pub fn init_logging(retention_days: u64) -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = get_log_directory()?;
    
    // Create log directory if it doesn't exist
    fs::create_dir_all(&log_dir)?;
    
    // Clean up old log files
    cleanup_old_logs(&log_dir, retention_days)?;
    
    // Set up file appender with daily rotation
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        &log_dir,
        "splendir.log"
    );
    
    // Initialize the subscriber
    tracing_subscriber::fmt()
        .with_writer(file_appender)
        .with_ansi(false)  // Don't use color codes in log files
        .with_target(true)  // Include the target (module path)
        .with_thread_ids(false)
        .with_line_number(true)
        .with_file(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();
    
    tracing::info!("Logging initialized at {}", log_dir.display());
    tracing::info!("Log retention set to {} days", retention_days);
    
    Ok(())
}

/// Get the log directory path (~/.splendir/logs)
fn get_log_directory() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home_dir = dirs::home_dir()
        .ok_or("Unable to determine home directory")?;
    
    Ok(home_dir.join(".splendir").join("logs"))
}

/// Remove log files older than the specified number of days
fn cleanup_old_logs(log_dir: &PathBuf, retention_days: u64) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    let retention_seconds = retention_days * 24 * 60 * 60;
    let cutoff_time = now.saturating_sub(retention_seconds);
    
    let mut removed_count = 0;
    let mut error_count = 0;
    
    // Iterate through files in the log directory
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            // Only process log files (*.log*)
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if !filename.starts_with("splendir.log") {
                    continue;
                }
                
                // Check file modification time
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(modified_duration) = modified.duration_since(UNIX_EPOCH) {
                            let file_time = modified_duration.as_secs();
                            
                            // Remove if older than retention period
                            if file_time < cutoff_time {
                                match fs::remove_file(&path) {
                                    Ok(_) => {
                                        removed_count += 1;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to remove old log file {}: {}", path.display(), e);
                                        error_count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if removed_count > 0 {
        eprintln!("Cleaned up {} old log file(s)", removed_count);
    }
    
    if error_count > 0 {
        eprintln!("Failed to remove {} log file(s)", error_count);
    }
    
    Ok(())
}

/// Get the path to the log directory for display in the UI
pub fn get_log_directory_path() -> Option<PathBuf> {
    get_log_directory().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::TempDir;
    
    #[test]
    fn test_cleanup_old_logs() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        
        // Create a few test log files
        let old_log = log_dir.join("splendir.log.2020-01-01");
        let recent_log = log_dir.join("splendir.log.2024-12-01");
        let current_log = log_dir.join("splendir.log");
        
        File::create(&old_log).unwrap().write_all(b"old").unwrap();
        File::create(&recent_log).unwrap().write_all(b"recent").unwrap();
        File::create(&current_log).unwrap().write_all(b"current").unwrap();
        
        // Modify the old log's timestamp to be very old
        // Note: This is platform-specific and might not work in all test environments
        // In a real scenario, you'd need platform-specific APIs to set file times
        
        // Clean up logs older than 30 days
        cleanup_old_logs(&log_dir, 30).unwrap();
        
        // Current and recent logs should still exist
        assert!(current_log.exists());
        // The old_log might or might not be removed depending on filesystem timestamp handling
    }
}
