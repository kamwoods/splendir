#![windows_subsystem = "windows"]
mod gui;
mod logging;

use std::process;

fn main() {
    // Initialize logging to ~/.splendir/logs
    // Keep logs for 30 days
    if let Err(e) = logging::init_logging(30) {
        eprintln!("Warning: Failed to initialize logging: {}", e);
        eprintln!("Application will continue without file logging.");
    }
    
    tracing::info!("Starting splendir application");
    
    // Initialize the GUI application
    if let Err(e) = gui::run() {
        tracing::error!("Failed to run GUI application: {}", e);
        eprintln!("Failed to run GUI application: {}", e);
        process::exit(1);
    }
    
    tracing::info!("Splendir application exited normally");
}
