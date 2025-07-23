#![windows_subsystem = "windows"]
mod gui;

use std::process;

fn main() {
    // Initialize the GUI application
    if let Err(e) = gui::run() {
        eprintln!("Failed to run GUI application: {}", e);
        process::exit(1);
    }
}
