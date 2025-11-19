## Splendir 

[![GitHub issues](https://img.shields.io/github/issues/kamwoods/splendir.svg)](https://github.com/kamwoods/splendir/issues)
[![Build](https://github.com/kamwoods/splendir/actions/workflows/rust.yml/badge.svg)](https://github.com/kamwoods/splendir/actions/workflows/rust.yml)
[![GitHub forks](https://img.shields.io/github/forks/kamwoods/splendir.svg)](https://github.com/kamwoods/splendir/network)

### A High Performance Directory Scanner and Printer

Splendir is an extremely fast directory scanner with GUI and CLI interfaces. Splendir generates tree views of files in a directory, customizable lists of file metadata, and high-level reports of directory contents and file type distributions. Releases include executables for Linux (x64) distros, Windows 11 (x64), and macOS (Apple M-series silicon).

Features:
- Multiple scan presets
- Virtual scrolling in tree and file list modes for live views of millions of files
- Live sorting of output in file list view
- Multi-threaded processing for high speed scans
- SHA256 and MD5 hash calculations on request
- Hidden file and symlink traversal on request
- File format identification on request
- Export tree structures as UTF-8 encoded text files
- Export directory listings as UTF-8 encoded CSV files

Splendir is built in [Rust](https://rust-lang.org/) and implements a GUI in [iced](https://iced.rs/). Multi-threading for hash calculations is handled by [rayon](https://github.com/rayon-rs/rayon).

The Splendir GUI in the current alpha releases is "feature complete" for the publicly described features. The Splendir CLI is a work-in-progress and may lag behind. The main branch of this repo may include untested development code that is subject to change.

### Install

The Splendir GUI and Splendir CLI are standalone executables. No installation is required. From the Releases section in the main GitHub repo you can download one of the following files:

- Linux executables: ```splendir-linux-x64.tar.gz```
- Windows executables: ```splendir-windows-x64.tar.gz```
- Mac executables: ```splendir-macos.tar.gz```

**Linux**

In a terminal, navigate to your download directory and extract the .tar.gz file:

```
cd /your/download/directory
tar zxvf splendir-linux-x64.tar.gz
```

Copy the executables to ```/usr/local/bin```:

```
sudo cp splendir_gui /usr/local/bin
sudo cp splendir /usr/local/bin
```

You can now run the GUI (or the CLI) by typing ```splendir_gui``` or ```splendir``` in the terminal and hitting enter.

**Windows 11**

Double-click to extract the ```splendir-windows-x64.tar.gz```. Double-click on ```splendir_gui.exe``` to run the GUI, or run ```splendir.exe``` from PowerShell to use the command-line utility. Depending on your Windows installation, you may get a warning that the ```Visual Studio C++ Redistributable``` package needs to be installed first. Windows will also generate a warning pop-up window about an unknown developer when running the GUI. Click ```More info``` and select ```Run Anyway``` to run the GUI.

**macOS**

Extract the ```splendir-macos.tar.gz``` file in your location of choice. Double-clicking on ```splendir_gui``` will generate an untrusted application warning. Click on ```Apple Menu > System Settings``` and then select ```Privacy & Security``` in the sidebar. In ```Security```, click ```Open``` and ```Open Anyway```. You will be asked for a login password to confirm.

### Usage (GUI)

Click the **Browse...** button to select a local directory. Click the **Start Scan** button to begin a scan once you have selected a directory. The **Mode:** dropdown can be set to **Detailed File List** (outputs a file list with metadata), **Tree View** (outputs a graphical tree view similar to the command-line tool "tree"), or **Directory Analysis** (a high-level overview of the directory contents). All three views are generated when **Start Scan** is clicked. When a scan is complete, an **Export** button will appear to allow export of the content. If **Detailed File List** is currently selected, clicking **Export** will generate a CSV file. If **Tree View** is selected, it will generate a UTF-8 text representation of the tree.

![Splendir Directory Listing View](assets/sds-dirview.png)

Both the **Directory Listing** view and **Tree View** are implemented with a virtual scrolling feature to provide live views of directories of any size. When scanning large directories, you will see a progress report as the tool builds this data structure. Once the directory has been scanned, you can scroll to any point in the output to inspect and review before exporting. You can also adjust the Sort Options to instantly view and export sorted results without having to rescan. The **Default** sort optioncorresponds to an alphabetized directory walk (all subdirectory entries grouped together at each level).

![Splendir Tree Listing View](assets/sds-treeview.png)

The **Detailed File List** view is exported as a UTF-8 encoded CSV file (this can be conveniently viewed in a spreadsheet), and the **Tree View** is exported as a UTF-8 encoded text file. Additional export options are planned for future releases.

![Splendir Directory Analysis View](assets/sds-analysis.png)

### Usage (CLI)

To generate a directory listing with file name, path, size, last modified date, and SHA256, invoke the CLI tool as follows:

```./splendir /path/to/dir```

To generate a tree view, invoke it as follows:

```./splendir --tree /path/to/dir```

To generate a tree view with basic colorization, invoke it as follows:

```./splendir -C --tree /path/to/dir```

Full features (subject to change in this early WIP) can be viewed with:

```./splendir --help```

```shell
Splendir - Recursively scan directories and display file information

USAGE:
    ./splendir [OPTIONS] <directory_path>

ARGUMENTS:
    <directory_path>    Path to the directory to scan

OPTIONS:
    --tree              Display results as a tree structure
    -C                  Colorize the tree output (only works with --tree)
    --fast              Fast mode - skip SHA256 calculation and limit depth
    --analyze           Comprehensive directory analysis with statistics
    -h, --help          Print this help information

EXAMPLES:
    ./splendir /home/user                    # Detailed file listing
    ./splendir --tree /home/user             # Tree view
    ./splendir --tree -C /home/user          # Colorized tree view
    ./splendir --fast /home/user             # Fast scan without hashes
    ./splendir --analyze /home/user          # Comprehensive analysis
    ./splendir --help                        # Show this help message

MODES:
    Default    : Shows detailed file information including SHA256 hashes
    Tree       : Shows directory structure as a visual tree
    Fast       : Quick scan without SHA256 calculation (faster for large dirs)
    Analysis   : Comprehensive statistics and file type breakdown
```

Additional features are in progress.

### Build (Developers and Contributors)

To build, ensure you are using [Rust 1.88.0 or newer](https://www.rust-lang.org/tools/install).

Clone this repo with the command:

```git clone https://github.com/kamwoods/splendir```

Navigate to the root of your cloned directory, and build the CLI and GUI binaries with:

```shell
cargo build --release
```

### Contributing

Open an issue in this repository to report bugs or request features, or open a PR to submit updates.

### License

Distributed under the terms of the MIT License. See the LICENSE file for additional details.
