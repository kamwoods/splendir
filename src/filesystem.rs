//! Filesystem type detection
//!
//! This module provides cross-platform detection of filesystem types,
//! which can be used to optimize scanning strategies (e.g., using MFT
//! for NTFS volumes).

use std::path::Path;

/// Detected filesystem types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemType {
    /// Windows NTFS
    Ntfs,
    /// Windows FAT32
    Fat32,
    /// Windows exFAT
    ExFat,
    /// Windows ReFS
    Refs,
    /// Linux ext2/ext3/ext4
    Ext,
    /// Linux Btrfs
    Btrfs,
    /// Linux XFS
    Xfs,
    /// Linux ZFS
    Zfs,
    /// macOS APFS
    Apfs,
    /// macOS HFS+
    HfsPlus,
    /// Network filesystem (SMB/CIFS, NFS, etc.)
    Network,
    /// Unknown or unsupported filesystem
    Unknown(String),
}

impl FilesystemType {
    /// Returns true if this filesystem type supports MFT-based scanning
    pub fn supports_mft(&self) -> bool {
        matches!(self, FilesystemType::Ntfs)
    }
    
    /// Returns a human-readable name for the filesystem
    pub fn name(&self) -> &str {
        match self {
            FilesystemType::Ntfs => "NTFS",
            FilesystemType::Fat32 => "FAT32",
            FilesystemType::ExFat => "exFAT",
            FilesystemType::Refs => "ReFS",
            FilesystemType::Ext => "ext2/3/4",
            FilesystemType::Btrfs => "Btrfs",
            FilesystemType::Xfs => "XFS",
            FilesystemType::Zfs => "ZFS",
            FilesystemType::Apfs => "APFS",
            FilesystemType::HfsPlus => "HFS+",
            FilesystemType::Network => "Network",
            FilesystemType::Unknown(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for FilesystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Information about a volume/mount point
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// The filesystem type
    pub filesystem_type: FilesystemType,
    /// The volume/mount root path (e.g., "C:\" on Windows, "/" on Unix)
    pub mount_point: std::path::PathBuf,
    /// Volume label if available
    pub label: Option<String>,
    /// Whether this appears to be a network/remote filesystem
    pub is_remote: bool,
}

/// Detect the filesystem type for a given path
///
/// # Arguments
/// * `path` - Any path on the filesystem to detect
///
/// # Returns
/// * `Some(VolumeInfo)` - Information about the volume containing the path
/// * `None` - If detection failed
///
/// # Example
/// ```no_run
/// use directory_scanner::filesystem::detect_filesystem;
///
/// if let Some(info) = detect_filesystem(std::path::Path::new("/home/user")) {
///     println!("Filesystem: {}", info.filesystem_type);
///     if info.filesystem_type.supports_mft() {
///         println!("MFT scanning available");
///     }
/// }
/// ```
pub fn detect_filesystem(path: &Path) -> Option<VolumeInfo> {
    // Ensure path exists
    if !path.exists() {
        return None;
    }
    
    // Canonicalize to resolve symlinks and get absolute path
    let canonical = path.canonicalize().ok()?;
    
    #[cfg(windows)]
    {
        detect_filesystem_windows(&canonical)
    }
    
    #[cfg(target_os = "linux")]
    {
        detect_filesystem_linux(&canonical)
    }
    
    #[cfg(target_os = "macos")]
    {
        detect_filesystem_macos(&canonical)
    }
    
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        // Fallback for other platforms
        Some(VolumeInfo {
            filesystem_type: FilesystemType::Unknown("unsupported platform".to_string()),
            mount_point: canonical,
            label: None,
            is_remote: false,
        })
    }
}

// ============================================================================
// Windows implementation
// ============================================================================

#[cfg(windows)]
fn detect_filesystem_windows(path: &Path) -> Option<VolumeInfo> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    // Drive type constants from Windows API
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew
    const DRIVE_REMOTE: u32 = 4;
    
    // Get the volume root path (e.g., "C:\")
    let path_str = path.to_string_lossy();
    
    // Extract the root - handle both "C:\..." and "\\?\C:\..." forms
    let root = if path_str.starts_with("\\\\?\\") {
        // Extended path format: \\?\C:\...
        if path_str.len() >= 7 {
            format!("{}\\", &path_str[4..6])
        } else {
            return None;
        }
    } else if path_str.len() >= 3 && path_str.chars().nth(1) == Some(':') {
        // Standard path format: C:\...
        format!("{}\\", &path_str[..2])
    } else if path_str.starts_with("\\\\") {
        // UNC path: \\server\share\...
        // Find the share portion
        let parts: Vec<&str> = path_str.trim_start_matches("\\\\").splitn(3, '\\').collect();
        if parts.len() >= 2 {
            format!("\\\\{}\\{}\\", parts[0], parts[1])
        } else {
            return None;
        }
    } else {
        return None;
    };
    
    // Convert to wide string for Windows API
    let root_wide: Vec<u16> = OsStr::new(&root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    
    // Buffers for GetVolumeInformationW
    let mut volume_name: Vec<u16> = vec![0; 256];
    let mut fs_name: Vec<u16> = vec![0; 256];
    let mut serial_number: u32 = 0;
    let mut max_component_length: u32 = 0;
    let mut fs_flags: u32 = 0;
    
    let success = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW(
            root_wide.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
            &mut serial_number,
            &mut max_component_length,
            &mut fs_flags,
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    
    if success == 0 {
        // API call failed - might be a network path that's unavailable
        // or access denied
        return Some(VolumeInfo {
            filesystem_type: FilesystemType::Unknown("detection failed".to_string()),
            mount_point: std::path::PathBuf::from(&root),
            label: None,
            is_remote: root.starts_with("\\\\"),
        });
    }
    
    // Convert filesystem name from wide string
    let fs_name_end = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
    let fs_name_string = String::from_utf16_lossy(&fs_name[..fs_name_end]);
    
    // Convert volume label from wide string
    let label_end = volume_name.iter().position(|&c| c == 0).unwrap_or(volume_name.len());
    let label = if label_end > 0 {
        Some(String::from_utf16_lossy(&volume_name[..label_end]))
    } else {
        None
    };
    
    // Determine if remote
    let drive_type = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_wide.as_ptr())
    };
    let is_remote = drive_type == DRIVE_REMOTE;
    
    // Parse filesystem type
    let filesystem_type = match fs_name_string.to_uppercase().as_str() {
        "NTFS" => FilesystemType::Ntfs,
        "FAT32" => FilesystemType::Fat32,
        "EXFAT" => FilesystemType::ExFat,
        "REFS" => FilesystemType::Refs,
        other => FilesystemType::Unknown(other.to_string()),
    };
    
    Some(VolumeInfo {
        filesystem_type,
        mount_point: std::path::PathBuf::from(&root),
        label,
        is_remote,
    })
}

// ============================================================================
// Linux implementation
// ============================================================================

#[cfg(target_os = "linux")]
fn detect_filesystem_linux(path: &Path) -> Option<VolumeInfo> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    // Read /proc/mounts to find the mount point for this path
    let mounts_file = File::open("/proc/mounts").ok()?;
    let reader = BufReader::new(mounts_file);
    
    let path_str = path.to_string_lossy();
    let mut best_match: Option<(String, String, String)> = None; // (mount_point, fs_type, device)
    let mut best_match_len = 0;
    
    for line in reader.lines() {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() >= 3 {
            let device = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];
            
            // Check if this mount point is a prefix of our path
            if path_str.starts_with(mount_point) || mount_point == "/" {
                let mount_len = mount_point.len();
                if mount_len > best_match_len {
                    best_match = Some((
                        mount_point.to_string(),
                        fs_type.to_string(),
                        device.to_string(),
                    ));
                    best_match_len = mount_len;
                }
            }
        }
    }
    
    let (mount_point, fs_type_str, device) = best_match?;
    
    // Determine if remote
    let is_remote = fs_type_str == "nfs" 
        || fs_type_str == "nfs4" 
        || fs_type_str == "cifs" 
        || fs_type_str == "smb"
        || fs_type_str == "smbfs"
        || fs_type_str == "fuse.sshfs"
        || device.contains(":");
    
    // Parse filesystem type
    let filesystem_type = match fs_type_str.as_str() {
        "ntfs" | "ntfs3" | "ntfs-3g" | "fuseblk" => {
            // fuseblk is often NTFS via ntfs-3g, but could be other FUSE filesystems
            // We check if the device looks like a block device
            if device.starts_with("/dev/") {
                FilesystemType::Ntfs
            } else {
                FilesystemType::Unknown(fs_type_str.clone())
            }
        }
        "vfat" | "fat32" => FilesystemType::Fat32,
        "exfat" => FilesystemType::ExFat,
        "ext2" | "ext3" | "ext4" => FilesystemType::Ext,
        "btrfs" => FilesystemType::Btrfs,
        "xfs" => FilesystemType::Xfs,
        "zfs" => FilesystemType::Zfs,
        "nfs" | "nfs4" | "cifs" | "smb" | "smbfs" => FilesystemType::Network,
        other => FilesystemType::Unknown(other.to_string()),
    };
    
    Some(VolumeInfo {
        filesystem_type,
        mount_point: std::path::PathBuf::from(mount_point),
        label: None, // Would need to read from /dev/disk/by-label or blkid
        is_remote,
    })
}

// ============================================================================
// macOS implementation
// ============================================================================

#[cfg(target_os = "macos")]
fn detect_filesystem_macos(path: &Path) -> Option<VolumeInfo> {
    use std::process::Command;
    
    // Use diskutil to get filesystem information
    // This is simpler than using the statfs syscall directly
    let output = Command::new("diskutil")
        .args(["info", "-plist", path.to_str()?])
        .output()
        .ok()?;
    
    if !output.status.success() {
        // Fallback: try to use statfs via df command
        return detect_filesystem_macos_fallback(path);
    }
    
    let plist_str = String::from_utf8_lossy(&output.stdout);
    
    // Simple plist parsing for the fields we need
    // (Avoids adding a plist crate dependency)
    let fs_type = extract_plist_string(&plist_str, "FilesystemType");
    let mount_point = extract_plist_string(&plist_str, "MountPoint")
        .unwrap_or_else(|| path.to_string_lossy().to_string());
    let volume_name = extract_plist_string(&plist_str, "VolumeName");
    
    let filesystem_type = match fs_type.as_deref() {
        Some("apfs") => FilesystemType::Apfs,
        Some("hfs") => FilesystemType::HfsPlus,
        Some("ntfs") => FilesystemType::Ntfs,
        Some("msdos") => FilesystemType::Fat32,
        Some("exfat") => FilesystemType::ExFat,
        Some("nfs") | Some("smbfs") | Some("afpfs") => FilesystemType::Network,
        Some(other) => FilesystemType::Unknown(other.to_string()),
        None => FilesystemType::Unknown("unknown".to_string()),
    };
    
    let is_remote = matches!(filesystem_type, FilesystemType::Network);
    
    Some(VolumeInfo {
        filesystem_type,
        mount_point: std::path::PathBuf::from(mount_point),
        label: volume_name,
        is_remote,
    })
}

#[cfg(target_os = "macos")]
fn detect_filesystem_macos_fallback(path: &Path) -> Option<VolumeInfo> {
    use std::process::Command;
    
    // Use df to get mount point and filesystem type
    let output = Command::new("df")
        .args(["-T", path.to_str()?])
        .output()
        .ok()?;
    
    if !output.status.success() {
        return Some(VolumeInfo {
            filesystem_type: FilesystemType::Unknown("detection failed".to_string()),
            mount_point: path.to_path_buf(),
            label: None,
            is_remote: false,
        });
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();
    
    // Second line contains the info (first is header)
    if lines.len() < 2 {
        return None;
    }
    
    let parts: Vec<&str> = lines[1].split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    
    let fs_type_str = parts[1];
    let mount_point = parts.last()?;
    
    let filesystem_type = match fs_type_str {
        "apfs" => FilesystemType::Apfs,
        "hfs" => FilesystemType::HfsPlus,
        "ntfs" => FilesystemType::Ntfs,
        "msdos" => FilesystemType::Fat32,
        "exfat" => FilesystemType::ExFat,
        other => FilesystemType::Unknown(other.to_string()),
    };
    
    Some(VolumeInfo {
        filesystem_type,
        mount_point: std::path::PathBuf::from(mount_point),
        label: None,
        is_remote: false,
    })
}

#[cfg(target_os = "macos")]
fn extract_plist_string(plist: &str, key: &str) -> Option<String> {
    // Very simple plist string extraction
    // Looking for: <key>KeyName</key>\n\t<string>Value</string>
    let key_tag = format!("<key>{}</key>", key);
    let key_pos = plist.find(&key_tag)?;
    let after_key = &plist[key_pos + key_tag.len()..];
    
    let string_start = after_key.find("<string>")?;
    let value_start = string_start + 8; // length of "<string>"
    let remaining = &after_key[value_start..];
    let string_end = remaining.find("</string>")?;
    
    Some(remaining[..string_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_filesystem_type_display() {
        assert_eq!(FilesystemType::Ntfs.to_string(), "NTFS");
        assert_eq!(FilesystemType::Ext.to_string(), "ext2/3/4");
        assert_eq!(FilesystemType::Unknown("foo".to_string()).to_string(), "foo");
    }
    
    #[test]
    fn test_supports_mft() {
        assert!(FilesystemType::Ntfs.supports_mft());
        assert!(!FilesystemType::Fat32.supports_mft());
        assert!(!FilesystemType::Ext.supports_mft());
        assert!(!FilesystemType::Apfs.supports_mft());
    }
    
    #[test]
    fn test_detect_current_directory() {
        // This should work on any platform
        let result = detect_filesystem(Path::new("."));
        assert!(result.is_some(), "Should detect filesystem for current directory");
        
        let info = result.unwrap();
        println!("Detected filesystem: {:?}", info);
        assert!(!info.mount_point.as_os_str().is_empty());
    }
}
