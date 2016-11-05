use netinfo::{Inode, Pid};
use netinfo::error::*;

use std::collections::HashMap;
use std::fs::{read_dir, read_link};
use std::str::FromStr;
use std::borrow::Borrow;
use std::io::ErrorKind as IOErrorKind;

/// This struct generates a HashMap from inodes to pid from file descriptors under `/proc/{pid}/fd/`.
///
/// Example: If `/proc/15321/fd/433` contains 'socket:[12345]', then we know that inode 12345 belongs to
/// process 15321.
#[derive(Debug)]
pub struct InodeToPidMap {
    inode_to_pid_map: HashMap<Inode, Pid>,
}

impl InodeToPidMap {
    /// Constructor for `InodeToPidMap`.
    pub fn new() -> InodeToPidMap {
        InodeToPidMap { inode_to_pid_map: HashMap::new() }
    }

    fn refresh_pid(&mut self, pid: Pid) -> Result<()> {

        // read file descriptors /proc/{pid}/fd and ignore PermissionDenied errors
        let entries = match read_dir(format!("/proc/{}/fd", pid)) {
            Ok(x) => x,
            Err(ioerror) => {
                if ioerror.kind() == IOErrorKind::PermissionDenied { /* ignore */ return Ok(()) }
                else { return Err(ioerror)?; }
            }
        };

        for dir_entry in entries {
            let dir_entry = dir_entry?;
            let link_target = if let Ok(x) = read_link(dir_entry.path()) { x } else { /* file has probably disappeared */ continue };
            let link_target_str = link_target.as_path().to_string_lossy();

            // sockets have the form "socket:[inode]"; for example "socket:[14235]"
            if link_target_str.starts_with("socket:[") && link_target_str.ends_with("]") {
                let inode = Inode::from_str(&link_target_str[8..link_target_str.len() - 1])?;
                self.inode_to_pid_map.insert(inode, pid);
            }
        }

        Ok(())
    }

    /// Discard current HashMap and rebuild from `/proc/{pid}/fd/`.
    pub fn refresh(&mut self) -> Result<()> {
        self.inode_to_pid_map.clear();

        let entries = read_dir("/proc")?;
        for dir_entry_opt in entries {
            let dir_entry = dir_entry_opt?;

            // test whether filename is /proc/{pid} or something else (non-numeric)
            let os_filename = dir_entry.file_name();
            let filename = (*os_filename).to_string_lossy();
            let is_numeric = filename.chars().all(|x| x.is_numeric());
            if !is_numeric { continue }

            // Is file directory? File should be directory containing file descriptors...
            // When the metadata() call fails, the file has probably disappeared.
            if dir_entry.metadata().ok().map_or(true, |metadata| !metadata.is_dir()) { continue }

            // get pid as number
            let pid = Pid::from_str(filename.borrow())?;

            // update inodes for this pid
            self.refresh_pid(pid)?;
        }

        Ok(())
    }

    /// Returns None if inode was not found
    pub fn find_pid(&self, inode: Inode) -> Option<Pid> {
        self.inode_to_pid_map.get(&inode).map(|&x| x)
    }
}
