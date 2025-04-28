//! Implements functionality around `mount(2)` system calls

use std::path::Path;

use anyhow::Result;
use log::debug;
use nix::mount::{self, MsFlags};

/// Initialize a freshly created mount namespace.
///
/// This function first mounts `/` with [`MsFlags::MS_REC`] and
/// [`MsFlags::MS_PRIVATE`] so that all `mount(2)` and `umount(2)` operations
/// performed within the mount namespace do not propagate into other namespace
/// in case that there is a shared subtree somewhere within the file system.
/// If `/` is already marked with [`MsFlags::MS_REC`], then this is a rather
/// redundant operation but honestly it probably never hurts to do it again.
pub fn init_namespace() -> Result<()> {
    mount::mount(
        Some(""),
        "/",
        Some(""),
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        Some(""),
    )?;
    debug!("mounted `/` with `MsFlags::MS_PRIVATE`");

    Ok(())
}

/// Mounts `procfs` at `path`.
pub fn procfs(path: &Path) -> Result<()> {
    mount::mount(Some("proc"), path, Some("proc"), MsFlags::empty(), Some(""))?;
    debug!("mounted `procfs` at `{:?}`", path);

    Ok(())
}

/// Creates a [`MsFlags::MS_BIND`] mount between `src` and `dst`.
pub fn bind(src: &Path, dst: &Path) -> Result<()> {
    mount::mount(Some(src), dst, Some(""), MsFlags::MS_BIND, Some(""))?;
    debug!("created bind mount {:?} -> {:?}", src, dst);

    Ok(())
}
