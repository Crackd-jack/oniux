//! Helper functions for `user_namespaces(7)`.
//!
//! All functions require a working procfs mount at `/proc`.

use std::{fs::File, io::Write};

use anyhow::Result;
use log::debug;
use nix::unistd::{Gid, Uid};

/// Performs a 1-by-1 mapping of two [`Uid`]'s.
///
/// This function may only be called once per `user_namespaces(7)`.
pub fn uid_map(inner: Uid, outer: Uid) -> Result<()> {
    let mut f = File::create("/proc/self/uid_map")?;
    f.write(format!("\t{inner}\t{outer}\t1\n").as_bytes())?;
    debug!("mapped UID {inner} to {outer}");

    Ok(())
}

/// Performs a 1-by-1 mapping of two [`Gid`]'s.
///
/// This function may only be called once per `user_namespaces(7)`.
pub fn gid_map(inner: Gid, outer: Gid) -> Result<()> {
    let mut f = File::create("/proc/self/gid_map")?;
    f.write(format!("\t{inner}\t{outer}\t1\n").as_bytes())?;
    debug!("mapped GID {inner} to {outer}");

    Ok(())
}

/// Allow `setgroups(2)` system call in the `user_namespaces(7)`?
///
/// This function may only be called once per `user_namespaces(7)`.
pub fn setgroups(allow: bool) -> Result<()> {
    let value = if allow {
        "allow\n".as_bytes()
    } else {
        "deny\n".as_bytes()
    };

    let mut f = File::create("/proc/self/setgroups")?;
    f.write(value)?;
    debug!("setgroups {allow}");

    Ok(())
}
