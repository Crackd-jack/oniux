use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::{self, Child, Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{bail, Result};
use log::debug;

/// Wrapper around the `unshare(2)` system call.
fn unshare(flags: i32) -> Result<()> {
    unsafe {
        let rc = libc::unshare(flags);
        if rc == 0 {
            Ok(())
        } else {
            bail!("unshare(2) failed with errno {}", *libc::__errno_location());
        }
    }
}

/// Wrapper around `fork(2)` that accepts a main function for the child.
fn fork<F: FnOnce() -> i32>(f: F) -> Result<i32> {
    let rc = unsafe { libc::fork() };
    if rc == -1 {
        bail!("fork(2) failed with errno {}", unsafe {
            *libc::__errno_location()
        });
    }

    if rc == 0 {
        // Child
        process::exit(f());
    } else {
        // Parent
        Ok(rc)
    }
}

/// Spawns a child process with all buffers being `/dev/null`.
fn spawn_silent_child(cmd: &str) -> Result<Child> {
    let mut cmd = Command::new(cmd);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    Ok(cmd.spawn()?)
}

fn main() -> Result<()> {
    env_logger::init();

    // TODO: Add handler for SIGCHLD?
    let onionmasq = spawn_silent_child("./target/debug/onionmasq")?;
    thread::sleep(Duration::from_millis(500));
    debug!("spawned onionmasq with PID {}", onionmasq.id());

    let (mut parent, mut child) = UnixStream::pair()?;
    debug!("created UnixStream");

    let proc = fork(|| {
        unshare(libc::CLONE_NEWNET & libc::CLONE_NEWNS).unwrap();

        Command::new("mount")
            .arg("-t")
            .arg("tmpfs")
            .arg("none")
            .arg("/tmp")
            .status()
            .unwrap();

        let mut resolv_conf = File::create("/tmp/resolv.conf").unwrap();
        resolv_conf
            .write_all("nameserver 169.254.42.53".as_bytes())
            .unwrap();
        drop(resolv_conf);

        Command::new("mount")
            .arg("--bind")
            .arg("/tmp/resolv.conf")
            .arg("/etc/resolv.conf")
            .status()
            .unwrap();

        // Only continue if parent has allowed us to.
        let mut buf = vec![0_u8];
        child.read(&mut buf).unwrap();

        let path = CString::new("/usr/bin/curl").unwrap();
        let argv = [
            path.clone(),
            CString::new("http://amiusingtor.net").unwrap(),
        ];
        let argv_p: Vec<*const u8> = argv
            .iter()
            .map(|arg| arg.as_ptr())
            .chain([std::ptr::null()])
            .collect();

        let rc = unsafe { libc::execv(path.as_ptr(), argv_p.as_ptr()) };
        if rc != 0 {
            panic!("call to execv failed with errno {}", unsafe {
                *libc::__errno_location()
            });
        }
        unreachable!()
    })?;
    thread::sleep(Duration::from_millis(500));
    debug!("spawned child with PID {}", proc);

    Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("onion0")
        .arg("netns")
        .arg(proc.to_string())
        .status()?;

    Command::new("nsenter")
        .arg(format!("--net=/proc/{proc}/ns/net"))
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg("onion0")
        .arg("up")
        .status()?;

    Command::new("nsenter")
        .arg(format!("--net=/proc/{proc}/ns/net"))
        .arg("ip")
        .arg("addr")
        .arg("add")
        .arg("169.254.42.1/24")
        .arg("dev")
        .arg("onion0")
        .status()?;

    Command::new("nsenter")
        .arg(format!("--net=/proc/{proc}/ns/net"))
        .arg("ip")
        .arg("route")
        .arg("add")
        .arg("default")
        .arg("via")
        .arg("169.254.42.1")
        .arg("dev")
        .arg("onion0")
        .status()?;

    parent.write_all("\0".as_bytes()).unwrap();

    let mut status = 0;
    let rc = unsafe { libc::waitpid(proc, &mut status, 0) };
    if rc == -1 {
        panic!("waitpid(2) failed with errno {}", unsafe {
            *libc::__errno_location()
        });
    }

    if libc::WIFEXITED(status) {
        std::process::exit(libc::WEXITSTATUS(status));
    } else {
        std::process::exit(1);
    }
}
