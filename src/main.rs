use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{self},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use caps::{CapSet, Capability};
use clap::Parser;
use ipc_channel::ipc::IpcReceiver;
use log::debug;
use nix::mount::{self, MsFlags};
use nix::{
    fcntl::{self, OFlag},
    libc,
    sched::{self, CloneFlags},
    sys::{
        stat::Mode,
        wait::{self, WaitStatus},
    },
    unistd::{self, ForkResult, Pid},
};
use std::thread;

mod netlink;

/// The size of the stacks of our child processes
const STACK_SIZE: usize = 1000 * 1000 * 8;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the onionmasq binary
    #[arg(long, default_value = "onionmasq")]
    onionmasq: PathBuf,

    /// The actual program to execute
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
}

/// Drop all capabilities in all capability sets
///
/// This function panics in case of failure and double-checks if the operation has been successful.
/// It is intentional, as failures are absolutely not tolerable in this function.
fn drop_caps() {
    let cap_sets = [
        CapSet::Ambient,
        // CapSet::Bounding,
        // ^^^^^^^^^^^^^^^^ but why?
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Permitted,
    ];

    // Clear all capabilities
    for cap in cap_sets {
        caps::clear(None, cap).unwrap();

        if !caps::read(None, cap).unwrap().is_empty() {
            panic!("dropping capabilities failed");
        }
    }
}

/// Generate an device name
fn gen_device_name() -> String {
    "onion0".into()
}

/// Generate an empty stack for calls to `clone(2)`
fn gen_stack() -> Vec<u8> {
    vec![0u8; STACK_SIZE]
}

fn isolation(cmd: &Vec<String>, rx: Arc<IpcReceiver<u32>>) -> Result<isize> {
    // Wait until our parent has set up everything nicely
    let index = rx.recv()?;

    // Configure the IP addresses of the interface
    netlink::add_address(index, IpAddr::V4(Ipv4Addr::new(169, 254, 42, 1)), 24)?;
    netlink::set_up(index)?;
    netlink::add_gateway(IpAddr::V4(Ipv4Addr::new(169, 254, 42, 1)))?;
    debug!("finished setting up the device");

    // Add DNS support
    mount::mount(
        Some(""),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_PRIVATE,
        Some(""),
    )?;
    debug!("mounted /tmp");

    let mut resolv_conf = File::create("/tmp/resolv.conf")?;
    resolv_conf.write_all("nameserver 169.254.42.53".as_bytes())?;
    drop(resolv_conf);
    debug!("created /tmp/resolv.conf");

    mount::mount(
        Some("/tmp/resolv.conf"),
        "/etc/resolv.conf",
        Some(""),
        MsFlags::MS_BIND | MsFlags::MS_PRIVATE,
        Some(""),
    )?;
    debug!("mounted /tmp/resolv.conf to /etc/resolv.conf");

    // VERY VERY IMPORTANT
    drop_caps();

    let cmd: Vec<CString> = cmd.iter().map(|s| CString::from_str(s).unwrap()).collect();
    unistd::execvp(&cmd[0], &cmd)?;

    Ok(0)
}

fn onionmasq(path: &Path, device: &str) -> Result<isize> {
    // VERY IMPORTANT
    drop_caps();

    let path = [path.as_os_str().as_bytes(), "\0".as_bytes()].concat();
    let path = CStr::from_bytes_with_nul(&path)?;

    let args: Vec<CString> = vec![path.into(), CString::new("-d")?, CString::new(device)?];

    // Redirect stdin, stdout, and stderr to `/dev/null`
    let nullfd = fcntl::open("/dev/null", OFlag::O_RDWR, Mode::empty())?;
    unistd::dup2(nullfd, 0)?;
    unistd::dup2(nullfd, 1)?;
    unistd::dup2(nullfd, 2)?;

    unistd::execv(path, &args)?;

    Ok(0)
}

fn main_main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Check if we run in a PID namespace
    if Pid::this().as_raw() != 1 {
        bail!("not running as PID 1 in a PID namespace");
    }

    // Check the capabilities
    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_SYS_ADMIN)? {
        bail!("not having CAP_SYS_ADMIN capability");
    }
    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_NET_ADMIN)? {
        bail!("not having CAP_NET_ADMIN capability");
    }

    let device = gen_device_name();

    let mut onionmasq_stack = gen_stack();
    let onionmasq_proc = unsafe {
        sched::clone(
            Box::new(|| onionmasq(&args.onionmasq, &device).unwrap()),
            &mut onionmasq_stack,
            CloneFlags::empty(),
            None,
        )?
    };
    debug!("spawned onionmasq with PID {}", onionmasq_proc.as_raw());
    thread::sleep(Duration::from_millis(500));
    debug!("waited 500ms for onionmasq to start up");

    let index = netlink::get_index(&device)?;
    debug!("found {device} interface with index {index}");

    let (tx, rx) = ipc_channel::ipc::channel::<u32>()?;
    let rx = Arc::new(rx);
    let mut isolation_stack = gen_stack();
    let isolation_proc = unsafe {
        sched::clone(
            Box::new(move || isolation(&args.cmd, rx.clone()).unwrap()),
            &mut isolation_stack,
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER,
            Some(libc::SIGCHLD),
        )?
    };
    debug!("spawned isolation with PID {}", isolation_proc.as_raw());

    netlink::set_ns(index, isolation_proc.as_raw() as u32)?;
    tx.send(index)?;

    // Parent no longer needs capabilities too
    drop_caps();

    match wait::waitpid(isolation_proc, None)? {
        WaitStatus::Exited(_, code) => process::exit(code),
        _ => process::exit(1),
    }
}

fn main() -> Result<()> {
    // TODO: Use clone(2) here, because it would be more consistent with the codebase then
    sched::unshare(CloneFlags::CLONE_NEWPID)?;
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            main_main().unwrap();
            process::exit(0);
        }
        ForkResult::Parent { child } => match wait::waitpid(child, None)? {
            WaitStatus::Exited(_, code) => process::exit(code),
            _ => process::exit(1),
        },
    }
}
