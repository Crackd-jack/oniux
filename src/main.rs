use std::{
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{self},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use caps::{CapSet, Capability, CapsHashSet};
use clap::Parser;
use ipc_channel::ipc::IpcReceiver;
use log::{debug, info};
use netlink_packet_route::AddressFamily;
use nix::mount::{self, MsFlags};
use nix::{
    fcntl::{self, OFlag},
    libc,
    sched::{self, CloneFlags},
    sys::{
        stat::Mode,
        wait::{self, WaitStatus},
    },
    unistd::{self},
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

/// Limit the capabilities of the process in case they were too high
///
/// This function limits the capabilities of the process in case they were too high,
/// by adjusting all capability sets to the bare minimum required for this software
/// to function properly.
///
/// The calling function only needs to ensure that [`Capability::CAP_SYS_ADMIN`]
/// and [`Capability::CAP_NET_ADMIN`] are present in [`CapSet::Permitted`].
///
/// This function panics in case of a failure and double checks its success,
/// because failure here is not tolerable.
///
/// The function should generally be called as soon as possible and only once.
fn limit_caps() {
    let sys_net = CapsHashSet::from([Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN]);

    // `Permitted` and `Effective` obviously need `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`,
    // because this application and its child processes need to create namespaces
    // as well as to move network interfaces between namespaces, alongside various
    // other network stack related operations required elevated capabilities.
    caps::set(None, CapSet::Permitted, &sys_net).unwrap();
    caps::set(None, CapSet::Effective, &sys_net).unwrap();
    assert_eq!(caps::read(None, CapSet::Permitted).unwrap(), sys_net);
    assert_eq!(caps::read(None, CapSet::Effective).unwrap(), sys_net);

    // `Inheritable` and `Ambiet` are in my (cve) opinion too hard to use properly.
    // The only benefit that they would offer would be, to launch the onionmasq
    // binary with the required capabilities, even if the file capabilities are
    // lower.  This convience feature does not justify the increased security risk
    // by using them.
    caps::clear(None, CapSet::Inheritable).unwrap();
    caps::clear(None, CapSet::Ambient).unwrap();
    assert_eq!(
        caps::read(None, CapSet::Inheritable).unwrap(),
        CapsHashSet::new()
    );
    assert_eq!(
        caps::read(None, CapSet::Ambient).unwrap(),
        CapsHashSet::new()
    );
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
    netlink::add_address(
        index,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1)),
        96,
    )?;
    netlink::set_up(index)?;
    netlink::set_default_gateway(index, AddressFamily::Inet)?;
    netlink::set_default_gateway(index, AddressFamily::Inet6)?;
    debug!("finished setting up networking");

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
    resolv_conf.write_all("nameserver 169.254.42.53\nnameserver fe80::53\n".as_bytes())?;
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

    caps::clear(None, CapSet::Permitted).unwrap();
    debug!("cleared all capabilities in isolation process");

    let cmd: Vec<CString> = cmd.iter().map(|s| CString::from_str(s).unwrap()).collect();
    unistd::execvp(&cmd[0], &cmd)?;
    unreachable!()
}

fn onionmasq(path: &Path, device: &str) -> Result<isize> {
    // Clear all `Permitted` capabilities for the process.
    caps::clear(None, CapSet::Permitted).unwrap();
    debug!("cleared permitted capabilities in onionmasq");

    let path = [path.as_os_str().as_bytes(), "\0".as_bytes()].concat();
    let path = CStr::from_bytes_with_nul(&path)?;

    let args: Vec<CString> = vec![path.into(), CString::new("-d")?, CString::new(device)?];

    // Redirect stdin, stdout, and stderr to `/dev/null`
    let nullfd = fcntl::open("/dev/null", OFlag::O_RDWR, Mode::empty())?;
    unistd::dup2(nullfd, 0)?;
    unistd::dup2(nullfd, 1)?;
    unistd::dup2(nullfd, 2)?;

    unistd::execv(path, &args)?;
    unreachable!()
}

fn main_main() -> Result<isize> {
    env_logger::init();

    let args = Args::parse();

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
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET,
            Some(libc::SIGCHLD),
        )?
    };
    debug!("spawned isolation with PID {}", isolation_proc.as_raw());

    netlink::set_ns(index, isolation_proc.as_raw() as u32)?;
    tx.send(index)?;

    // Parent no longer needs capabilities too
    caps::clear(None, CapSet::Permitted).unwrap();
    debug!("cleared permitted capabilities in main process");

    match wait::waitpid(isolation_proc, None)? {
        WaitStatus::Exited(_, code) => {
            info!("isolated process exited with {code}");
            process::exit(code);
        }
        res => {
            info!("isolated process exited with {:?}", res);
            process::exit(1);
        }
    }
}

fn main() -> Result<()> {
    // Check the capabilities
    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_SYS_ADMIN)? {
        bail!("not having CAP_SYS_ADMIN capability");
    }
    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_NET_ADMIN)? {
        bail!("not having CAP_NET_ADMIN capability");
    }

    limit_caps();

    let mut stack = gen_stack();
    let proc = unsafe {
        sched::clone(
            Box::new(|| main_main().unwrap()),
            &mut stack,
            CloneFlags::CLONE_NEWPID,
            Some(libc::SIGCHLD),
        )
    }?;

    match wait::waitpid(proc, None)? {
        WaitStatus::Exited(_, code) => process::exit(code),
        _ => process::exit(1),
    }
}
