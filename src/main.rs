use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixDatagram,
    },
    path::PathBuf,
    process::{Command, ExitCode, ExitStatus},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use caps::CapSet;
use clap::Parser;
use log::debug;
use netlink_packet_route::AddressFamily;
use nix::{
    libc,
    sched::{self, CloneFlags},
    sys::wait::{self, WaitStatus},
    unistd::{Gid, Uid},
};
use onion_tunnel::{config::TunnelConfig, scaffolding::LinuxScaffolding, OnionTunnel};
use sendfd::{RecvWithFd, SendWithFd};
use smoltcp::phy::{Medium, TunTapInterface};
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

mod mount;
mod netlink;
mod user;

/// The size of the stacks of our child processes
const STACK_SIZE: usize = 1000 * 1000 * 8;

/// The name of the loopback device
const LOOPBACK_DEVICE: &str = "lo";

/// The name of the TUN device
const DEVICE_NAME: &str = "onion0";

#[derive(Parser, Debug)]
struct Args {
    /// The actual program to execute
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
}

/// Generate an empty stack for calls to `clone(2)`
fn gen_stack() -> Vec<u8> {
    vec![0u8; STACK_SIZE]
}

fn isolation(parent: UnixDatagram, uid: Uid, gid: Gid, cmd: &[String]) -> Result<ExitStatus> {
    // Initialize the mount namespace properly.
    mount::init_namespace()?;
    mount::procfs(&PathBuf::from("/proc"))?;
    debug!("finished mount namespace setup");

    // Perform UID and GID mappings.
    user::setgroups(false)?;
    user::uid_map(uid, uid)?;
    user::gid_map(gid, gid)?;
    debug!("finished user namespace mappings");

    // Overwrite `/etc/resolv.conf` with a bind mound to use the nameservers
    // provided by onionmasq.
    let mut resolv_conf = NamedTempFile::new()?;
    resolv_conf.write_all("nameserver 169.254.42.53\nnameserver fe80::53\n".as_bytes())?;
    debug!(
        "created temporary resolv.conf(5) at {:?}",
        resolv_conf.path()
    );
    mount::bind(resolv_conf.path(), &PathBuf::from("/etc/resolv.conf"))?;
    debug!("mounted {:?} to /etc/resolv.conf", resolv_conf.path());

    // Setup the loopback device.
    let loopback_index = netlink::get_index(LOOPBACK_DEVICE)?;
    netlink::add_address(loopback_index, IpAddr::V4(Ipv4Addr::LOCALHOST), 8)?;
    netlink::add_address(loopback_index, IpAddr::V6(Ipv6Addr::LOCALHOST), 128)?;
    netlink::set_up(loopback_index)?;
    debug!("finished setting up {LOOPBACK_DEVICE}");

    // Create and configure a TUN interface for use with onionmasq.
    let tun = TunTapInterface::new(DEVICE_NAME, Medium::Ip)
        .context("failed to open tun interface, is tun kmod loaded?")?;
    let tun_index = netlink::get_index(DEVICE_NAME)?;
    netlink::add_address(tun_index, IpAddr::V4(Ipv4Addr::new(169, 254, 42, 1)), 24)?;
    netlink::add_address(
        tun_index,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1)),
        96,
    )?;
    netlink::set_up(tun_index)?;
    netlink::set_default_gateway(tun_index, AddressFamily::Inet)?;
    netlink::set_default_gateway(tun_index, AddressFamily::Inet6)?;
    debug!("finished setting up the TUN device");

    // Drop all capabilities.
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Ambient)?;
    debug!("dropped all capabilites");

    // Send the device to the parent.
    parent.send_with_fd(&[0; 1024], &[tun.as_raw_fd()])?;
    drop(tun);
    debug!("sent TUN device");

    // The 100ms is a rather arbitrary timeout, but it probably does not hurt
    // to wait until the parent has received the file descriptor and launched
    // the onion-tunnel thread.
    // TODO: Consider using IPC here to indicate that we can continue although
    // that might be a little bit overkill.
    thread::sleep(Duration::from_millis(100));

    // Run the actual child and wait for its termination.
    // It is important to not use something like `execve` or anything that else
    // that could hinder the execution of Rust Drop traits, as otherwise the
    // `resolv_conf` file will leak into the temporary directory.
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .spawn()
        .context("failed to spawn command")?;
    Ok(child.wait()?)
}

fn main() -> Result<ExitCode> {
    // Initialize the application.
    env_logger::init();
    let args = Args::parse();

    // Create IPC primitives.
    let (parent, child) = UnixDatagram::pair()?;

    // Obtain user information.
    let uid = Uid::current();
    let gid = Gid::current();

    let mut stack = gen_stack();
    let proc = unsafe {
        sched::clone(
            Box::new(|| {
                // This statement looks a bit complicated but all it does is
                // converting `Result<ExitStatus, Error>` to `isize`.
                isolation(parent.try_clone().unwrap(), uid, gid, &args.cmd)
                    .map(|exit_status| exit_status.code().unwrap_or(1))
                    // fail with status 127 if we failed to spawn the process
                    .inspect_err(|e| eprintln!("failed to spawn command: {e:?}"))
                    .unwrap_or(127)
                    .try_into()
                    .unwrap() // all i32 are be castable to isize on 32/64b platforms
            }),
            &mut stack,
            CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWUSER,
            Some(libc::SIGCHLD),
        )
    }?;
    drop(parent);

    // Receive file descriptor.
    let mut fds = [-1];
    let (_, nfds) = child.recv_with_fd(&mut [0; 1024], &mut fds)?;
    assert_eq!(nfds, 1);
    assert_ne!(fds[0], -1);
    let tun = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    debug!("received TUN file descriptor");

    // Spawn task to handle the TUN device in.
    // Maybe we could use `Runtime::spawn` instead, but spawning the task
    // ourselves in combinating with `Runtime::block_on` gives me a more fuzzy
    // feeling in terms of control.
    thread::spawn(|| {
        Runtime::new().unwrap().block_on(async move {
            let can_mark = LinuxScaffolding::can_mark();
            let scaffolding = LinuxScaffolding {
                can_mark,
                cc: None,
                log_connections: false,
            };
            let mut tunnel = OnionTunnel::create_with_fd(scaffolding, tun, TunnelConfig::default())
                .await
                .unwrap();

            tunnel.run().await
        })
    });
    debug!("spawned onion-tunnel thread");

    // Wait until the isolation process `proc` has finished and return its
    // status as an `ExitCode`.
    match wait::waitpid(proc, None)? {
        WaitStatus::Exited(_, code) => Ok(ExitCode::from(u8::try_from(code)?)),
        _ => Ok(ExitCode::FAILURE),
    }
}
