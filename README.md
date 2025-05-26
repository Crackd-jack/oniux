# oniux

**This is still considered experimental software!**

*oniux* is a tool that utilizes various Linux `namespaces(7)` in order to isolate
an arbitrary application over the Tor network.  To achieve this, it makes heavy
use of the [onionmasq](https://gitlab.torproject.org/tpo/core/onionmasq), which
offers a TUN device to send Tor traffic through.

## Usage

```sh
cargo build
./target/debug/oniux curl https://check.torproject.org
```

Running *oniux* will require the `tun` kernel module.  Usually, it should be
loaded by default in most Linux distributions, but if you get a `File not found`
error while running *oniux*, you may want to do a `modprobe tun` and run *oniux*
again.

## Security

While *oniux* makes it harder for an application to leak than *torsocks*, it
does not mean *oniux* is immune to it.  Primarily, malconfigured applications
can still leak in the case they communicate (for example via Unix domain
sockets) to processes outside of *oniux*.  A good example for that might be an
instance of *Emacs* in the server mode.  If the server process runs outside of
*oniux*, then obviously all clients that connect to it, will leak network
connections, regardless if the various Emacs clients are run through *oniux* or
not.  This is a technical limitation of network namespaces.  Unfortunately,
there is no real way to block IPC without compromising usability, as in that
case, an application isolated via *oniux* would probably provide no difference
towards an isolation done via a virtual machine or an ordinary container.

## Internal Workings

*oniux* works by immediately spawning a child process using the `clone(2)`
system call, which is isolated in its own network, mount, PID, and user
namespace.  This process then mounts its own copy of `/proc` followed by
UID and GID mappings to the respective UID and GID of the parent process.
Afterwards, it creates a temporary file with nameserver entries which will then
be bind mounted onto `/etc/resolv.conf`, so that applications running within the
namespace will use onionmasq's own DNS resolver.  Next, the child process will
create a TUN interface named `onion0` followed by some `rtnetlink(7)` operations
required to set up the interface, such as assigning IP addresses.  Then, the
child process will send the file descriptor of the TUN interface over a Unix
Domain socket to the parent process, who has been waiting for this message ever
since executing the `clone(2)` beforehand.  Once that is done, the child process
will drop all of its capabilities which were acquired as part of being the root
process in the user namespace.  Finally, the command supplied by the user will
be executed using facilities provided by the Rust standard library.

## Credits

Many thanks go to `7ppKb5bW`, who taught me on how this can implemented without
the use of `capabilities(7)` by using `user_namespaces(7)` properly.
