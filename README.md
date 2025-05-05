# oniux

**This is still considered experimental software!**

*oniux* is a tool that utilizes various Linux `namespaces(7)` in order to isolate
an arbitrary application over the Tor network.  To achieve this, it makes heavy
use of the [onionmasq](https://gitlab.torproject.org/tpo/core/onionmasq), which
offers a TUN device to send Tor traffic through.

## Usage

```sh
cargo build
./target/debug/oniux curl https://amiusingtor.net
```

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
