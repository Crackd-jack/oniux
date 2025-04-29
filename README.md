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

**TODO**

## Credits

Many thanks go to `7ppKb5bW`, who taught me on how this can implemented without
the use of `capabilities(7)` by using `user_namespaces(7)` properly.
