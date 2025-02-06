# oniux

**WARNING:** This is experimental software, do not use it.

## Usage

```sh
cargo build
sudo setcap cap_net_admin,cap_sys_admin+ep ./target/debug/oniux
./target/debug/oniux --onionmasq /path/to/onionmasq/binary curl https://amiusingtor.net
```