Netinfo
----------

Netinfo is a Rust library and command line application that groups network usage by process. It works in a nethogs-like way, so you don't need a special kernel module.

In comparison to nethogs, it also supports UDP connections.

Because it heavily uses the `/proc`-filesystem, only Linux is supported at the moment.

[Documentation](https://docs.rs/netinfo)

[Crates.io](https://crates.io/crates/netinfo)

How to use the library
----------

Add this to your `Cargo.toml`:

```toml
[dependencies]
netinfo = 0.2
```

How to compile the binary
----------

Install Rust and Cargo, then call:

```bash
# This will create the binary `~/.cargo/bin/netinfo`
$ cargo install netinfo
```

Running binaries
----------

To avoid `Permission denied` errors, you will either have to run the progam as root or allow the program to capture the network traffic:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/your/bin
```
