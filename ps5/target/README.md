# Rust PS5 target

`x86_64-ps5-freebsd.json` comes from the `ps5/` directory of
[`ps5-dump-forge`](https://github.com/quer3q/ps5-dump-forge) (GPL-3.0),
revision `2e0745e`. It is kept here so the Rust build gets its PIC,
red-zone, TLS and panic settings.
