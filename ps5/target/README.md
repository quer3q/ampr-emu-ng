# Rust PS5 target

`x86_64-ps5-freebsd.json` comes from the `ps5/` directory of
[`ps5-dump-forge`](https://github.com/quer3q/ps5-dump-forge), revision
`2e0745e`. That project is GPL-3.0. Keep the target definition in this
repository so the Rust build uses its PIC, red-zone, TLS, and panic settings.
