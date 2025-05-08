# qxvanity

Fast vanity key generator.

## Features

- Supports several key formats
- Regex matching
- Multiple patterns

## Supported key formats

- WireGuard
- SSH Ed25519

## Usage

```
$ git clone https://github.com/nagornin/qxvanity
$ cd qxvanity
$ RUSTFLAGS='-C target-cpu=native' cargo build --release
$ target/release/qxvanity -t wireguard '^(?i)Test'
[2025-05-06T23:25:02Z INFO  qxvanity] Found a matching keypair
private:
DjrNB8TqjyvZ/6DKjyJ7OyLOCjG/6EP5AEOKZbYmBvk=

public:
TeSttzybp0UXNtizfTr0ND9A2Kl0cjQbNcUFxSkfSkY=
```

To enable case-insensitive matching, use `(?i)`. For example, `^(?i)Test` will search for keys that start with "Test" regardless of case.

```
Usage: qxvanity [OPTIONS] --type <KIND> <PATTERNS>...

Arguments:
  <PATTERNS>...  Regex patterns to search public keys for

Options:
  -t, --type <KIND>
          Type of keypair to generate [possible values: wireguard, ssh-ed25519]
  -s, --status-interval <STATUS_INTERVAL>
          Print search status with this interval, 0 to never print [default: 5s]
  -c, --count <COUNT>
          Number of matching keypairs to generate, 0 to keep generating forever [default: 1]
  -p, --threads <THREADS>
          Number of threads [default: auto]
  -k, --match-key-material
          Only match the actual key material, ignore any metadata
  -h, --help
          Print help
```

## Performance

Tested on a Ryzen 7 5800U (HP ProBook 455 G8).

```
$ RUSTFLAGS='-C target-cpu=native' cargo run --release -- -t <type> '^Test'
```

| Key type    | Average keys/s | Max keys/s |
| ----------- | -------------- | ---------- |
| WireGuard   | 350,000        | 520,000    |
| SSH Ed25519 | 345,000        | 505,000    |

## Notes

- You almost certainly will get better performance if you compile this with `-C target-cpu=native` or similar. On my laptop it speeds up search by about 20%.
