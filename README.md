# eapmd5-client

Minimal EAP-MD5 (IEEE 802.1X) authentication client written in Rust.

Raw AF_PACKET socket to send/receive EAPOL frames directly on the specified network interface. Authenticates using EAP-MD5 challenge-response (RFC 3748) and maintains the session by handling reauthentication requests.

## Usage

Requires `CAP_NET_RAW` capability or root privileges.

```
eapmd5-client -i <interface> -u <username> -p <password>
```

| Flag | Long | Env | Description |
|------|------|-----|-------------|
| `-i` | `--interface` | `EAP_INTERFACE` | Network interface name |
| `-u` | `--username` | `EAP_USERNAME` | Username |
| `-p` | `--password` | `EAP_PASSWORD` | Password |
| | `--no-logoff` | `EAP_NO_LOGOFF` | Do not send EAPOL-Logoff on exit |

Log level is controlled via `RUST_LOG` (default: `info`).

## Build

```
cargo build --release
```

## Docker

```
docker compose up -d
```

Edit `docker-compose.yml` to set your interface, username, and password. `network_mode: host` and `CAP_NET_RAW` are required.

Container images for arm64 are published to GHCR on each push to `main`:

```
docker pull ghcr.io/<owner>/eapmd5-client:latest
```

## License

MIT
