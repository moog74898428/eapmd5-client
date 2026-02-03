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
| | `--mac` | `EAP_MAC` | Override source MAC address (e.g. `00:11:22:33:44:55`) |
| | `--wait-on-failure` | `EAP_WAIT_ON_FAILURE` | Wait for reauth instead of exiting on initial auth failure |

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

### RouterOS Container

To run on MikroTik RouterOS with container support:

1. Pull the image and create a mount for the registry:

```
/container/config set registry-url=https://ghcr.io tmpdir=usb1/pull
/container/add remote-image=<owner>/eapmd5-client:latest interface=veth1 root-dir=usb1/containers/eapmd5 \
    envlist=eapmd5-env
```

2. Create environment variables:

```
/container/envs
add name=eapmd5-env key=EAP_INTERFACE value=veth1
add name=eapmd5-env key=EAP_USERNAME value=your_username
add name=eapmd5-env key=EAP_PASSWORD value=your_password
add name=eapmd5-env key=EAP_MAC value=00:11:22:33:44:55
```

3. Create a veth interface and bridge it to WAN:

```
/interface/veth add name=veth1 address=192.168.100.2/24 gateway=192.168.100.1
/interface/bridge/port add bridge=bridge-wan interface=veth1
```

4. Start the container:

```
/container/start 0
```

Note: Set `EAP_MAC` to match the MAC address of your WAN interface for ISPs that bind authentication to MAC.

## License

MIT
