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

1. Create a veth interface:

```
/interface veth add name=veth-eapmd5 address=10.88.88.1/24 gateway=10.88.88.254
```

2. Configure the WAN bridge to forward reserved addresses (required for EAPOL):

```
/interface bridge set bridge1 protocol-mode=none forward-reserved-addresses=yes
/interface bridge port add bridge=bridge1 interface=veth-eapmd5
```

3. Add bridge filter rules to block unwanted traffic from the container:

```
/interface bridge filter
add chain=forward in-interface=veth-eapmd5 mac-protocol=0x888e action=accept comment="Allow EAPOL from container"
add chain=forward in-interface=veth-eapmd5 action=drop comment="Drop all other traffic from container"
```

4. Create environment variables:

```
/container envs
add list=eapmd5 key=EAP_INTERFACE value=veth-eapmd5
add list=eapmd5 key=EAP_MAC value=AA:BB:CC:DD:EE:FF
add list=eapmd5 key=EAP_USERNAME value=YOUR_USERNAME
add list=eapmd5 key=EAP_PASSWORD value=YOUR_PASSWORD
add list=eapmd5 key=EAP_NO_LOGOFF value=true
```

5. Create and start the container:

```
/container add name=eapmd5-client \
    interface=veth-eapmd5 \
    remote-image=ghcr.io/<owner>/eapmd5-client:latest \
    root-dir=/usb1/containers/eapmd5 \
    envlist=eapmd5 \
    start-on-boot=yes \
    logging=yes
```

Note: Set `EAP_MAC` to match the MAC address of your WAN interface for ISPs that bind authentication to MAC. The `forward-reserved-addresses=yes` setting is required to pass EAPOL frames (destination `01:80:C2:00:00:03`) through the bridge.

## License

MIT
