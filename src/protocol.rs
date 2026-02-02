/// 802.1X PAE group multicast address
pub const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// EtherType for 802.1X (EAP over LAN)
pub const ETH_P_PAE: u16 = 0x888E;

pub const EAPOL_VERSION: u8 = 1;

// EAPOL packet types
pub const EAPOL_EAP_PACKET: u8 = 0;
pub const EAPOL_START: u8 = 1;
pub const EAPOL_LOGOFF: u8 = 2;

// EAP codes
pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;

// EAP types
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5: u8 = 4;

// Minimum Ethernet frame size (excluding FCS)
const MIN_ETH_FRAME: usize = 60;

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

fn padded(mut frame: Vec<u8>) -> Vec<u8> {
    if frame.len() < MIN_ETH_FRAME {
        frame.resize(MIN_ETH_FRAME, 0);
    }
    frame
}

fn push_eth_header(buf: &mut Vec<u8>, dst: &[u8; 6], src: &[u8; 6]) {
    buf.extend_from_slice(dst);
    buf.extend_from_slice(src);
    buf.extend_from_slice(&ETH_P_PAE.to_be_bytes());
}

fn push_eapol_header(buf: &mut Vec<u8>, ptype: u8, body_len: u16) {
    buf.push(EAPOL_VERSION);
    buf.push(ptype);
    buf.extend_from_slice(&body_len.to_be_bytes());
}

pub fn build_eapol_start(src_mac: &[u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(MIN_ETH_FRAME);
    push_eth_header(&mut f, &PAE_GROUP_ADDR, src_mac);
    push_eapol_header(&mut f, EAPOL_START, 0);
    padded(f)
}

pub fn build_eapol_logoff(src_mac: &[u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(MIN_ETH_FRAME);
    push_eth_header(&mut f, &PAE_GROUP_ADDR, src_mac);
    push_eapol_header(&mut f, EAPOL_LOGOFF, 0);
    padded(f)
}

pub fn build_eap_response_identity(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    id: u8,
    username: &[u8],
) -> Vec<u8> {
    // EAP: code(1) + id(1) + length(2) + type(1) + identity
    let eap_len = 5u16 + username.len() as u16;
    let mut f = Vec::with_capacity(MIN_ETH_FRAME);
    push_eth_header(&mut f, dst_mac, src_mac);
    push_eapol_header(&mut f, EAPOL_EAP_PACKET, eap_len);
    // EAP packet
    f.push(EAP_RESPONSE);
    f.push(id);
    f.extend_from_slice(&eap_len.to_be_bytes());
    f.push(EAP_TYPE_IDENTITY);
    f.extend_from_slice(username);
    padded(f)
}

pub fn build_eap_response_md5(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    id: u8,
    hash: &[u8; 16],
    username: &[u8],
) -> Vec<u8> {
    // EAP: code(1) + id(1) + length(2) + type(1) + value_size(1) + value(16) + name
    let eap_len = 6u16 + 16 + username.len() as u16;
    let mut f = Vec::with_capacity(MIN_ETH_FRAME);
    push_eth_header(&mut f, dst_mac, src_mac);
    push_eapol_header(&mut f, EAPOL_EAP_PACKET, eap_len);
    // EAP packet
    f.push(EAP_RESPONSE);
    f.push(id);
    f.extend_from_slice(&eap_len.to_be_bytes());
    f.push(EAP_TYPE_MD5);
    f.push(16); // value size
    f.extend_from_slice(hash);
    f.extend_from_slice(username);
    padded(f)
}

pub fn build_eap_response_nak(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    id: u8,
    desired_type: u8,
) -> Vec<u8> {
    // EAP: code(1) + id(1) + length(2) + type(1) + desired_auth_type(1)
    let eap_len = 6u16;
    let mut f = Vec::with_capacity(MIN_ETH_FRAME);
    push_eth_header(&mut f, dst_mac, src_mac);
    push_eapol_header(&mut f, EAPOL_EAP_PACKET, eap_len);
    f.push(EAP_RESPONSE);
    f.push(id);
    f.extend_from_slice(&eap_len.to_be_bytes());
    f.push(EAP_TYPE_NAK);
    f.push(desired_type);
    padded(f)
}

// ---------------------------------------------------------------------------
// Frame parsers
// ---------------------------------------------------------------------------

pub struct EapolFrame {
    pub src_mac: [u8; 6],
    pub packet_type: u8,
    pub body: Vec<u8>,
}

pub struct EapPacket {
    pub code: u8,
    pub id: u8,
    pub eap_type: Option<u8>,
    pub data: Vec<u8>,
}

impl EapolFrame {
    /// Parse an Ethernet + EAPOL frame.  Returns `None` if too short or wrong
    /// EtherType.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        // Ethernet(14) + EAPOL header(4) = 18 bytes minimum
        if raw.len() < 18 {
            return None;
        }

        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
        if ethertype != ETH_P_PAE {
            return None;
        }

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&raw[6..12]);

        let packet_type = raw[15];
        let body_len = u16::from_be_bytes([raw[16], raw[17]]) as usize;

        let body = if body_len > 0 && raw.len() >= 18 + body_len {
            raw[18..18 + body_len].to_vec()
        } else {
            Vec::new()
        };

        Some(EapolFrame {
            src_mac,
            packet_type,
            body,
        })
    }
}

impl EapPacket {
    /// Parse an EAP packet from the EAPOL body.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let code = data[0];
        let id = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length {
            return None;
        }

        // Request / Response carry a Type field; Success / Failure do not.
        let (eap_type, type_data) = if (code == EAP_REQUEST || code == EAP_RESPONSE) && length > 4
        {
            (Some(data[4]), data[5..length].to_vec())
        } else {
            (None, Vec::new())
        };

        Some(EapPacket {
            code,
            id,
            eap_type,
            data: type_data,
        })
    }
}
