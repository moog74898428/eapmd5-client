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

        // Validate body_len against actual frame length
        if raw.len() < 18 + body_len {
            return None;
        }
        let body = raw[18..18 + body_len].to_vec();

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eapol_frame(src_mac: &[u8; 6], packet_type: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 60];
        // dst mac (PAE group)
        frame[0..6].copy_from_slice(&PAE_GROUP_ADDR);
        // src mac
        frame[6..12].copy_from_slice(src_mac);
        // ethertype
        frame[12..14].copy_from_slice(&ETH_P_PAE.to_be_bytes());
        // EAPOL version
        frame[14] = EAPOL_VERSION;
        // EAPOL packet type
        frame[15] = packet_type;
        // EAPOL body length
        frame[16..18].copy_from_slice(&(body.len() as u16).to_be_bytes());
        // body
        frame[18..18 + body.len()].copy_from_slice(body);
        frame
    }

    fn make_eap_packet(code: u8, id: u8, eap_type: Option<u8>, data: &[u8]) -> Vec<u8> {
        let has_type = eap_type.is_some();
        let length = 4 + if has_type { 1 + data.len() } else { 0 };
        let mut pkt = Vec::with_capacity(length);
        pkt.push(code);
        pkt.push(id);
        pkt.extend_from_slice(&(length as u16).to_be_bytes());
        if let Some(t) = eap_type {
            pkt.push(t);
            pkt.extend_from_slice(data);
        }
        pkt
    }

    #[test]
    fn test_eapol_frame_parse_valid() {
        let src = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let body = [1, 2, 3, 4];
        let frame = make_eapol_frame(&src, EAPOL_EAP_PACKET, &body);

        let parsed = EapolFrame::parse(&frame).unwrap();
        assert_eq!(parsed.src_mac, src);
        assert_eq!(parsed.packet_type, EAPOL_EAP_PACKET);
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn test_eapol_frame_parse_too_short() {
        let frame = vec![0u8; 17]; // need at least 18
        assert!(EapolFrame::parse(&frame).is_none());
    }

    #[test]
    fn test_eapol_frame_parse_wrong_ethertype() {
        let mut frame = make_eapol_frame(&[0; 6], EAPOL_EAP_PACKET, &[]);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        assert!(EapolFrame::parse(&frame).is_none());
    }

    #[test]
    fn test_eapol_frame_parse_body_len_mismatch() {
        let src = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut frame = make_eapol_frame(&src, EAPOL_EAP_PACKET, &[1, 2]);
        // Claim body is 50 bytes but frame is only 60 total (18 header + 42 max body)
        frame[16] = 0;
        frame[17] = 50;
        // Should fail because 18 + 50 > 60
        assert!(EapolFrame::parse(&frame).is_none());
    }

    #[test]
    fn test_eap_packet_parse_request_identity() {
        let pkt = make_eap_packet(EAP_REQUEST, 42, Some(EAP_TYPE_IDENTITY), &[]);
        let parsed = EapPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.code, EAP_REQUEST);
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.eap_type, Some(EAP_TYPE_IDENTITY));
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_eap_packet_parse_md5_challenge() {
        let challenge = [0x11u8; 16];
        let mut data = vec![16u8]; // value size
        data.extend_from_slice(&challenge);
        let pkt = make_eap_packet(EAP_REQUEST, 5, Some(EAP_TYPE_MD5), &data);
        let parsed = EapPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.code, EAP_REQUEST);
        assert_eq!(parsed.id, 5);
        assert_eq!(parsed.eap_type, Some(EAP_TYPE_MD5));
        assert_eq!(parsed.data.len(), 17); // value_size + challenge
    }

    #[test]
    fn test_eap_packet_parse_success() {
        let pkt = make_eap_packet(EAP_SUCCESS, 10, None, &[]);
        let parsed = EapPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.code, EAP_SUCCESS);
        assert_eq!(parsed.id, 10);
        assert_eq!(parsed.eap_type, None);
    }

    #[test]
    fn test_eap_packet_parse_failure() {
        let pkt = make_eap_packet(EAP_FAILURE, 10, None, &[]);
        let parsed = EapPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.code, EAP_FAILURE);
        assert_eq!(parsed.id, 10);
        assert_eq!(parsed.eap_type, None);
    }

    #[test]
    fn test_eap_packet_parse_too_short() {
        let pkt = vec![1, 2, 3]; // need at least 4
        assert!(EapPacket::parse(&pkt).is_none());
    }

    #[test]
    fn test_eap_packet_parse_length_mismatch() {
        let mut pkt = make_eap_packet(EAP_REQUEST, 1, Some(EAP_TYPE_IDENTITY), &[]);
        // Claim length is 100 but actual data is shorter
        pkt[2] = 0;
        pkt[3] = 100;
        assert!(EapPacket::parse(&pkt).is_none());
    }

    #[test]
    fn test_build_eapol_start() {
        let src = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let frame = build_eapol_start(&src);
        assert_eq!(frame.len(), 60); // minimum ethernet frame
        let parsed = EapolFrame::parse(&frame).unwrap();
        assert_eq!(parsed.src_mac, src);
        assert_eq!(parsed.packet_type, EAPOL_START);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn test_build_eapol_logoff() {
        let src = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let frame = build_eapol_logoff(&src);
        let parsed = EapolFrame::parse(&frame).unwrap();
        assert_eq!(parsed.packet_type, EAPOL_LOGOFF);
    }

    #[test]
    fn test_build_eap_response_identity() {
        let src = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dst = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = build_eap_response_identity(&src, &dst, 42, b"testuser");
        let eapol = EapolFrame::parse(&frame).unwrap();
        assert_eq!(eapol.packet_type, EAPOL_EAP_PACKET);
        let eap = EapPacket::parse(&eapol.body).unwrap();
        assert_eq!(eap.code, EAP_RESPONSE);
        assert_eq!(eap.id, 42);
        assert_eq!(eap.eap_type, Some(EAP_TYPE_IDENTITY));
        assert_eq!(&eap.data, b"testuser");
    }

    #[test]
    fn test_build_eap_response_md5() {
        let src = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dst = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let hash = [0xab; 16];
        let frame = build_eap_response_md5(&src, &dst, 5, &hash, b"user");
        let eapol = EapolFrame::parse(&frame).unwrap();
        let eap = EapPacket::parse(&eapol.body).unwrap();
        assert_eq!(eap.code, EAP_RESPONSE);
        assert_eq!(eap.id, 5);
        assert_eq!(eap.eap_type, Some(EAP_TYPE_MD5));
        // data = value_size(1) + hash(16) + username(4)
        assert_eq!(eap.data.len(), 1 + 16 + 4);
        assert_eq!(eap.data[0], 16); // value size
        assert_eq!(&eap.data[1..17], &hash);
        assert_eq!(&eap.data[17..], b"user");
    }
}
