use anyhow::{bail, Result};
use log::{debug, error, info, warn};
use md5::{Digest, Md5};
use std::sync::atomic::Ordering;

use crate::protocol::*;
use crate::socket::RawSocket;
use crate::RUNNING;

const MAX_START_RETRIES: u32 = 10;
const MAX_FRAME_SIZE: usize = 1514;

#[derive(Debug, PartialEq)]
enum State {
    Idle,
    Starting,
    Identity,
    Challenging,
    Authenticated,
}

pub struct Client {
    socket: RawSocket,
    username: String,
    password: String,
    state: State,
    authenticator_mac: [u8; 6],
    no_logoff: bool,
}

impl Client {
    pub fn new(socket: RawSocket, username: String, password: String, no_logoff: bool) -> Self {
        Self {
            socket,
            username,
            password,
            state: State::Idle,
            authenticator_mac: PAE_GROUP_ADDR,
            no_logoff,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        loop {
            if !RUNNING.load(Ordering::Relaxed) {
                self.send_logoff();
                return Ok(());
            }

            match self.state {
                State::Idle => self.start_auth()?,
                State::Authenticated => self.wait_for_reauth()?,
                _ => self.wait_for_response()?,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Authentication phases
    // -----------------------------------------------------------------------

    fn start_auth(&mut self) -> Result<()> {
        for attempt in 1..=MAX_START_RETRIES {
            if !RUNNING.load(Ordering::Relaxed) {
                return Ok(());
            }

            info!("Sending EAPOL-Start (attempt {}/{})", attempt, MAX_START_RETRIES);
            self.socket.send(&build_eapol_start(self.socket.mac()))?;
            self.state = State::Starting;

            let mut buf = [0u8; MAX_FRAME_SIZE];
            match self.socket.recv(&mut buf)? {
                Some(n) => {
                    if self.handle_frame(&buf[..n])? {
                        return Ok(());
                    }
                }
                None => {
                    warn!("Timeout waiting for response");
                }
            }
        }
        bail!(
            "No response from authenticator after {} attempts",
            MAX_START_RETRIES
        );
    }

    fn wait_for_response(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        match self.socket.recv(&mut buf)? {
            Some(n) => {
                self.handle_frame(&buf[..n])?;
            }
            None => {
                warn!("Timeout in state {:?}, resetting", self.state);
                self.state = State::Idle;
            }
        }
        Ok(())
    }

    fn wait_for_reauth(&mut self) -> Result<()> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        if let Some(n) = self.socket.recv(&mut buf)? {
            self.handle_frame(&buf[..n])?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Frame handling
    // -----------------------------------------------------------------------

    fn handle_frame(&mut self, raw: &[u8]) -> Result<bool> {
        let eapol = match EapolFrame::parse(raw) {
            Some(f) => f,
            None => return Ok(false),
        };

        // Ignore our own frames (AF_PACKET may echo them back)
        if eapol.src_mac == *self.socket.mac() {
            return Ok(false);
        }

        if eapol.packet_type != EAPOL_EAP_PACKET {
            return Ok(false);
        }

        // Remember the authenticator's MAC for subsequent responses
        self.authenticator_mac = eapol.src_mac;

        let eap = match EapPacket::parse(&eapol.body) {
            Some(p) => p,
            None => return Ok(false),
        };

        match eap.code {
            EAP_REQUEST => self.handle_request(&eap),
            EAP_SUCCESS => {
                info!("EAP-Success (id={})", eap.id);
                self.state = State::Authenticated;
                Ok(true)
            }
            EAP_FAILURE => {
                error!("EAP-Failure (id={})", eap.id);
                bail!("Authentication rejected by authenticator");
            }
            code => {
                debug!("Ignoring EAP code {}", code);
                Ok(false)
            }
        }
    }

    fn handle_request(&mut self, eap: &EapPacket) -> Result<bool> {
        match eap.eap_type {
            Some(EAP_TYPE_IDENTITY) => {
                info!("EAP-Request/Identity (id={})", eap.id);
                let frame = build_eap_response_identity(
                    self.socket.mac(),
                    &self.authenticator_mac,
                    eap.id,
                    self.username.as_bytes(),
                );
                self.socket.send(&frame)?;
                info!("Sent EAP-Response/Identity (user={})", self.username);
                self.state = State::Identity;
                Ok(true)
            }

            Some(EAP_TYPE_MD5) => {
                info!("EAP-Request/MD5-Challenge (id={})", eap.id);

                if eap.data.is_empty() {
                    bail!("Empty MD5-Challenge data");
                }
                let value_size = eap.data[0] as usize;
                if eap.data.len() < 1 + value_size {
                    bail!(
                        "Truncated MD5-Challenge: value_size={} data_len={}",
                        value_size,
                        eap.data.len()
                    );
                }
                let challenge = &eap.data[1..1 + value_size];

                // RFC 3748 §5.4: Response Value = MD5(ID || secret || challenge)
                let mut hasher = Md5::new();
                hasher.update([eap.id]);
                hasher.update(self.password.as_bytes());
                hasher.update(challenge);
                let hash: [u8; 16] = hasher.finalize().into();

                let frame = build_eap_response_md5(
                    self.socket.mac(),
                    &self.authenticator_mac,
                    eap.id,
                    &hash,
                    self.username.as_bytes(),
                );
                self.socket.send(&frame)?;
                info!("Sent EAP-Response/MD5-Challenge");
                self.state = State::Challenging;
                Ok(true)
            }

            Some(EAP_TYPE_NOTIFICATION) => {
                let msg = String::from_utf8_lossy(&eap.data);
                info!("EAP-Notification: {}", msg);
                Ok(false)
            }

            Some(unsupported) => {
                warn!(
                    "Unsupported EAP type {}, sending NAK (desired=MD5)",
                    unsupported
                );
                let frame = build_eap_response_nak(
                    self.socket.mac(),
                    &self.authenticator_mac,
                    eap.id,
                    EAP_TYPE_MD5,
                );
                self.socket.send(&frame)?;
                Ok(true)
            }

            None => Ok(false),
        }
    }

    fn send_logoff(&self) {
        if self.no_logoff {
            return;
        }
        if self.state == State::Authenticated {
            info!("Sending EAPOL-Logoff");
            let _ = self.socket.send(&build_eapol_logoff(self.socket.mac()));
        }
    }
}
