mod client;
mod protocol;
mod socket;

use anyhow::Result;
use clap::Parser;
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};

pub static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser)]
#[command(name = "eapmd5-client", about = "EAP-MD5 (802.1X) authentication client")]
struct Args {
    /// Network interface name
    #[arg(short, long, env = "EAP_INTERFACE")]
    interface: String,

    /// Username
    #[arg(short, long, env = "EAP_USERNAME")]
    username: String,

    /// Password
    #[arg(short, long, env = "EAP_PASSWORD")]
    password: String,
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn format_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Install signal handlers for graceful shutdown
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
    }

    info!("Opening interface {}", args.interface);
    let sock = socket::RawSocket::new(&args.interface)?;
    info!("MAC address: {}", format_mac(sock.mac()));

    let mut client = client::Client::new(sock, args.username, args.password);

    match client.run() {
        Ok(()) => {
            info!("Client stopped");
            Ok(())
        }
        Err(e) if !RUNNING.load(Ordering::Relaxed) => {
            info!("Client stopped (interrupted)");
            Err(e)
        }
        Err(e) => Err(e),
    }
}
