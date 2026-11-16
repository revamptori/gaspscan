//! Raw-packet SYN probe engine (Linux only).
//!
//! Two modes:
//!
//! 1. Normal SYN scan — crafts raw IPv4+TCP SYN packets from the machine's
//!    real source address and reads SYN-ACK / RST replies (a classic
//!    "half-open" scan). Requires root (or CAP_NET_RAW).
//!
//! 2. Spoofed-source probe — the same packets are sent with a source address
//!    chosen by the user (`--source-ip`). This mode is *send-only*: any
//!    SYN-ACK is delivered to the spoofed address, not to this machine, so
//!    no per-port verdict can be produced. It exists to demonstrate, in a
//!    lab you control, what raw packet crafting looks like and why egress
//!    filtering (BCP 38) matters. Requires `--i-am-authorized` in addition
//!    to root.
//!
//! EDUCATIONAL USE ONLY — see README.md for the legal notice. Never scan or
//! spoof traffic on networks you do not own or lack written permission to
//! test.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Read;
use std::net::IpAddr;
use std::os::raw::c_int;
use std::time::{Duration, Instant};

use crate::output::{PortResult, PortState};
use crate::packet::{
    build_syn_packet, parse_ipv4_tcp, SynParams, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use crate::util::ephemeral_port;

// --- Linux socket constants (x86_64; the tool is Linux-only) ---
const AF_INET: c_int = 2;
const SOCK_RAW: c_int = 3;
const IPPROTO_TCP: c_int = 6;
const SOL_SOCKET: c_int = 1;
const SOL_IP: c_int = 0;
const IP_HDRINCL: c_int = 3;
const SO_RCVTIMEO: c_int = 20;

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: Socklen,
    ) -> c_int;
    fn sendto(
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
        dest_addr: *const c_void,
        addrlen: Socklen,
    ) -> isize;
    fn recv(fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
}

/// `socklen_t` / `c_uint` are both 32-bit on Linux x86_64; spelled out
/// to keep the FFI signatures explicit.
type Socklen = u32;

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: [u8; 2], // network byte order
    sin_addr: [u8; 4], // network byte order
    sin_zero: [u8; 8],
}

#[repr(C)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn last_error_string() -> String {
    std::io::Error::last_os_error().to_string()
}

/// RAII wrapper for a raw file descriptor.
struct RawFd(c_int);

impl Drop for RawFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                close(self.0);
            }
        }
    }
}

fn sockaddr_in_for(addr: std::net::Ipv4Addr, port: u16) -> SockaddrIn {
    SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be_bytes(),
        sin_addr: addr.octets(),
        sin_zero: [0; 8],
    }
}

fn ipv4_octets(addr: std::net::Ipv4Addr) -> [u8; 4] {
    addr.octets()
}

fn parse_ipv4(addr: IpAddr, what: &str) -> Result<std::net::Ipv4Addr, String> {
    match addr {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(format!("{} must be an IPv4 address (raw IPv4 only)", what)),
    }
}

/// Read 16 bytes of OS randomness for sequence numbers and IP ids.
fn os_random_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => bytes,
        Err(_) => {
            // Fall back to a time/pid mix if /dev/urandom is unreadable.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_nanos();
            let pid = std::process::id() as u128;
            let mixed = now ^ (pid << 64) ^ 0x9e3779b97f4a7c15;
            bytes.copy_from_slice(&mixed.to_le_bytes()[..16]);
            bytes
        }
    }
}

fn open_raw_sender() -> Result<RawFd, String> {
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
    if fd < 0 {
        let e = errno();
        return Err(if e == 1 || e == 13 {
            "raw sockets require root or CAP_NET_RAW (try: sudo gaspscan syn ...)".to_string()
        } else {
            format!("could not open raw socket: {}", last_error_string())
        });
    }
    let one: c_int = 1;
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_IP,
            IP_HDRINCL,
            &one as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as Socklen,
        )
    };
    if rc != 0 {
        let msg = last_error_string();
        unsafe {
            close(fd);
        }
        return Err(format!("could not enable IP_HDRINCL: {}", msg));
    }
    Ok(RawFd(fd))
}

fn open_raw_receiver(timeout: Duration) -> Result<RawFd, String> {
    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
    if fd < 0 {
        return Err(format!(
            "could not open raw receive socket: {}",
            last_error_string()
        ));
    }
    let tv = TimeVal {
        tv_sec: timeout.as_secs() as i64,
        tv_usec: timeout.subsec_micros() as i64,
    };
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv as *const TimeVal as *const c_void,
            std::mem::size_of::<TimeVal>() as Socklen,
        )
    };
    if rc != 0 {
        let msg = last_error_string();
        unsafe {
            close(fd);
        }
        return Err(format!("could not set receive timeout: {}", msg));
    }
    Ok(RawFd(fd))
}

fn local_source_addr(target: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
    // Ask the kernel which local address it would use to reach the target.
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            if sock.connect((target, 9)).is_err() {
                return std::net::Ipv4Addr::UNSPECIFIED;
            }
            match sock.local_addr() {
                Ok(a) => match a.ip() {
                    IpAddr::V4(v4) => v4,
                    _ => std::net::Ipv4Addr::UNSPECIFIED,
                },
                Err(_) => std::net::Ipv4Addr::UNSPECIFIED,
            }
        }
        Err(_) => std::net::Ipv4Addr::UNSPECIFIED,
    }
}

struct SentProbe {
    port: u16,
    src_port: u16,
    seq: u32,
}

fn send_probes(
    sender: &RawFd,
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    ports: &[u16],
) -> (Vec<SentProbe>, Vec<(u16, String)>) {
    let rand = os_random_bytes();
    let mut sent = Vec::with_capacity(ports.len());
    let mut failed = Vec::new();
    for (i, &port) in ports.iter().enumerate() {
        let src_port = ephemeral_port(i as u32);
        let seq = u32::from_be_bytes([
            rand[i % 12],
            rand[(i + 3) % 12 + 1],
            rand[(i + 5) % 16],
            rand[(i + 7) % 16],
        ]);
        let ip_id = u16::from_be_bytes([rand[(i * 2 + 1) % 16], rand[(i * 2 + 7) % 16]]);
        let params = SynParams {
            src_addr: ipv4_octets(src_ip),
            dst_addr: ipv4_octets(dst_ip),
            src_port,
            dst_port: port,
            seq,
            ip_id,
            ttl: 64,
            window: 64240,
        };
        let packet = build_syn_packet(&params);
        let dest = sockaddr_in_for(dst_ip, 0);
        let rc = unsafe {
            sendto(
                sender.0,
                packet.as_ptr(),
                packet.len(),
                0,
                &dest as *const SockaddrIn as *const c_void,
                std::mem::size_of::<SockaddrIn>() as Socklen,
            )
        };
        if rc < 0 {
            failed.push((port, last_error_string()));
        } else {
            sent.push(SentProbe {
                port,
                src_port,
                seq,
            });
        }
    }
    (sent, failed)
}

/// Run a send-only spoofed-source probe. Returns one `PortResult` with state
/// `Sent` per port, or `Error` per port that failed to send.
pub fn spoofed_probe(
    target: &str,
    source: IpAddr,
    ports: &[u16],
) -> Result<Vec<PortResult>, String> {
    let dst_ip = parse_ipv4(crate::scan::resolve_target(target)?, "target")?;
    let src_ip = parse_ipv4(source, "source address")?;
    let sender = open_raw_sender()?;
    let (sent, failed) = send_probes(&sender, src_ip, dst_ip, ports);

    let mut results: Vec<PortResult> = Vec::with_capacity(ports.len());
    for probe in &sent {
        results.push(PortResult {
            port: probe.port,
            state: PortState::Sent,
            banner: None,
        });
    }
    for (port, err) in failed {
        results.push(PortResult {
            port,
            state: PortState::Error(err),
            banner: None,
        });
    }
    results.sort_by_key(|r| r.port);
    Ok(results)
}

/// Run a full half-open SYN scan (raw packets, real source address).
pub fn syn_scan(target: &str, ports: &[u16], timeout: Duration) -> Result<Vec<PortResult>, String> {
    let dst_ip = parse_ipv4(crate::scan::resolve_target(target)?, "target")?;
    let src_ip = local_source_addr(dst_ip);
    if src_ip == std::net::Ipv4Addr::UNSPECIFIED {
        return Err("could not determine local source address for target".to_string());
    }

    let sender = open_raw_sender()?;
    // Open the receive path *before* sending so replies cannot race us.
    let receiver = open_raw_receiver(Duration::from_millis(200))?;
    let (sent, failed) = send_probes(&sender, src_ip, dst_ip, ports);

    // Map our ephemeral source port -> (probed port, seq) for matching replies.
    let mut by_src_port: HashMap<u16, (u16, u32)> = HashMap::with_capacity(sent.len());
    for probe in &sent {
        by_src_port.insert(probe.src_port, (probe.port, probe.seq));
    }

    let mut states: HashMap<u16, PortState> = HashMap::with_capacity(sent.len());

    let deadline = Instant::now() + timeout + Duration::from_millis(500);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && states.len() < sent.len() {
        let n = unsafe { recv(receiver.0, buf.as_mut_ptr(), buf.len(), 0) };
        if n <= 0 {
            // Timeout tick (EAGAIN/EWOULDBLOCK); loop around until deadline.
            continue;
        }
        let packet = &buf[..n as usize];
        if let Some(parsed) = parse_ipv4_tcp(packet) {
            if parsed.src_addr != ipv4_octets(dst_ip) {
                continue; // not from our target
            }
            let lookup = by_src_port.get(&parsed.dst_port).copied();
            let (port, our_seq) = match lookup {
                Some(v) => v,
                None => continue, // not a reply to our probe
            };
            if parsed.src_port != port {
                continue;
            }
            let expects_ack = parsed.ack == our_seq.wrapping_add(1);
            let syn_ack =
                parsed.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == (TCP_FLAG_SYN | TCP_FLAG_ACK);
            if syn_ack && expects_ack && !states.contains_key(&port) {
                states.insert(port, PortState::Open);
            } else if parsed.flags & TCP_FLAG_RST != 0 && !states.contains_key(&port) {
                // RST answering our SYN (ack check relaxed: some stacks send
                // RST without a valid ACK for our unsolicited SYN).
                states.insert(port, PortState::Closed);
            }
        }
    }

    let mut results: Vec<PortResult> = Vec::with_capacity(ports.len());
    for probe in &sent {
        let state = states
            .get(&probe.port)
            .cloned()
            .unwrap_or(PortState::OpenFiltered);
        results.push(PortResult {
            port: probe.port,
            state,
            banner: None,
        });
    }
    for (port, err) in failed {
        results.push(PortResult {
            port,
            state: PortState::Error(err),
            banner: None,
        });
    }
    results.sort_by_key(|r| r.port);
    Ok(results)
}
