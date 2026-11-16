//! TCP connect scan and best-effort UDP scan.
//!
//! These modes use ordinary sockets and require no special privileges.

use std::io::Read;
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::output::{PortResult, PortState};

/// Options shared by the scanning modes.
#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub threads: usize,
    pub banner: bool,
}

/// Resolve `target` (IP literal or DNS name) once. Returns the first usable
/// IP address.
pub fn resolve_target(target: &str) -> Result<std::net::IpAddr, String> {
    // Port 0 is only used to trigger resolution; we override the port later.
    let trimmed = target.trim();
    let addr_str = if trimmed.contains(':') && !trimmed.starts_with('[') {
        format!("[{}]:0", trimmed) // IPv6 literal needs brackets
    } else {
        format!("{}:0", trimmed)
    };
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => Ok(addr.ip()),
            None => Err(format!("could not resolve '{}'", target)),
        },
        Err(e) => Err(format!("could not resolve '{}': {}", target, e)),
    }
}

fn probe_tcp_port(ip: std::net::IpAddr, port: u16, opts: &ScanOptions) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, opts.timeout) {
        Ok(stream) => {
            let mut banner = None;
            if opts.banner {
                banner = read_banner(&stream, Duration::from_millis(800));
            }
            let _ = stream.shutdown(Shutdown::Both);
            PortResult {
                port,
                state: PortState::Open,
                banner,
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortResult {
            port,
            state: PortState::Closed,
            banner: None,
        },
        Err(ref e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            PortResult {
                port,
                state: PortState::OpenFiltered,
                banner: None,
            }
        }
        Err(e) => PortResult {
            port,
            state: PortState::Error(e.to_string()),
            banner: None,
        },
    }
}

fn probe_udp_port(ip: std::net::IpAddr, port: u16, opts: &ScanOptions) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let bind_addr: SocketAddr = match ip {
        std::net::IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        std::net::IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            return PortResult {
                port,
                state: PortState::Error(e.to_string()),
                banner: None,
            }
        }
    };
    if let Err(e) = socket.connect(addr) {
        return PortResult {
            port,
            state: PortState::Error(e.to_string()),
            banner: None,
        };
    }
    let _ = socket.set_read_timeout(Some(opts.timeout));
    let _ = socket.set_write_timeout(Some(opts.timeout));
    // A single zero byte: enough to trigger an ICMP port-unreachable from a
    // closed UDP port on most systems, and harmless to open ones.
    if let Err(e) = socket.send(&[0u8]) {
        return PortResult {
            port,
            state: PortState::Error(e.to_string()),
            banner: None,
        };
    }
    let mut buf = [0u8; 512];
    match socket.recv(&mut buf) {
        Ok(_) => PortResult {
            port,
            state: PortState::Open,
            banner: None,
        },
        Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortResult {
            port,
            state: PortState::Closed,
            banner: None,
        },
        Err(ref e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            PortResult {
                port,
                state: PortState::OpenOrFiltered,
                banner: None,
            }
        }
        Err(e) => PortResult {
            port,
            state: PortState::Error(e.to_string()),
            banner: None,
        },
    }
}

/// Read up to 64 bytes from a freshly-opened TCP stream without blocking
/// forever. Returns `None` when nothing arrives.
fn read_banner(stream: &TcpStream, timeout: Duration) -> Option<String> {
    let _ = stream.set_read_timeout(Some(timeout));
    let mut buf = [0u8; 64];
    let mut read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return None,
    };
    match read_stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
        Err(_) => None,
    }
}

fn run_work_queue<F>(ports: &[u16], threads: usize, worker: F) -> Vec<PortResult>
where
    F: Fn(u16) -> PortResult + Send + Sync + 'static,
{
    let ports = Arc::new(ports.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::with_capacity(ports.len())));
    let worker = Arc::new(worker);
    let thread_count = threads.max(1).min(ports.len().max(1));

    let mut handles = Vec::with_capacity(thread_count);
    for _ in 0..thread_count {
        let next = Arc::clone(&next);
        let results = Arc::clone(&results);
        let worker = Arc::clone(&worker);
        let ports = Arc::clone(&ports);
        handles.push(std::thread::spawn(move || loop {
            let idx = next.fetch_add(1, Ordering::Relaxed);
            if idx >= ports.len() {
                break;
            }
            let result = worker(ports[idx]);
            let mut guard = results.lock().unwrap();
            guard.push(result);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut out = std::mem::take(&mut *results.lock().unwrap());
    out.sort_by_key(|r| r.port);
    out
}

/// Scan `ports` on `target` using TCP connect(). `banner` enables a short
/// read on open ports.
pub fn tcp_connect_scan(
    target: &str,
    ports: &[u16],
    opts: &ScanOptions,
) -> Result<Vec<PortResult>, String> {
    let ip = resolve_target(target)?;
    let results = run_work_queue(ports, opts.threads, |port| probe_tcp_port(ip, port, opts));
    Ok(results)
}

/// Best-effort UDP scan. Closed ports usually answer with ICMP
/// port-unreachable (reported as `closed`); silence is reported as
/// `open|filtered` because UDP gives us no way to tell the two apart.
pub fn udp_scan(
    target: &str,
    ports: &[u16],
    opts: &ScanOptions,
) -> Result<Vec<PortResult>, String> {
    let ip = resolve_target(target)?;
    let opts = *opts;
    // UDP replies (and ICMP errors) are per-socket; keep it serial to avoid
    // flooding and to keep the semantics predictable on noisy networks.
    let results = run_work_queue(ports, 1, move |port| probe_udp_port(ip, port, &opts));
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_localhost() {
        let ip = resolve_target("127.0.0.1").unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn rejects_unresolvable() {
        // .invalid is reserved by RFC 2606 and must not resolve.
        assert!(resolve_target("definitely-not-a-real-host.invalid").is_err());
    }
}
