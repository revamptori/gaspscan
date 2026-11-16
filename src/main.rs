//! gaspscan — an educational port scanner.
//!
//! Features: TCP connect scan, best-effort UDP scan, raw-packet SYN scan
//! (half-open) and a send-only forged-source SYN probe for lab use.
//!
//! **Educational use only.** Only scan or spoof traffic on networks you own
//! or are explicitly authorized to test. See README.md for the full notice.

mod cli;
mod output;
mod packet;
mod ports;
mod scan;
mod syn;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = cli::run(&args);
    std::process::exit(code);
}
