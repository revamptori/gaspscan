//! Command-line interface: argument parsing, dispatch and the user-facing
//! legal/authorization notices.

use std::net::IpAddr;
use std::process;
use std::time::{Duration, Instant};

use crate::output::{render_report, OutputFormat, PortState};
use crate::ports::{parse_port_spec, COMMON_PORTS};
use crate::scan::{tcp_connect_scan, udp_scan, ScanOptions};
use crate::syn::{spoofed_probe, syn_scan};

pub const VERSION: &str = "0.1.0";

const LEGAL_NOTICE: &str = "gaspscan is for EDUCATIONAL use on networks you own or are authorized to test.\nScanning or spoofing traffic on other networks may be illegal. See README.md.";

pub fn usage() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "gaspscan {} — educational port scanner (TCP connect, UDP, raw SYN)\n\n",
        VERSION,
    ));
    out.push_str("USAGE:\n");
    out.push_str("    gaspscan <COMMAND> <host> [OPTIONS]\n\n");
    out.push_str("COMMANDS:\n");
    out.push_str("    scan <host>    TCP connect scan (no special privileges required)\n");
    out.push_str("    udp  <host>    best-effort UDP scan (closed vs open|filtered)\n");
    out.push_str("    syn  <host>    raw-packet SYN scan (requires root / CAP_NET_RAW)\n");
    out.push_str("    ports          list well-known ports built into the tool\n");
    out.push_str("    help           show this help\n\n");
    out.push_str("OPTIONS:\n");
    out.push_str("    --ports <spec>      e.g. \"22,80,443\", \"1-1024\", \"common\" (default), \"all\"\n");
    out.push_str("    --timeout <ms>      per-port timeout in milliseconds (default: 800)\n");
    out.push_str("    --threads <n>       concurrent probes for TCP scan (default: 100, max 512)\n");
    out.push_str("    --banner            read up to 64 bytes from open TCP services\n");
    out.push_str("    --json              emit JSON instead of a table\n");
    out.push_str("    --show-closed       include closed ports in the output\n");
    out.push_str("    --source-ip <ip>    (syn only) forge this source address on every probe;\n");
    out.push_str("                        send-only mode: replies go to the forged address, not to you\n");
    out.push_str("    --i-am-authorized   (required with --source-ip) confirm you own this network\n");
    out.push_str("                        or have written permission to test it\n\n");
    out.push_str("EXAMPLES:\n");
    out.push_str("    gaspscan scan 127.0.0.1 --ports common\n");
    out.push_str("    gaspscan scan target.example.com --ports 22,80,443 --banner\n");
    out.push_str("    sudo gaspscan syn 127.0.0.1 --ports 1-1024\n");
    out.push_str("    sudo gaspscan syn lab-vm --ports 22,80 --source-ip 198.51.100.7 --i-am-authorized\n\n");
    out.push_str(LEGAL_NOTICE);
    out.push('\n');
    out
}

struct Options {
    command: String,
    host: Option<String>,
    ports_spec: String,
    timeout_ms: u64,
    threads: usize,
    banner: bool,
    json: bool,
    show_closed: bool,
    source_ip: Option<IpAddr>,
    i_am_authorized: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        command: String::new(),
        host: None,
        ports_spec: "common".to_string(),
        timeout_ms: 800,
        threads: 100,
        banner: false,
        json: false,
        show_closed: false,
        source_ip: None,
        i_am_authorized: false,
    };

    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--ports" | "--timeout" | "--threads" | "--source-ip" => {
                i += 1;
                if i >= args.len() {
                    return Err(format!("{} requires a value", arg));
                }
                let value = args[i].as_str();
                match arg {
                    "--ports" => opts.ports_spec = value.to_string(),
                    "--timeout" => {
                        opts.timeout_ms = value.parse::<u64>().map_err(|_| {
                            format!(
                                "--timeout must be a number of milliseconds, got '{}'",
                                value,
                            )
                        })?
                    }
                    "--threads" => {
                        opts.threads = value
                            .parse::<usize>()
                            .map_err(|_| format!("--threads must be a number, got '{}'", value))?
                    }
                    "--source-ip" => {
                        opts.source_ip = Some(
                            value.parse::<IpAddr>().map_err(|_| {
                                format!("--source-ip is not a valid IP address: '{}'", value)
                            })?,
                        )
                    }
                    _ => unreachable!(),
                }
            }
            "--banner" => opts.banner = true,
            "--json" => opts.json = true,
            "--show-closed" => opts.show_closed = true,
            "--i-am-authorized" => opts.i_am_authorized = true,
            "--help" | "-h" => {
                print!("{}", usage());
                process::exit(0);
            }
            "--version" | "-V" => {
                println!("gaspscan {}", VERSION);
                process::exit(0);
            }
            _ => {
                if let Some(v) = arg.strip_prefix("--ports=") {
                    opts.ports_spec = v.to_string();
                } else if let Some(v) = arg.strip_prefix("--timeout=") {
                    opts.timeout_ms = v.parse::<u64>().map_err(|_| {
                        "--timeout must be a number of milliseconds".to_string()
                    })?;
                } else if let Some(v) = arg.strip_prefix("--threads=") {
                    opts.threads = v
                        .parse::<usize>()
                        .map_err(|_| "--threads must be a number".to_string())?;
                } else if let Some(v) = arg.strip_prefix("--source-ip=") {
                    opts.source_ip = Some(
                        v.parse::<IpAddr>()
                            .map_err(|_| "--source-ip is not a valid IP address".to_string())?,
                    );
                } else if arg.starts_with("--") {
                    return Err(format!("unknown option '{}'", arg));
                } else {
                    positional.push(arg);
                }
            }
        }
        i += 1;
    }

    if opts.threads == 0 {
        return Err("--threads must be at least 1".to_string());
    }
    if opts.threads > 512 {
        opts.threads = 512;
    }
    if opts.timeout_ms == 0 {
        return Err("--timeout must be at least 1 ms".to_string());
    }

    match positional.len() {
        0 => return Err("missing command".to_string()),
        1 => {
            opts.command = positional[0].to_string();
        }
        2 => {
            opts.command = positional[0].to_string();
            opts.host = Some(positional[1].to_string());
        }
        _ => return Err(format!("unexpected argument '{}'", positional[2])),
    }
    Ok(opts)
}

fn print_report(
    target: &str,
    scan_type: &str,
    results: &[crate::output::PortResult],
    ms: u128,
    opts: &Options,
) {
    let format = if opts.json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };
    print!(
        "{}",
        render_report(target, scan_type, results, ms, format, opts.show_closed)
    );
}

pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, usage());
            return 2;
        }
    };

    match opts.command.as_str() {
        "help" => {
            print!("{}", usage());
            0
        }
        "ports" => {
            println!("well-known ports built into gaspscan:");
            for chunk in COMMON_PORTS.chunks(4) {
                let line: Vec<String> = chunk
                    .iter()
                    .map(|&(p, name)| format!("{:>5}/tcp {:<16}", p, name))
                    .collect();
                println!("{}", line.join(" "));
            }
            0
        }
        "scan" | "udp" | "syn" => {
            let host = match &opts.host {
                Some(h) => h.clone(),
                None => {
                    eprintln!("error: '{}' requires a host\n\n{}", opts.command, usage());
                    return 2;
                }
            };
            let ports = match parse_port_spec(&opts.ports_spec) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 2;
                }
            };

            let scan_opts = ScanOptions {
                timeout: Duration::from_millis(opts.timeout_ms),
                threads: opts.threads,
                banner: opts.banner,
            };

            // Touching raw sockets requires care; fail fast before doing work.
            if opts.banner && opts.command == "syn" {
                eprintln!(
                    "note: --banner has no effect on the syn command (no connection is made)"
                );
            }

            let started = Instant::now();
            match opts.command.as_str() {
                "scan" => match tcp_connect_scan(&host, &ports, &scan_opts) {
                    Ok(results) => {
                        let ms = started.elapsed().as_millis();
                        print_report(&host, "connect", &results, ms, &opts);
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        1
                    }
                },
                "udp" => match udp_scan(&host, &ports, &scan_opts) {
                    Ok(results) => {
                        let ms = started.elapsed().as_millis();
                        print_report(&host, "udp", &results, ms, &opts);
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        1
                    }
                },
                "syn" => {
                    if let Some(source) = opts.source_ip {
                        // Forged-source mode: send-only, gated on explicit consent.
                        if !opts.i_am_authorized {
                            eprintln!(
                                "error: --source-ip FORGES the source address of every probe.\n\
                                 Every packet claims to come from {} instead of this machine.\n\
                                 This is only acceptable on networks you own or are explicitly\n\
                                 authorized (in writing) to test, e.g. a lab for studying BCP 38\n\
                                 egress filtering. Re-run with --i-am-authorized to confirm.",
                                source
                            );
                            return 2;
                        }
                        eprintln!(
                            "note: forged-source mode is SEND-ONLY. Replies (if any) will be\n\
                             delivered to {}, not to this machine. No port can be classified.",
                            source
                        );
                        match spoofed_probe(&host, source, &ports) {
                            Ok(results) => {
                                let ms = started.elapsed().as_millis();
                                print_report(&host, "syn-spoof", &results, ms, &opts);
                                let sent = results
                                    .iter()
                                    .filter(|r| r.state == PortState::Sent)
                                    .count();
                                eprintln!(
                                    "sent {} spoofed SYN probes to {}. Observe the traffic with a packet capture on the path (e.g. tcpdump) — replies, if the network allows them, go to {}.",
                                    sent, host, source
                                );
                                0
                            }
                            Err(e) => {
                                eprintln!("error: {}", e);
                                1
                            }
                        }
                    } else {
                        match syn_scan(
                            &host,
                            &ports,
                            scan_opts.timeout + Duration::from_millis(1500),
                        ) {
                            Ok(results) => {
                                let ms = started.elapsed().as_millis();
                                print_report(&host, "syn", &results, ms, &opts);
                                0
                            }
                            Err(e) => {
                                eprintln!("error: {}", e);
                                1
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        other => {
            eprintln!("error: unknown command '{}'\n\n{}", other, usage());
            2
        }
    }
}
