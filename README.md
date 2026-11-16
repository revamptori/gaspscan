# gaspscan

An **educational** port scanner written in Rust: TCP connect scan, a
best-effort UDP scan, a raw-packet SYN ("half-open") scan, and a send-only
forged-source SYN probe for demonstrating IP spoofing in a lab.

> [!WARNING]
> **Educational use only.** Port scanning networks you do not own or are not
> authorized to test is illegal in many jurisdictions (e.g. unauthorized
> access under the US Computer Fraud and Abuse Act, the UK Computer Misuse
> Act, and similar laws elsewhere). Forging source addresses is even more
> sensitive: an IP packet that claims to come from someone else can disrupt
> networks and is treated as an attack by essentially every provider. Use
> this tool **only** on networks you own or have *explicit written
> permission* to test — e.g. a home lab, a VM, or a sanctioned class/CTF.
> The authors take no responsibility for misuse.

---

## Why this exists

gaspscan is a learning project for understanding:

- how a connect() scan differs from a raw SYN scan at the wire level,
- how IPv4 + TCP packets are laid out (headers, checksums, sequence numbers),
- how a source address is just a field in the IPv4 header — and what that
  means (spoiler: anyone who can inject packets can *claim* to be anyone,
  which is why **BCP 38** requires networks to drop packets with forged
  source addresses),
- and why "the response went somewhere else" is the whole reason spoofing is
  limited to one-way probes.

It is deliberately small (~1,700 lines including tests, no dependencies) and heavily commented
so it can be read end-to-end.

## Features

| Command | Privileges | What it does |
| ------- | ---------- | ------------ |
| `scan`  | none | TCP connect() scan of a port spec, with concurrency, optional banner grab |
| `udp`   | none | Best-effort UDP scan: distinguishes `closed` (ICMP port-unreachable) from `open\|filtered` |
| `syn`   | root | Raw IPv4+TCP SYN probes; classifies ports as `open` (SYN-ACK), `closed` (RST) or `filtered\|open` (silence) |
| `syn --source-ip <ip>` | root + `--i-am-authorized` | Same probes with a **forged source address**. Send-only — no verdicts can be produced because replies go to the forged address |
| `ports` | none | Lists the built-in well-known-port table |

All modes support `--json` for machine-readable output, `--timeout`,
`--threads`, `--show-closed` and port specs like `22,80,1000-1010`, `common`
or `all`.

## Build

Requires a stable Rust toolchain (edition 2018):

```console
$ cargo build --release
$ ./target/release/gaspscan --help
```

Run the test suite:

```console
$ cargo test
```

> Raw-socket modes are Linux-only and need root (or `CAP_NET_RAW`):
>
> ```console
> $ sudo ./target/release/gaspscan syn 127.0.0.1 --ports 1-1024
> ```

## Usage

### TCP connect scan (no privileges)

```console
$ gaspscan scan 127.0.0.1 --ports 22,80,443
gaspscan connect scan of 127.0.0.1 (3 ports probed in 1 ms)
PORT    STATE       SERVICE         BANNER
22      open        ssh             SSH-2.0-OpenSSH_9.2
80      closed      http            -
443     closed      https           -
summary: 1 open, 2 closed/filtered of 3 probed
```

### UDP scan (best-effort)

```console
$ gaspscan udp 127.0.0.1 --ports 53,123,161
```

UDP gives no guarantees: silence means *open|filtered*, an ICMP port
unreachable (surfaced by the kernel as `ECONNREFUSED`) means *closed*.

### SYN scan (half-open, root required)

```console
$ sudo gaspscan syn 127.0.0.1 --ports 1-1024
```

Sends a SYN and looks at the reply:

- `SYN+ACK` (with the correct ack of our sequence number) → `open`
- `RST` → `closed`
- silence → `filtered|open`

The kernel will still complete its own TCP handshake machinery (and will
usually RST after the SYN-ACK since no socket is bound); the raw socket sees
the SYN-ACK regardless, which is the point of a half-open scan.

### Forged-source probe (send-only, gated)

```console
$ sudo gaspscan syn 192.0.2.10 --ports 22,80 \
      --source-ip 198.51.100.7 --i-am-authorized
```

This crafts IPv4+TCP SYN packets whose **source address field is
`198.51.100.7`** instead of this machine's address. gaspscan will:

- refuse to run without root,
- refuse to run without `--i-am-authorized`,
- never print per-port verdicts in this mode (replies, if the network does
  not drop the spoofed packets, are delivered to `198.51.100.7`),
- remind you to observe the traffic with a packet capture (`tcpdump`,
  Wireshark) inside the lab.

This is useful for *teaching*: it shows that a source address is just four
bytes you write into the header, and why networks must drop packets whose
source doesn't match the ingress interface (BCP 38). It is not a tool for
attacking anything, and it cannot be used to "get at" a host — it sends
exactly one SYN per port and reads nothing back.

## How the packets are built

`src/packet.rs` builds the 20-byte IPv4 header (version/IHL `0x45`, total
length, identification, don't-fragment flag, TTL 64, protocol TCP) and the
20-byte TCP header (source/destination port, sequence number, SYN flag,
window) from scratch, then computes:

- the IPv4 header checksum (RFC 1071, ones'-complement of the ones'-complement
  sum),
- the TCP checksum over the pseudo-header + TCP header.

`parse_ipv4_tcp` decodes replies for the receive path, and unit tests
round-trip the constructed packets and verify checksums — including an RFC
1071 worked-example test vector.

The raw sockets are opened as `SOCK_RAW` + `IPPROTO_TCP`; sending uses
`IP_HDRINCL` so the kernel transmits the packet we built (with our chosen
source address) instead of adding its own.

## Limitations (honest ones)

- **Spoofed packets almost never traverse real networks.** Modern egress
  filtering (BCP 38 / SAVI) drops them at the first hop. This is the entire
  reason spoofing only works inside deliberately-misconfigured or
  single-controlled labs.
- Forged-source mode is **send-only** by physics, not by policy: TCP is a
  bidirectional protocol, and the reply is routed to the forged address.
- SYN scan replies can race the kernel's own TCP stack; on loopback this is
  fine, and against remote hosts the SYN-ACK is observable on the raw socket
  before cleanup.
- IPv4 only. No IPv6 raw mode, no TCP options in probes, no fragmentation,
  no decoys, no evasion features — intentionally.
- UDP "scan" cannot reliably distinguish open from filtered, like every UDP
  scanner including nmap's.
- The ephemeral source port selection is simple (pid/counter mixing), not
  cryptographically random.

## What this tool deliberately does NOT do

No exploitation, no payloads, no vulnerability detection, no decoy fleets, no
IDS-signature evasion, no scan scheduling/botnet orchestration, no credential
attacks. If you want those, study how they work in a lab with established
tools like nmap; this project is about the packet mechanics.

## Project layout

```
src/
  main.rs     entry point
  cli.rs      argument parsing, dispatch, authorization gates
  scan.rs     TCP connect + UDP scanning (threads)
  syn.rs      raw SYN scan and forged-source probe (Linux raw sockets)
  packet.rs   IPv4/TCP header construction, RFC 1071 checksums
  ports.rs    port-spec parser + well-known port table
  output.rs   human/JSON reporting
  util.rs     helpers (JSON escaping, deadlines, ephemeral ports)
```

## Legal & ethical notice

Only use gaspscan on systems you own or are explicitly authorized to test.
Authorization means a signed scope document, a lab you control, or the
written consent of the system owner. "It's reachable from the internet" is
not authorization. Unauthorized scanning wastes resources, can trigger
security systems, and in many places is a criminal offense. The forged-source
mode is for controlled experiments (e.g. validating your own egress
filtering) only.

This software is provided "as is", without warranty of any kind. See
`LICENSE`.
