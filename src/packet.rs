//! Raw IPv4 + TCP packet construction for the educational SYN scanner.
//!
//! Everything in this module works on plain byte buffers so it can be unit
//! tested without any network privileges. The checksum functions follow
//! RFC 1071 (Internet checksum).
//!
//! EDUCATIONAL USE ONLY: these packets are for analysing traffic on networks
//! you own or are authorized to test (see README.md).

/// IPv4 header length in bytes (no options, IHL = 5).
pub const IPV4_HEADER_LEN: usize = 20;
/// TCP header length in bytes (no options, data offset = 5).
pub const TCP_HEADER_LEN: usize = 20;
/// Total size of an IPv4 + TCP SYN probe packet.
pub const SYN_PACKET_LEN: usize = IPV4_HEADER_LEN + TCP_HEADER_LEN;

/// IANA protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;
/// TCP flag: SYN.
pub const TCP_FLAG_SYN: u8 = 0x02;
/// TCP flag: ACK.
pub const TCP_FLAG_ACK: u8 = 0x10;
/// TCP flag: RST.
pub const TCP_FLAG_RST: u8 = 0x04;

/// RFC 1071 Internet checksum over `data`.
///
/// The caller is expected to supply an even-length slice; a trailing odd byte
/// is handled by padding a zero octet. The result is the one's-complement of
/// the one's-complement sum, in host order.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = ((chunk[0] as u32) << 8) | (chunk[1] as u32);
        sum += word;
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        sum += (rem[0] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Verify that a buffer (with an already-computed checksum field filled in)
/// sums to zero. Used by unit tests and by the receiver for sanity checks.
pub fn internet_checksum_valid(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}

/// A decoded view of the interesting fields of a received TCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTcpPacket {
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

/// Parameters used to build a TCP SYN probe.
#[derive(Debug, Clone)]
pub struct SynParams {
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ip_id: u16,
    pub ttl: u8,
    /// TCP window field; purely cosmetic for a single probe.
    pub window: u16,
}

/// Build the IPv4 pseudo-header used for the TCP checksum calculation.
fn tcp_pseudo_header(src: [u8; 4], dst: [u8; 4], tcp_len: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.push(0); // zero padding
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(&tcp_len.to_be_bytes());
    buf
}

/// Build a complete IPv4 + TCP SYN packet.
pub fn build_syn_packet(p: &SynParams) -> [u8; SYN_PACKET_LEN] {
    let mut packet = [0u8; SYN_PACKET_LEN];

    // --- IPv4 header ---
    packet[0] = 0x45; // version 4, IHL 5 (20 bytes, no options)
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(SYN_PACKET_LEN as u16).to_be_bytes()); // total length
    packet[4..6].copy_from_slice(&p.ip_id.to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: don't fragment
    packet[8] = p.ttl;
    packet[9] = IPPROTO_TCP;
    // 10..12 checksum; computed below
    packet[12..16].copy_from_slice(&p.src_addr);
    packet[16..20].copy_from_slice(&p.dst_addr);
    let ip_cksum = internet_checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // --- TCP header ---
    let tcp = &mut packet[IPV4_HEADER_LEN..];
    tcp[0..2].copy_from_slice(&p.src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&p.dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&p.seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack number
    tcp[12] = 0x50; // data offset = 5 (20 bytes), reserved = 0
    tcp[13] = TCP_FLAG_SYN;
    tcp[14..16].copy_from_slice(&p.window.to_be_bytes());
    // 16..18 checksum; computed below
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

    let mut tcp_bytes = [0u8; TCP_HEADER_LEN];
    tcp_bytes.copy_from_slice(tcp);
    let pseudo = tcp_pseudo_header(p.src_addr, p.dst_addr, TCP_HEADER_LEN as u16);
    let mut sum_input = pseudo;
    sum_input.extend_from_slice(&tcp_bytes);
    let tcp_cksum = internet_checksum(&sum_input);
    tcp[16..18].copy_from_slice(&tcp_cksum.to_be_bytes());

    packet
}

/// Parse an IPv4+TCP packet received on a raw socket.
///
/// Returns `None` for malformed packets (wrong version, truncated, fragmented,
/// or not TCP). Note the raw socket may hand us packets in either host or
/// network order for the IP header depending on platform; on Linux the IP
/// header is in network byte order and the kernel does *not* rewrite it.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<ParsedTcpPacket> {
    if packet.len() < IPV4_HEADER_LEN + TCP_HEADER_LEN {
        return None;
    }
    let version_ihl = packet[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_HEADER_LEN || packet.len() < ihl + TCP_HEADER_LEN {
        return None;
    }
    if packet[9] != IPPROTO_TCP {
        return None;
    }
    // Skip fragments: we cannot reassemble them.
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_frag & 0x2000 != 0 || flags_frag & 0x1fff != 0 {
        return None; // MF set or non-zero fragment offset
    }

    let mut src_addr = [0u8; 4];
    let mut dst_addr = [0u8; 4];
    src_addr.copy_from_slice(&packet[12..16]);
    dst_addr.copy_from_slice(&packet[16..20]);

    let tcp = &packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < TCP_HEADER_LEN {
        return None;
    }
    let flags = tcp[13];

    Some(ParsedTcpPacket {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // Worked example from RFC 1071: bytes 00 01 f2 03 f4 f5 f6 f7
        // sum = 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2ddf0 -> fold -> 0xddf2
        // one's complement = 0x220d
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_odd_length_rounds() {
        let even = internet_checksum(&[0xff, 0xff, 0xff]);
        // trailing byte 0xff becomes 0xff00
        assert_eq!(even, internet_checksum(&[0xff, 0xff, 0xff, 0x00]));
    }

    #[test]
    fn valid_checksum_detects_single_bit_flip() {
        let mut pkt = build_syn_packet(&SynParams {
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
            src_port: 40001,
            dst_port: 80,
            seq: 0xdeadbeef,
            ip_id: 0x1234,
            ttl: 64,
            window: 64240,
        });
        assert!(internet_checksum_valid(&pkt[..IPV4_HEADER_LEN]));
        pkt[19] ^= 0x01;
        assert!(!internet_checksum_valid(&pkt[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn syn_packet_round_trips_through_parser() {
        let params = SynParams {
            src_addr: [192, 0, 2, 10],
            dst_addr: [198, 51, 100, 20],
            src_port: 43210,
            dst_port: 443,
            seq: 0x01020304,
            ip_id: 0xbeef,
            ttl: 64,
            window: 64240,
        };
        let pkt = build_syn_packet(&params);
        let parsed = parse_ipv4_tcp(&pkt).expect("should parse");
        assert_eq!(parsed.src_addr, params.src_addr);
        assert_eq!(parsed.dst_addr, params.dst_addr);
        assert_eq!(parsed.src_port, params.src_port);
        assert_eq!(parsed.dst_port, params.dst_port);
        assert_eq!(parsed.seq, params.seq);
        assert_eq!(parsed.ack, 0);
        assert_eq!(parsed.flags, TCP_FLAG_SYN);
    }

    #[test]
    fn syn_packet_ip_header_is_20_bytes_and_self_consistent() {
        let pkt = build_syn_packet(&SynParams {
            src_addr: [127, 0, 0, 1],
            dst_addr: [127, 0, 0, 1],
            src_port: 1111,
            dst_port: 2222,
            seq: 1,
            ip_id: 2,
            ttl: 64,
            window: 64240,
        });
        assert_eq!(pkt[0] >> 4, 4);
        assert_eq!((pkt[0] & 0x0f) * 4, IPV4_HEADER_LEN as u8);
        assert_eq!(
            u16::from_be_bytes([pkt[2], pkt[3]]) as usize,
            SYN_PACKET_LEN
        );
        assert_eq!(pkt[9], IPPROTO_TCP);
        // IP header checksum covers itself
        assert!(internet_checksum_valid(&pkt[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn parser_rejects_garbage() {
        assert!(parse_ipv4_tcp(&[]).is_none());
        assert!(parse_ipv4_tcp(&[0u8; 19]).is_none());
        assert!(parse_ipv4_tcp(&[0u8; 40]).is_none()); // version 0
    }
}
