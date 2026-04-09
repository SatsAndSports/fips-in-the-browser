//! IPv6 helpers for browser-side FIPS traffic.
//!
//! Includes:
//! - FIPS IPv6 address derivation from NodeAddr
//! - IPv6 shim compression/decompression (same format as native FIPS)
//! - ICMPv6 Echo Request builder/parser and Echo Reply builder/parser

/// FIPS IPv6 prefix (`fd00::/8`).
pub const FIPS_ADDRESS_PREFIX: u8 = 0xfd;

/// Compressed format byte for mesh-internal IPv6 shim traffic.
pub const IPV6_SHIM_FORMAT_COMPRESSED: u8 = 0x00;

const IPV6_HEADER_SIZE: usize = 40;
const IPV6_SHIM_RESIDUAL_SIZE: usize = 6;
const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const DEFAULT_HOP_LIMIT: u8 = 64;
const DEFAULT_PING_ID: u16 = 0xF105u16;

/// Derive the FIPS IPv6 address bytes from a NodeAddr.
///
/// Native FIPS maps:
///   IPv6[0]   = 0xfd
///   IPv6[1..] = NodeAddr[0..15]
pub fn ipv6_from_node_addr(node_addr: &[u8; 16]) -> [u8; 16] {
    let mut ipv6 = [0u8; 16];
    ipv6[0] = FIPS_ADDRESS_PREFIX;
    ipv6[1..16].copy_from_slice(&node_addr[..15]);
    ipv6
}

/// Format IPv6 bytes in conventional colon-separated hex.
pub fn format_ipv6(addr: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    Ipv6Addr::from(*addr).to_string()
}

/// Compress a full IPv6 packet to the shim format.
pub fn compress_ipv6(ipv6_packet: &[u8]) -> Option<Vec<u8>> {
    if ipv6_packet.len() < IPV6_HEADER_SIZE || ipv6_packet[0] >> 4 != 6 {
        return None;
    }

    let upper_payload = &ipv6_packet[IPV6_HEADER_SIZE..];
    let mut out = Vec::with_capacity(1 + IPV6_SHIM_RESIDUAL_SIZE + upper_payload.len());
    out.push(IPV6_SHIM_FORMAT_COMPRESSED);
    out.extend_from_slice(&ipv6_packet[0..4]);
    out.push(ipv6_packet[6]);
    out.push(ipv6_packet[7]);
    out.extend_from_slice(upper_payload);
    Some(out)
}

/// Decompress a shim payload back to a full IPv6 packet.
pub fn decompress_ipv6(
    shim_payload: &[u8],
    src_ipv6: [u8; 16],
    dst_ipv6: [u8; 16],
) -> Option<Vec<u8>> {
    if shim_payload.len() < 1 + IPV6_SHIM_RESIDUAL_SIZE {
        return None;
    }
    if shim_payload[0] != IPV6_SHIM_FORMAT_COMPRESSED {
        return None;
    }

    let residual = &shim_payload[1..1 + IPV6_SHIM_RESIDUAL_SIZE];
    let upper_payload = &shim_payload[1 + IPV6_SHIM_RESIDUAL_SIZE..];
    let upper_len = upper_payload.len();

    let mut ipv6 = Vec::with_capacity(IPV6_HEADER_SIZE + upper_len);
    ipv6.push((residual[0] & 0x0F) | 0x60);
    ipv6.extend_from_slice(&residual[1..4]);
    ipv6.extend_from_slice(&(upper_len as u16).to_be_bytes());
    ipv6.push(residual[4]);
    ipv6.push(residual[5]);
    ipv6.extend_from_slice(&src_ipv6);
    ipv6.extend_from_slice(&dst_ipv6);
    ipv6.extend_from_slice(upper_payload);
    Some(ipv6)
}

/// Build a full IPv6 packet containing an ICMPv6 Echo Request.
pub fn build_icmpv6_echo_request(src_ipv6: [u8; 16], dst_ipv6: [u8; 16], seq: u16) -> Vec<u8> {
    let payload = b"fips-browser-ping";

    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(ICMPV6_ECHO_REQUEST);
    icmp.push(0); // code
    icmp.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    icmp.extend_from_slice(&DEFAULT_PING_ID.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);

    let checksum = icmpv6_checksum(src_ipv6, dst_ipv6, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut ipv6 = Vec::with_capacity(IPV6_HEADER_SIZE + icmp.len());
    ipv6.push(0x60);
    ipv6.push(0x00);
    ipv6.push(0x00);
    ipv6.push(0x00);
    ipv6.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6.push(IPV6_NEXT_HEADER_ICMPV6);
    ipv6.push(DEFAULT_HOP_LIMIT);
    ipv6.extend_from_slice(&src_ipv6);
    ipv6.extend_from_slice(&dst_ipv6);
    ipv6.extend_from_slice(&icmp);
    ipv6
}

/// Parse an IPv6 packet as an ICMPv6 Echo Request.
/// Returns (identifier, sequence) if it matches.
pub fn parse_icmpv6_echo_request(ipv6_packet: &[u8]) -> Option<(u16, u16)> {
    if ipv6_packet.len() < IPV6_HEADER_SIZE + 8 || ipv6_packet[0] >> 4 != 6 {
        return None;
    }
    if ipv6_packet[6] != IPV6_NEXT_HEADER_ICMPV6 {
        return None;
    }

    let icmp = &ipv6_packet[IPV6_HEADER_SIZE..];
    if icmp[0] != ICMPV6_ECHO_REQUEST || icmp[1] != 0 {
        return None;
    }

    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some((ident, seq))
}

/// Build an ICMPv6 Echo Reply from a valid Echo Request packet.
pub fn build_icmpv6_echo_reply(request_ipv6: &[u8]) -> Option<Vec<u8>> {
    let (ident, seq) = parse_icmpv6_echo_request(request_ipv6)?;
    if request_ipv6.len() < IPV6_HEADER_SIZE + 8 {
        return None;
    }

    let mut src_ipv6 = [0u8; 16];
    src_ipv6.copy_from_slice(&request_ipv6[24..40]);
    let mut dst_ipv6 = [0u8; 16];
    dst_ipv6.copy_from_slice(&request_ipv6[8..24]);

    let request_icmp = &request_ipv6[IPV6_HEADER_SIZE..];
    let payload = &request_icmp[8..];

    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(ICMPV6_ECHO_REPLY);
    icmp.push(0);
    icmp.extend_from_slice(&0u16.to_be_bytes());
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);

    let checksum = icmpv6_checksum(src_ipv6, dst_ipv6, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut ipv6 = Vec::with_capacity(IPV6_HEADER_SIZE + icmp.len());
    ipv6.extend_from_slice(&request_ipv6[..4]);
    ipv6[0] = (ipv6[0] & 0x0F) | 0x60;
    ipv6.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    ipv6.push(IPV6_NEXT_HEADER_ICMPV6);
    ipv6.push(request_ipv6[7]);
    ipv6.extend_from_slice(&src_ipv6);
    ipv6.extend_from_slice(&dst_ipv6);
    ipv6.extend_from_slice(&icmp);
    Some(ipv6)
}

/// Parse an IPv6 packet as an ICMPv6 Echo Reply.
/// Returns (identifier, sequence) if it matches.
pub fn parse_icmpv6_echo_reply(ipv6_packet: &[u8]) -> Option<(u16, u16)> {
    if ipv6_packet.len() < IPV6_HEADER_SIZE + 8 || ipv6_packet[0] >> 4 != 6 {
        return None;
    }
    if ipv6_packet[6] != IPV6_NEXT_HEADER_ICMPV6 {
        return None;
    }

    let icmp = &ipv6_packet[IPV6_HEADER_SIZE..];
    if icmp[0] != ICMPV6_ECHO_REPLY || icmp[1] != 0 {
        return None;
    }

    let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some((ident, seq))
}

fn icmpv6_checksum(src: [u8; 16], dst: [u8; 16], icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum = add_words(sum, &src);
    sum = add_words(sum, &dst);

    let len = (icmp.len() as u32).to_be_bytes();
    sum = add_words(sum, &len);

    let next_header = [0u8, 0u8, 0u8, IPV6_NEXT_HEADER_ICMPV6];
    sum = add_words(sum, &next_header);

    // ICMPv6 body
    sum = add_words(sum, icmp);

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        sum = sum.wrapping_add((rem[0] as u32) << 8);
    }
    sum
}
