//! Bounded classic-PCAP reader and conservative IP transport parser.
//!
//! This is an observer, not an IP stack: no fragment reassembly, jumbo IPv6,
//! checksum verification, or encrypted/tunnel transport decoding is attempted.
//! Checksums are deliberately not checked because local captures can precede
//! NIC checksum offload. Packet/header lengths are always checked first.
//! Layout references: the-tcpdump-group/libpcap `sf-pcap.c`, `pcap/sll.h`,
//! RFC 791, RFC 8200, RFC 4302, RFC 9293, and RFC 768.

use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_FRAME_LEN: usize = 262_144;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;
const MAX_IPV6_EXTENSIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_seq: Option<u32>,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Self::Little => u16::from_le_bytes(a),
            Self::Big => u16::from_be_bytes(a),
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }
}

fn supported(linktype: u32) -> bool {
    matches!(linktype, LINKTYPE_ETHERNET | LINKTYPE_RAW | LINKTYPE_LINUX_SLL | LINKTYPE_LINUX_SLL2)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Parse one complete captured frame. Unsupported link types are configuration
/// errors. Malformed/truncated/fragmented frames and unsupported protocols are
/// `Ok(None)`, so callers cannot accidentally classify a partial payload.
pub fn parse_packet(linktype: u32, bytes: &[u8]) -> Result<Option<Packet>, String> {
    if !supported(linktype) {
        return Err(format!("unsupported PCAP linktype {linktype}"));
    }
    Ok(parse_frame(linktype, bytes).unwrap_or(None))
}

fn parse_frame(linktype: u32, bytes: &[u8]) -> Result<Option<Packet>, String> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err("frame exceeds configured maximum".into());
    }
    let (mut ether_type, mut offset) = match linktype {
        LINKTYPE_ETHERNET => {
            if bytes.len() < 14 {
                return Err("truncated Ethernet header".into());
            }
            (be16(&bytes[12..14]), 14)
        }
        LINKTYPE_RAW => {
            let version = bytes.first().ok_or("empty raw IP frame")? >> 4;
            return match version {
                4 => parse_ipv4(bytes),
                6 => parse_ipv6(bytes),
                _ => Err("invalid raw IP version".into()),
            };
        }
        LINKTYPE_LINUX_SLL => {
            if bytes.len() < 16 {
                return Err("truncated Linux SLL header".into());
            }
            (be16(&bytes[14..16]), 16)
        }
        LINKTYPE_LINUX_SLL2 => {
            if bytes.len() < 20 || bytes[2..4] != [0, 0] {
                return Err("truncated/invalid Linux SLL2 header".into());
            }
            (be16(&bytes[0..2]), 20)
        }
        _ => return Err("unsupported linktype".into()),
    };
    // Ethernet and cooked captures use the same VLAN protocol encapsulation.
    // No inner-IP scan: unknown encapsulations must stay unclassified.
    for _ in 0..2 {
        if !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if bytes.len() < offset + 4 {
            return Err("truncated VLAN header".into());
        }
        ether_type = be16(&bytes[offset + 2..offset + 4]);
        offset += 4;
    }
    if matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        return Err("more than two VLAN headers".into());
    }
    match ether_type {
        0x0800 => parse_ipv4(&bytes[offset..]),
        0x86dd => parse_ipv6(&bytes[offset..]),
        _ => Ok(None),
    }
}

fn parse_ipv4(bytes: &[u8]) -> Result<Option<Packet>, String> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return Err("truncated/invalid IPv4 header".into());
    }
    let header_len = usize::from(bytes[0] & 15) * 4;
    let total_len = usize::from(be16(&bytes[2..4]));
    if header_len < 20 || total_len < header_len || total_len > bytes.len() {
        return Err("invalid/truncated IPv4 length".into());
    }
    let fragment = be16(&bytes[6..8]);
    // Reject MF, nonzero offset and the reserved flag. DF alone is fine.
    if fragment & 0xbfff != 0 {
        return Err("IPv4 fragments/reserved flags are not supported".into());
    }
    let src = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
    parse_transport(src, dst, bytes[9], &bytes[header_len..total_len])
}

fn parse_ipv6(bytes: &[u8]) -> Result<Option<Packet>, String> {
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return Err("truncated/invalid IPv6 header".into());
    }
    let payload_len = usize::from(be16(&bytes[4..6]));
    if payload_len == 0 {
        // Zero-length/no-next-header traffic has no transport data; jumbograms
        // require separate validation and must never be interpreted as TCP/UDP.
        return Ok(None);
    }
    let end = 40 + payload_len;
    if end > bytes.len() {
        return Err("truncated IPv6 payload".into());
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    dst.copy_from_slice(&bytes[24..40]);
    let (src, dst) = (IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)));
    let mut next = bytes[6];
    let mut offset = 40usize;
    let mut count = 0;
    loop {
        match next {
            6 | 17 => return parse_transport(src, dst, next, &bytes[offset..end]),
            44 => return Err("IPv6 fragments, including atomic fragments, are not supported".into()),
            0 | 43 | 60 | 51 => {
                if count >= MAX_IPV6_EXTENSIONS || offset + 2 > end {
                    return Err("truncated/excessive IPv6 extension headers".into());
                }
                if next == 0 && offset != 40 {
                    return Err("IPv6 hop-by-hop header is not first".into());
                }
                let length = if next == 51 {
                    // AH Payload Len counts 32-bit words, excluding first two.
                    (usize::from(bytes[offset + 1]) + 2) * 4
                } else {
                    (usize::from(bytes[offset + 1]) + 1) * 8
                };
                if (next == 51 && length < 12) || offset + length > end {
                    return Err("invalid/truncated IPv6 extension length".into());
                }
                next = bytes[offset];
                offset += length;
                count += 1;
            }
            // Includes ESP, No Next Header, tunnels, ICMPv6 and unknown options.
            _ => return Ok(None),
        }
    }
}

fn parse_transport(src_ip: IpAddr, dst_ip: IpAddr, protocol: u8, bytes: &[u8]) -> Result<Option<Packet>, String> {
    let (header_len, tcp_seq, flags) = match protocol {
        6 => {
            if bytes.len() < 20 {
                return Err("truncated TCP header".into());
            }
            let header_len = usize::from(bytes[12] >> 4) * 4;
            if header_len < 20 || header_len > bytes.len() {
                return Err("invalid TCP data offset".into());
            }
            let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            (header_len, Some(seq), bytes[13])
        }
        17 => {
            if bytes.len() < 8 {
                return Err("truncated UDP header".into());
            }
            let length = usize::from(be16(&bytes[4..6]));
            // IP-layer padding is outside IP total length. Inside IP, a
            // conflicting UDP length is ambiguous and not sent to the matcher.
            if length < 8 || length != bytes.len() {
                return Err("invalid UDP length".into());
            }
            (8, None, 0)
        }
        _ => return Ok(None),
    };
    Ok(Some(Packet {
        src_ip,
        dst_ip,
        src_port: be16(&bytes[..2]),
        dst_port: be16(&bytes[2..4]),
        protocol,
        tcp_seq,
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload: bytes[header_len..].to_vec(),
    }))
}

/// Sequential PCAP 2.4 reader. Buffers at most MAX_FRAME_LEN captured bytes,
/// plus one bounded parsed transport payload; it never buffers the whole file.
pub struct Capture<R: Read> {
    reader: R,
    endian: Endian,
    fraction_base: u32,
    snaplen: u32,
    frame: Vec<u8>,
    pub linktype: u32,
    pub packets_read: u64,
    pub malformed_packets: u64,
    pub skipped_packets: u64,
}

impl<R: Read> Capture<R> {
    pub fn new(mut reader: R) -> Result<Self, String> {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header).map_err(|e| format!("cannot read PCAP global header: {e}"))?;
        let (endian, fraction_base) = match header[..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, 1_000_000),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, 1_000_000),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, 1_000_000_000),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, 1_000_000_000),
            _ => return Err("unsupported capture magic; classic PCAP is required, not PCAPNG".into()),
        };
        if endian.u16(&header[4..6]) != 2 || endian.u16(&header[6..8]) != 4 {
            return Err("only PCAP version 2.4 is supported".into());
        }
        let snaplen = endian.u32(&header[16..20]);
        if snaplen == 0 || snaplen as usize > MAX_FRAME_LEN {
            return Err(format!("PCAP snaplen must be 1..={MAX_FRAME_LEN}"));
        }
        let linktype = endian.u32(&header[20..24]);
        if !supported(linktype) {
            return Err(format!("unsupported PCAP linktype/metadata 0x{linktype:x}"));
        }
        Ok(Self {
            reader, endian, fraction_base, snaplen, frame: Vec::new(), linktype,
            packets_read: 0, malformed_packets: 0, skipped_packets: 0,
        })
    }

    /// End of file is `None`; a skipped frame is `Some((time, None))`.
    /// PCAP framing errors are fatal; packet errors are counted and skipped.
    pub fn next_packet(&mut self) -> Result<Option<(f64, Option<Packet>)>, String> {
        let mut header = [0u8; 16];
        loop {
            match self.reader.read(&mut header[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("cannot read PCAP packet header: {e}")),
            }
        }
        self.reader.read_exact(&mut header[1..]).map_err(|e| format!("truncated PCAP packet header: {e}"))?;
        let secs = self.endian.u32(&header[0..4]);
        let fraction = self.endian.u32(&header[4..8]);
        let captured = self.endian.u32(&header[8..12]);
        let original = self.endian.u32(&header[12..16]);
        if fraction >= self.fraction_base {
            return Err("PCAP timestamp fraction exceeds its resolution".into());
        }
        if captured > self.snaplen || captured as usize > MAX_FRAME_LEN || captured > original {
            return Err("invalid PCAP captured/original length".into());
        }
        self.frame.resize(captured as usize, 0);
        self.reader.read_exact(&mut self.frame).map_err(|e| format!("truncated PCAP packet data: {e}"))?;
        self.packets_read = self.packets_read.saturating_add(1);
        let time = f64::from(secs) + f64::from(fraction) / f64::from(self.fraction_base);
        if captured < original {
            self.malformed_packets = self.malformed_packets.saturating_add(1);
            return Ok(Some((time, None)));
        }
        let packet = match parse_frame(self.linktype, &self.frame) {
            Ok(Some(packet)) => Some(packet),
            Ok(None) => {
                self.skipped_packets = self.skipped_packets.saturating_add(1);
                None
            }
            Err(_) => {
                self.malformed_packets = self.malformed_packets.saturating_add(1);
                None
            }
        };
        Ok(Some((time, packet)))
    }
}
