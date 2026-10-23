use dpi_bridge::packet::{parse_packet, Capture, MAX_FRAME_LEN};
use std::io::{self, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr};

fn tcp(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[..2].copy_from_slice(&50000u16.to_be_bytes());
    packet[2..4].copy_from_slice(&443u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
    packet[12] = 0x50;
    packet[13] = 0x17;
    packet.extend_from_slice(payload);
    packet
}

fn udp(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 8];
    packet[..2].copy_from_slice(&50000u16.to_be_bytes());
    packet[2..4].copy_from_slice(&53u16.to_be_bytes());
    packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&[10, 10, 10, 69]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
    packet.extend_from_slice(payload);
    packet
}

fn ipv6(proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = proto;
    packet[7] = 64;
    packet[8] = 0xfd;
    packet[23] = 69;
    packet[24..28].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]);
    packet[39] = 1;
    packet.extend_from_slice(payload);
    packet
}

fn link(linktype: u32, ip: &[u8], tags: usize) -> Vec<u8> {
    let ether_type: u16 = if ip[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
    let mut frame = match linktype {
        1 => vec![0; 14],
        113 => vec![0; 16],
        276 => vec![0; 20],
        101 => return ip.to_vec(),
        _ => panic!("invalid test linktype"),
    };
    let field = match linktype { 1 => 12, 113 => 14, _ => 0 };
    frame[field..field+2].copy_from_slice(&(if tags > 0 { 0x8100u16 } else { ether_type }).to_be_bytes());
    for index in 0..tags {
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&(if index + 1 < tags { 0x88a8u16 } else { ether_type }).to_be_bytes());
    }
    frame.extend_from_slice(ip);
    frame
}

fn put16(out: &mut Vec<u8>, value: u16, little: bool) {
    out.extend_from_slice(&if little { value.to_le_bytes() } else { value.to_be_bytes() });
}

fn put32(out: &mut Vec<u8>, value: u32, little: bool) {
    out.extend_from_slice(&if little { value.to_le_bytes() } else { value.to_be_bytes() });
}

fn capture_header(little: bool, nano: bool, linktype: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put32(&mut out, if nano { 0xa1b23c4d } else { 0xa1b2c3d4 }, little);
    put16(&mut out, 2, little);
    put16(&mut out, 4, little);
    put32(&mut out, 0, little);
    put32(&mut out, 0, little);
    put32(&mut out, MAX_FRAME_LEN as u32, little);
    put32(&mut out, linktype, little);
    out
}

fn record(out: &mut Vec<u8>, frame: &[u8], little: bool, fraction: u32, original: u32) {
    put32(out, 1700000000, little);
    put32(out, fraction, little);
    put32(out, frame.len() as u32, little);
    put32(out, original, little);
    out.extend_from_slice(frame);
}

#[test]
fn supports_all_four_linktypes_with_exact_tcp_fields() {
    let ip = ipv4(6, &tcp(b"hello"));
    for linktype in [1, 101, 113, 276] {
        let packet = parse_packet(linktype, &link(linktype, &ip, 0)).unwrap().unwrap();
        assert_eq!(packet.src_ip, IpAddr::V4(Ipv4Addr::new(10,10,10,69)));
        assert_eq!(packet.src_port, 50000);
        assert_eq!(packet.dst_port, 443);
        assert_eq!(packet.protocol, 6);
        assert_eq!(packet.tcp_seq, Some(0x12345678));
        assert!(packet.syn && packet.ack && packet.fin && packet.rst);
        assert_eq!(packet.payload, b"hello");
    }
}

#[test]
fn accepts_two_vlan_layers_and_rejects_a_third() {
    let ip = ipv4(17, &udp(b"abc"));
    for linktype in [1, 113, 276] {
        for tags in [1,2] {
            assert_eq!(parse_packet(linktype, &link(linktype, &ip, tags)).unwrap().unwrap().payload, b"abc");
        }
        assert!(parse_packet(linktype, &link(linktype, &ip, 3)).unwrap().is_none());
    }
}

#[test]
fn ipv6_udp_and_supported_extensions() {
    for extension in [0,43,60,51] {
        let mut ext = vec![0u8; if extension == 51 { 16 } else { 8 }];
        ext[0] = 17;
        ext[1] = if extension == 51 { 2 } else { 0 };
        ext.extend_from_slice(&udp(b"dns"));
        let packet = parse_packet(101, &ipv6(extension, &ext)).unwrap().unwrap();
        assert!(packet.src_ip.is_ipv6());
        assert_eq!(packet.protocol, 17);
        assert_eq!(packet.tcp_seq, None);
        assert!(!packet.syn && !packet.ack && !packet.fin && !packet.rst);
        assert_eq!(packet.payload, b"dns");
    }
}

#[test]
fn ipv4_options_and_link_padding_do_not_become_payload() {
    let mut ip = ipv4(6, &tcp(b"x"));
    ip.splice(20..20, [1,1,0,0]);
    ip[0] = 0x46;
    let total = ip.len() as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0xaa;20]);
    assert_eq!(parse_packet(101, &ip).unwrap().unwrap().payload, b"x");
}

#[test]
fn rejects_all_ip_fragments_including_atomic_ipv6() {
    for field in [1u16, 0x2000, 0x2001] {
        let mut ip = ipv4(6, &tcp(b"must not match"));
        ip[6..8].copy_from_slice(&field.to_be_bytes());
        assert!(parse_packet(101, &ip).unwrap().is_none());
    }
    for field in [0u16,1,8] {
        let mut frag = vec![0u8;8];
        frag[0] = 6;
        frag[2..4].copy_from_slice(&field.to_be_bytes());
        frag.extend_from_slice(&tcp(b"must not match"));
        assert!(parse_packet(101, &ipv6(44, &frag)).unwrap().is_none());
    }
    let mut df = ipv4(6, &tcp(b"ok"));
    df[6] = 0x40;
    assert!(parse_packet(101, &df).unwrap().is_some());
}

#[test]
fn every_truncation_of_valid_ip_tcp_udp_is_rejected() {
    for ip in [ipv4(6, &tcp(b"data")), ipv4(17, &udp(b"data")), ipv6(6, &tcp(b"data")), ipv6(17, &udp(b"data"))] {
        for linktype in [1,101,113,276] {
            let frame = link(linktype, &ip, 0);
            for end in 0..frame.len() {
                assert!(parse_packet(linktype, &frame[..end]).unwrap().is_none(), "type={linktype} end={end}");
            }
        }
    }
}

#[test]
fn refuses_conflicting_transport_lengths() {
    for offset in [0u8,4,15] {
        let mut segment = tcp(b"abc");
        segment[12] = offset << 4;
        assert!(parse_packet(101, &ipv4(6, &segment)).unwrap().is_none());
    }
    for length in [0u16,7,8,100] {
        let mut segment = udp(b"abc");
        segment[4..6].copy_from_slice(&length.to_be_bytes());
        assert!(parse_packet(101, &ipv6(17, &segment)).unwrap().is_none());
    }
}

#[test]
fn extension_headers_are_bounded_and_not_scanned_for_embedded_tcp() {
    let mut too_short = vec![17,255,0,0,0,0,0,0];
    too_short.extend_from_slice(&udp(b"x"));
    assert!(parse_packet(101, &ipv6(60, &too_short)).unwrap().is_none());
    let mut chain = Vec::new();
    for index in 0..17 { chain.extend_from_slice(&[if index == 16 {17} else {60},0,0,0,0,0,0,0]); }
    chain.extend_from_slice(&udp(b"x"));
    assert!(parse_packet(101, &ipv6(60, &chain)).unwrap().is_none());
    assert!(parse_packet(101, &ipv6(50, &tcp(b"encrypted lookalike"))).unwrap().is_none());
}

#[test]
fn reads_both_endians_and_both_timestamp_resolutions() {
    let frame = link(1, &ipv4(6, &tcp(b"pcap")), 0);
    for little in [true,false] {
        for nano in [true,false] {
            let mut bytes = capture_header(little,nano,1);
            record(&mut bytes,&frame,little,if nano {123_456_789} else {123_456},frame.len() as u32);
            let mut capture = Capture::new(Cursor::new(bytes)).unwrap();
            assert_eq!(capture.linktype,1);
            let (time,packet) = capture.next_packet().unwrap().unwrap();
            assert!((time-(1700000000.0+if nano {0.123456789} else {0.123456})).abs() < 0.000001);
            assert_eq!(packet.unwrap().payload,b"pcap");
            assert!(capture.next_packet().unwrap().is_none());
            assert_eq!(capture.packets_read,1);
        }
    }
}

#[test]
fn malformed_frame_is_counted_without_losing_next_record() {
    let valid = ipv4(17,&udp(b"next"));
    let mut bytes = capture_header(true,false,101);
    record(&mut bytes,&[0],true,0,1);
    record(&mut bytes,&valid,true,0,valid.len() as u32);
    let mut capture=Capture::new(Cursor::new(bytes)).unwrap();
    assert!(capture.next_packet().unwrap().unwrap().1.is_none());
    assert_eq!(capture.next_packet().unwrap().unwrap().1.unwrap().payload,b"next");
    assert_eq!(capture.malformed_packets,1);
}

#[test]
fn snapshot_truncation_is_not_allowed_to_classify() {
    let valid=ipv4(6,&tcp(b"partial even if IP length fits"));
    let mut bytes=capture_header(true,false,101);
    record(&mut bytes,&valid,true,0,valid.len() as u32+1);
    let mut capture=Capture::new(Cursor::new(bytes)).unwrap();
    assert!(capture.next_packet().unwrap().unwrap().1.is_none());
    assert_eq!(capture.malformed_packets,1);
}

#[test]
fn pcap_structural_errors_are_fatal_before_large_allocations() {
    for length in 0..24 { assert!(Capture::new(Cursor::new(vec![0u8;length])).is_err()); }
    let mut pcapng=capture_header(true,false,1);
    pcapng[..4].copy_from_slice(&[0x0a,0x0d,0x0d,0x0a]);
    assert!(Capture::new(Cursor::new(pcapng)).is_err());
    let mut huge=capture_header(true,false,1);
    huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Capture::new(Cursor::new(huge)).is_err());
    assert!(Capture::new(Cursor::new(capture_header(true,false,999))).is_err());
    for (captured,original,fraction) in [(u32::MAX,u32::MAX,0),(20,10,0),(0,0,1_000_000)] {
        let mut bytes=capture_header(true,false,101);
        put32(&mut bytes,1,true);put32(&mut bytes,fraction,true);
        put32(&mut bytes,captured,true);put32(&mut bytes,original,true);
        assert!(Capture::new(Cursor::new(bytes)).unwrap().next_packet().is_err());
    }
    let frame=ipv4(17,&udp(b"a"));
    let mut bytes=capture_header(true,false,101);
    record(&mut bytes,&frame,true,0,frame.len() as u32);
    for end in 25..bytes.len() {
        assert!(Capture::new(Cursor::new(bytes[..end].to_vec())).unwrap().next_packet().is_err());
    }
}

struct ShortReader { bytes: Cursor<Vec<u8>>, interrupted: bool }
impl Read for ShortReader {
    fn read(&mut self, out:&mut [u8])->io::Result<usize> {
        if !self.interrupted { self.interrupted=true;return Err(io::Error::from(io::ErrorKind::Interrupted)); }
        let size=out.len().min(3);
        self.bytes.read(&mut out[..size])
    }
}

#[test]
fn read_trait_supports_short_reads_and_interruption() {
    let frame=ipv4(6,&tcp(b"stream"));
    let mut bytes=capture_header(true,false,101);
    record(&mut bytes,&frame,true,0,frame.len() as u32);
    let reader=ShortReader{bytes:Cursor::new(bytes),interrupted:false};
    let mut capture=Capture::new(reader).unwrap();
    assert_eq!(capture.next_packet().unwrap().unwrap().1.unwrap().payload,b"stream");
}

#[test]
fn arbitrary_bytes_and_oversized_frames_never_panic() {
    let mut seed=7u32;
    for length in 0..512 {
        let bytes:Vec<u8>=(0..length).map(|_| {seed=seed.wrapping_mul(1664525).wrapping_add(1013904223);(seed>>24) as u8}).collect();
        for linktype in [1,101,113,276] { let _=parse_packet(linktype,&bytes).unwrap(); }
    }
    assert!(parse_packet(101,&vec![0;MAX_FRAME_LEN+1]).unwrap().is_none());
    assert!(parse_packet(999,&[]).is_err());
}
