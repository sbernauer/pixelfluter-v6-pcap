use std::{
    net::Ipv6Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Ok, Result};
use etherparse::PacketBuilder;
use pcap::{Device, Packet, PacketHeader};

mod args;

const SRC_MAC: [u8; 6] = [0x13, 0x13, 0x13, 0x13, 0x13, 0x13];
// const DST_MAC: [u8; 6] = [42, 42, 42, 42, 42, 42];
const DST_MAC: [u8; 6] = [0xb8, 0x27, 0xeb, 0x0a, 0x1e, 0x5b];
// b8:27:eb:0a:1e:5b

fn main() -> Result<()> {
    let src_ip = "::1";
    let dst_ip_net = "2001:67c:20a1:1234::";

    let src_ip: Ipv6Addr = src_ip
        .parse()
        .with_context(|| format!("Failde to parse source IP {src_ip}"))?;
    let dst_ip_net: Ipv6Addr = dst_ip_net
        .parse()
        .with_context(|| format!("Failed to parse destination IP subnet {dst_ip_net}"))?;
    if dst_ip_net.octets()[8..].iter().any(|o| *o != 0) {
        bail!("The given IPv6 subnet must be a /64 network!");
    }

    let now = now()?;

    // FIXME: I don't want to do this just to write packets to a file beause
    // 1. This requires more permissions than needed
    // 2. This might also capture other packets flying around
    let loopback = Device::from("lo");
    // let cap = Capture::from_device(loopback)?
    //     .promisc(false)
    //     .snaplen(0)
    //     .open()
    //     .unwrap();
    let cap = loopback.open()?;
    let mut save = cap.savefile("pixelflut_v6.pcap")?;

    for x in 100_u16..200 {
        for y in 100_u16..200 {
            let rgba: u32 = 0xeeee_eeee;

            let mut dst_ip = dst_ip_net.octets();
            dst_ip[8] = (x >> 8) as u8;
            dst_ip[9] = x as u8;
            dst_ip[10] = (y >> 8) as u8;
            dst_ip[11] = y as u8;
            dst_ip[12] = (rgba >> 24) as u8;
            dst_ip[13] = (rgba >> 16) as u8;
            dst_ip[14] = (rgba >> 8) as u8;
            dst_ip[15] = rgba as u8;

            let packet_builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
                .ipv6(src_ip.octets(), dst_ip, u8::MAX) //destination mac
                .udp(1337, 1234);
            let payload = [];

            let mut packet_data = Vec::<u8>::with_capacity(packet_builder.size(payload.len()));
            packet_builder.write(&mut packet_data, &payload).unwrap();

            let packet_len: u32 = packet_data
                .len()
                .try_into()
                .context("Packet too long for u32")?;
            let pcap_header = PacketHeader {
                ts: now,
                caplen: packet_len,
                len: packet_len,
            };
            let pcap_packet: Packet = Packet {
                header: &pcap_header,
                data: &packet_data,
            };

            save.write(&pcap_packet);
        }
    }

    Ok(())
}

fn now() -> Result<libc::timeval> {
    let unx_time: std::time::Duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get duration since unix epoch")?;

    Ok(libc::timeval {
        tv_sec: unx_time
            .as_secs()
            .try_into()
            .context("Failed to convert unix seconds to i64")?,
        tv_usec: unx_time
            .subsec_micros()
            .try_into()
            .context("Failed to convert unix subsec_micros to i64")?,
    })
}

// // https://github.com/rust-pcap/pcap/issues/98
// fn write_packet_to_file(mut file: impl Write, packet: &Packet) -> Result<()> {
//     unsafe {
//         file.write_all(any_as_u8_slice(&(packet.header.ts.tv_sec as u32)))
//             .unwrap();
//         file.write_all(any_as_u8_slice(&(packet.header.ts.tv_usec as u32)))
//             .unwrap();
//         file.write_all(any_as_u8_slice(&packet.header.caplen))
//             .unwrap();
//         file.write_all(any_as_u8_slice(&packet.header.len)).unwrap();
//     }
//     file.write_all(&packet.data).unwrap();

//     Ok(())
// }

// unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
//     slice::from_raw_parts((p as *const T) as *const u8, mem::size_of::<T>())
// }
