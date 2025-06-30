#![no_std]

// This file exists to enable the library target.

use aya_log_common::DefaultFormatter;
use aya_log_ebpf::WriteToBuf;
use core::num::NonZeroUsize;

#[repr(C)]
#[derive(Debug)]
pub struct Protocol(pub u8);

impl WriteToBuf for Protocol {
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        let protocol = self.0;
        let protocol_str = match protocol {
            17 => "UDP",
            6 => "TCP",
            1 => "ICMP",
            58 => "ICMPv6",
            2 => "IGMP",
            103 => "PIM",
            132 => "SCTP",
            _ => "Unknown",
        };

        protocol_str.write(buf)
    }
}

impl DefaultFormatter for Protocol {}

#[repr(C, packed)]
pub struct EthHdr {
    pub eth_dmac: [u8; 6],
    pub eth_smac: [u8; 6],
    pub eth_proto: u16,
}

#[repr(C, packed)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C, packed)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}
