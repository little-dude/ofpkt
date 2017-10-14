use byteorder::{ByteOrder, NetworkEndian};
use smoltcp::wire::{EthernetAddress, EthernetProtocol, Icmpv4Message, Ipv4Address};

use super::Packet;
use super::{FlowMatchFieldMaskedRepr, FlowMatchFieldRepr};
use super::consts;

/// Flow match field for the destination address in Ethernet header.
///
/// - **Prereqs**: None.
/// - **Format**: 48-bit Ethernet MAC address.
/// - **Masking**: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthernetDestination {
    value: EthernetAddress,
    mask: Option<EthernetAddress>,
}

impl EthernetDestination {
    /// Create a new `EthernetDestination` flow match field
    pub fn new(value: EthernetAddress, mask: Option<EthernetAddress>) -> Self {
        EthernetDestination {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for EthernetDestination {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        let value = EthernetAddress::from_bytes(&buf[0..6]);
        let mask = if packet.has_mask() {
            Some(EthernetAddress::from_bytes(&buf[6..12]))
        } else {
            None
        };
        EthernetDestination::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            12
        } else {
            6
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[6..].as_mut().copy_from_slice(mask.as_bytes())
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ETHERNET_DESTINATION
    }
}

impl FlowMatchFieldMaskedRepr for EthernetDestination {
    type Mask = EthernetAddress;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// Source address in Ethernet header.
///
/// Prereqs: None.
///
/// Format: 48-bit Ethernet MAC address.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthernetSource {
    value: EthernetAddress,
    mask: Option<EthernetAddress>,
}

impl EthernetSource {
    pub fn new(value: EthernetAddress, mask: Option<EthernetAddress>) -> Self {
        EthernetSource {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for EthernetSource {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        let value = EthernetAddress::from_bytes(&buf[0..6]);
        let mask = if packet.has_mask() {
            Some(EthernetAddress::from_bytes(&buf[6..12]))
        } else {
            None
        };

        EthernetSource::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            12
        } else {
            6
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[6..].as_mut().copy_from_slice(mask.as_bytes())
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ETHERNET_SOURCE
    }
}

impl FlowMatchFieldMaskedRepr for EthernetSource {
    type Mask = EthernetAddress;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// Packet’s Ethernet type.
///
/// Prereqs: None.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthernetType(EthernetProtocol);

impl EthernetType {
    pub fn new(value: EthernetProtocol) -> Self {
        EthernetType(value)
    }
}

impl FlowMatchFieldRepr for EthernetType {
    type Value = EthernetProtocol;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let value = EthernetProtocol::from(NetworkEndian::read_u16(packet.value()));
        EthernetType::new(value)
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0.into());
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ETHERNET_TYPE
    }
}

/// For a packet with an 802.1Q header, this is the VLAN-ID (VID) from the outermost tag, with the CFI bit forced to 1. For a packet with no 802.1Q header, the CFI bit is forced to 0.
///
/// Prereqs: None.
///
/// Format: 16-bit integer in network byte order with bit 13 indicating presence of VLAN header and 3 most-significant bits forced to 0. Only the lower 13 bits have meaning.
///
/// Masking: Arbitrary masks.
///
/// This field can be used in various ways:
///
/// - If it is not constrained at all, the nx_match matches packets without an 802.1Q header or with an 802.1Q header that has any VID value.
/// - Testing for an exact match with 0x0 matches only packets without an 802.1Q header.
/// - Testing for an exact match with a VID value with CFI=1 matches packets that have an 802.1Q header with a specified VID.
/// - Testing for an exact match with a nonzero VID value with CFI=0 does not make sense. The switch may reject this combination.
/// - Testing with nxm_value=0, nxm_mask=0x0fff matches packets with no 802.1Q header or with an 802.1Q header with a VID of 0.
/// - Testing with nxm_value=0x1000, nxm_mask=0x1000 matches packets with an 802.1Q header that has any VID value.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VlanId {
    value: u16,
    mask: Option<u16>,
}

impl VlanId {
    pub fn new(value: u16, mask: Option<u16>) -> Self {
        VlanId {
            value: value & 0x1fff,
            mask: mask.and_then(|mask| Some(mask & 0x1fff)),
        }
    }

    /// Set the CFI (aka DEI) bit to 1, indicating that a VLAN id is set
    pub fn set_dei(&mut self) {
        self.value |= 0x1000
    }

    /// Unset the CFI (aka DEI) bit to 1, indicating that no VLAN id is set
    pub fn unset_dei(&mut self) {
        self.value &= 0x0fff
    }
}

impl FlowMatchFieldRepr for VlanId {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = NetworkEndian::read_u16(&bytes[0..2]);
        if packet.has_mask() {
            VlanId::new(value, Some(NetworkEndian::read_u16(&bytes[2..4])))
        } else {
            VlanId::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u16(&mut buf[2..4], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = 0x1fff & value
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::VLAN_ID
    }
}

impl FlowMatchFieldMaskedRepr for VlanId {
    type Mask = u16;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask & 0x1fff)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// 802.1Q PCP.
///
/// For a packet with an 802.1Q header, this is the VLAN-PCP from the outermost tag. For a
/// packet with no 802.1Q header, this has value 0.
///
/// Prereqs: OXM_OF_VLAN_VID must be different from OFPVID_NONE.
///
/// Format: 8-bit integer with 5 most-significant bits forced to 0.  Only the lower 3 bits have
/// meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VlanPriority(u8);

impl VlanPriority {
    pub fn new(value: u8) -> Self {
        VlanPriority(value & 0b0000_0111)
    }
}

impl FlowMatchFieldRepr for VlanPriority {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        VlanPriority::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 0b0000_0111;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::VLAN_PRIORITY
    }
}

/// The Diff Serv Code Point (DSCP) bits of the IP header. Part of the IPv4 ToS field or the IPv6 Traffic Class field.
///
/// Prereqs: either OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd).
///
/// Format: 8-bit integer with 2 most-significant bits forced to 0. Only the lower 6 bits have meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpDscp(u8);

impl IpDscp {
    pub fn new(value: u8) -> Self {
        IpDscp(value & 0b0011_1111)
    }
}

impl FlowMatchFieldRepr for IpDscp {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        IpDscp::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 0b0011_1111;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IP_DSCP
    }
}

/// The ECN bits of the IP header. Part of the IPv4 ToS field or the IPv6 Traffic Class field.
///
/// Prereqs: either OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd).
///
/// Format: 8-bit integer with 6 most-significant bits forced to 0.  Only the lower 2 bits have meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpEcn(u8);

impl IpEcn {
    pub fn new(value: u8) -> Self {
        IpEcn(value & 0b0000_0011)
    }
}

impl FlowMatchFieldRepr for IpEcn {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        IpEcn::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 0b0000_0011;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IP_ECN
    }
}

/// The "protocol" byte in the IP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd).
///
/// Format: 8-bit integer.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpProtocol(u8);

impl IpProtocol {
    pub fn new(value: u8) -> Self {
        IpProtocol(value)
    }
}

impl FlowMatchFieldRepr for IpProtocol {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        IpProtocol::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IP_PROTOCOL
    }
}

/// The source address in the IP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x0800 exactly, or PACKET_TYPE must match (1,0x800) exactly.
///
/// Format: 32-bit integer in network byte order.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv4Source {
    value: Ipv4Address,
    mask: Option<Ipv4Address>,
}

impl Ipv4Source {
    pub fn new(value: Ipv4Address, mask: Option<Ipv4Address>) -> Self {
        Ipv4Source {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for Ipv4Source {
    type Value = Ipv4Address;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = Ipv4Address::from_bytes(&bytes[0..4]);
        if packet.has_mask() {
            Ipv4Source::new(value, Some(Ipv4Address::from_bytes(&bytes[4..8])))
        } else {
            Ipv4Source::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[4..8].copy_from_slice(mask.as_bytes());
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV4_SOURCE
    }
}

impl FlowMatchFieldMaskedRepr for Ipv4Source {
    type Mask = Ipv4Address;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// The destination address in the IP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x0800 exactly, or PACKET_TYPE must match (1,0x800) exactly.
///
/// Format: 32-bit integer in network byte order.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArpSpa {
    value: Ipv4Address,
    mask: Option<Ipv4Address>,
}

impl ArpSpa {
    pub fn new(value: Ipv4Address, mask: Option<Ipv4Address>) -> Self {
        ArpSpa {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for ArpSpa {
    type Value = Ipv4Address;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = Ipv4Address::from_bytes(&bytes[0..4]);
        if packet.has_mask() {
            ArpSpa::new(value, Some(Ipv4Address::from_bytes(&bytes[4..8])))
        } else {
            ArpSpa::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[4..8].copy_from_slice(mask.as_bytes());
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ARP_SPA
    }
}

impl FlowMatchFieldMaskedRepr for ArpSpa {
    type Mask = Ipv4Address;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArpTpa {
    value: Ipv4Address,
    mask: Option<Ipv4Address>,
}

impl ArpTpa {
    pub fn new(value: Ipv4Address, mask: Option<Ipv4Address>) -> Self {
        ArpTpa {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for ArpTpa {
    type Value = Ipv4Address;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = Ipv4Address::from_bytes(&bytes[0..4]);
        if packet.has_mask() {
            ArpTpa::new(value, Some(Ipv4Address::from_bytes(&bytes[4..8])))
        } else {
            ArpTpa::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[4..8].copy_from_slice(mask.as_bytes());
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ARP_TPA
    }
}

impl FlowMatchFieldMaskedRepr for ArpTpa {
    type Mask = Ipv4Address;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}


/// The source port in the TCP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 6 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcpSource(u16);

impl TcpSource {
    pub fn new(value: u16) -> Self {
        TcpSource(value)
    }
}

impl FlowMatchFieldRepr for TcpSource {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        TcpSource::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::TCP_SOURCE
    }
}

/// The destination port in the TCP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 6 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcpDestination(u16);

impl TcpDestination {
    pub fn new(value: u16) -> Self {
        TcpDestination(value)
    }
}

impl FlowMatchFieldRepr for TcpDestination {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        TcpDestination::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::TCP_DESTINATION
    }
}


/// The flags in the TCP header.
///
/// Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd. OXM_OF_IP_PROTO must match 6 exactly.
///
/// Format: 16-bit integer with 4 most-significant bits forced to 0.
///
/// Masking: Bits 0-11 fully maskable. *
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TcpFlags {
    value: u16,
    mask: Option<u16>,
}

impl TcpFlags {
    pub fn new(value: u16, mask: Option<u16>) -> Self {
        TcpFlags {
            value: value & 0x0fff,
            mask: mask.and_then(|mask| Some(mask & 0x0fff)),
        }
    }
}

impl FlowMatchFieldRepr for TcpFlags {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = NetworkEndian::read_u16(&bytes[..2]);
        if packet.has_mask() {
            TcpFlags::new(value, Some(NetworkEndian::read_u16(&bytes[2..4])))
        } else {
            TcpFlags::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(&mut buf[0..2], self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u16(&mut buf[2..4], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value & 0x0fff;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::TCP_FLAGS
    }
}

impl FlowMatchFieldMaskedRepr for TcpFlags {
    type Mask = u16;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask & 0x0fff);
    }

    fn unset_mask(&mut self) {
        self.mask = None;
    }
}

/// The source port in the UDP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 17 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UdpSource(u16);

impl UdpSource {
    pub fn new(value: u16) -> Self {
        UdpSource(value)
    }
}

impl FlowMatchFieldRepr for UdpSource {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        UdpSource::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::UDP_SOURCE
    }
}

/// The destination port in the UDP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 17 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UdpDestination(u16);

impl UdpDestination {
    pub fn new(value: u16) -> Self {
        UdpDestination(value)
    }
}

impl FlowMatchFieldRepr for UdpDestination {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        UdpDestination::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::UDP_DESTINATION
    }
}

/// The source port in the SCTP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 132 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SctpSource(u16);

impl SctpSource {
    pub fn new(value: u16) -> Self {
        SctpSource(value)
    }
}

impl FlowMatchFieldRepr for SctpSource {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        SctpSource::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::SCTP_SOURCE
    }
}

/// The destionation port in the SCTP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd, or PACKET_TYPE must be either (1,0x800) or (1,0x86dd), OXM_OF_IP_PROTO must match 132 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SctpDestination(u16);

impl SctpDestination {
    pub fn new(value: u16) -> Self {
        SctpDestination(value)
    }
}

impl FlowMatchFieldRepr for SctpDestination {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        SctpDestination::new(NetworkEndian::read_u16(packet.value()))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::SCTP_DESTINATION
    }
}

/// The code in the ICMP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x0800 exactly, or PACKET_TYPE must match (1,0x800) exactly. OXM_OF_IP_PROTO must match 1 exactly.
///
/// Format: 8-bit integer.
///
/// Masking: Not maskable. */
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IcmpCode(u8);

impl IcmpCode {
    pub fn new(value: u8) -> Self {
        IcmpCode(value)
    }
}

impl FlowMatchFieldRepr for IcmpCode {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        IcmpCode::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ICMP_CODE
    }
}

/// The type in the ICMP header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x0800 exactly, or PACKET_TYPE must match (1,0x800) exactly. OXM_OF_IP_PROTO must match 1 exactly.
///
/// Format: 8-bit integer.
///
/// Masking: Not maskable. */
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IcmpType(Icmpv4Message);

impl IcmpType {
    pub fn new(value: Icmpv4Message) -> Self {
        IcmpType(value)
    }
}

impl FlowMatchFieldRepr for IcmpType {
    type Value = Icmpv4Message;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        IcmpType::new(Icmpv4Message::from(packet.value()[0]))
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0.into();
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ICMP_TYPE
    }
}

/// ARP opcode.
///
/// For an Ethernet+IP ARP packet, the opcode in the ARP header. Always 0 otherwise.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
///
/// Format: 16-bit integer in network byte order.
///
/// Masking: Not maskable
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArpOpCode(EthernetProtocol);

impl ArpOpCode {
    pub fn new(value: EthernetProtocol) -> Self {
        ArpOpCode(value)
    }
}

impl FlowMatchFieldRepr for ArpOpCode {
    type Value = EthernetProtocol;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        ArpOpCode::new(EthernetProtocol::from(
            NetworkEndian::read_u16(packet.value()),
        ))
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.0.into());
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ARP_OP_CODE
    }
}

/// For an Ethernet+IP ARP packet, the source or target protocol address in the ARP header. Always 0 otherwise.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
///
/// Format: 32-bit integer in network byte order.
///
/// Masking: Arbitrary masks.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv4Destination {
    value: Ipv4Address,
    mask: Option<Ipv4Address>,
}

impl Ipv4Destination {
    pub fn new(value: Ipv4Address, mask: Option<Ipv4Address>) -> Self {
        Ipv4Destination {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for Ipv4Destination {
    type Value = Ipv4Address;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = Ipv4Address::from_bytes(&bytes[0..4]);
        if packet.has_mask() {
            Ipv4Destination::new(value, Some(Ipv4Address::from_bytes(&bytes[4..8])))
        } else {
            Ipv4Destination::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[4..8].copy_from_slice(mask.as_bytes());
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV4_DESTINATION
    }
}

impl FlowMatchFieldMaskedRepr for Ipv4Destination {
    type Mask = Ipv4Address;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// For an Ethernet+IP ARP packet, the source or target hardware address in the ARP header. Always 0 otherwise.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
/// Format: 48-bit Ethernet MAC address.
///
/// Masking: Not maskable
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArpSha {
    value: EthernetAddress,
    mask: Option<EthernetAddress>,
}

impl ArpSha {
    pub fn new(value: EthernetAddress, mask: Option<EthernetAddress>) -> Self {
        ArpSha {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for ArpSha {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        let value = EthernetAddress::from_bytes(&buf[0..6]);
        let mask = if packet.has_mask() {
            Some(EthernetAddress::from_bytes(&buf[6..12]))
        } else {
            None
        };
        ArpSha::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            12
        } else {
            6
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[6..12].as_mut().copy_from_slice(mask.as_bytes())
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ARP_SHA
    }
}

impl FlowMatchFieldMaskedRepr for ArpSha {
    type Mask = EthernetAddress;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ArpTha {
    value: EthernetAddress,
    mask: Option<EthernetAddress>,
}

impl ArpTha {
    pub fn new(value: EthernetAddress, mask: Option<EthernetAddress>) -> Self {
        ArpTha {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for ArpTha {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        let value = EthernetAddress::from_bytes(&buf[0..6]);
        let mask = if packet.has_mask() {
            Some(EthernetAddress::from_bytes(&buf[6..12]))
        } else {
            None
        };
        ArpTha::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            12
        } else {
            6
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.value.as_bytes());
        if let Some(mask) = self.mask {
            buf[6..12].as_mut().copy_from_slice(mask.as_bytes())
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::ARP_THA
    }
}

impl FlowMatchFieldMaskedRepr for ArpTha {
    type Mask = EthernetAddress;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// The source or destination address in the IPv6 header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly.
///
/// Format: 128-bit IPv6 address.
///
/// Masking: Arbitrary masks.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6Source {
    value: [u8; 16],
    mask: Option<[u8; 16]>,
}

impl Ipv6Source {
    fn new(value: [u8; 16], mask: Option<[u8; 16]>) -> Self {
        Ipv6Source {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for Ipv6Source {
    type Value = [u8; 16];

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();

        let mut value = [0; 16];
        value.as_mut().copy_from_slice(&buf[0..16]);

        let mask = if packet.has_mask() {
            let mut mask = [0; 16];
            mask.as_mut().copy_from_slice(&buf[16..32]);
            Some(mask)
        } else {
            None
        };

        Ipv6Source::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            32
        } else {
            16
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.value[..]);
        if let Some(mask) = self.mask {
            buf[16..].as_mut().copy_from_slice(&mask[..])
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV6_SOURCE
    }
}

impl FlowMatchFieldMaskedRepr for Ipv6Source {
    type Mask = [u8; 16];

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6Destination {
    value: [u8; 16],
    mask: Option<[u8; 16]>,
}

impl Ipv6Destination {
    fn new(value: [u8; 16], mask: Option<[u8; 16]>) -> Self {
        Ipv6Destination {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for Ipv6Destination {
    type Value = [u8; 16];

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();

        let mut value = [0; 16];
        value.as_mut().copy_from_slice(&buf[0..16]);

        let mask = if packet.has_mask() {
            let mut mask = [0; 16];
            mask.as_mut().copy_from_slice(&buf[16..32]);
            Some(mask)
        } else {
            None
        };

        Ipv6Destination::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            32
        } else {
            16
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.value[..]);
        if let Some(mask) = self.mask {
            buf[16..].as_mut().copy_from_slice(&mask[..])
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV6_DESTINATION
    }
}

impl FlowMatchFieldMaskedRepr for Ipv6Destination {
    type Mask = [u8; 16];

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// The IPv6 Flow Label
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly.
///
/// Format: 32-bit integer with 12 most-significant bits forced to 0.  Only the lower 20 bits have meaning.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6FlowLabel {
    value: u32,
    mask: Option<u32>,
}

impl Ipv6FlowLabel {
    pub fn new(value: u32, mask: Option<u32>) -> Self {
        Ipv6FlowLabel {
            value: value & 0x000f_ffff,
            mask: mask.and_then(|mask| Some(mask & 0x000f_ffff)),
        }
    }
}

impl FlowMatchFieldRepr for Ipv6FlowLabel {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();

        let value = NetworkEndian::read_u32(&buf[..4]);
        if packet.has_mask() {
            Ipv6FlowLabel::new(value, Some(NetworkEndian::read_u32(&buf[4..8])))
        } else {
            Ipv6FlowLabel::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u32(&mut buf[4..8], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = 0x000f_ffff & value
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV6_FLOW_LABEL
    }
}

impl FlowMatchFieldMaskedRepr for Ipv6FlowLabel {
    type Mask = u32;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}



/// The code in the ICMPv6 header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly, OXM_OF_IP_PROTO must match 58 exactly.
///
/// Format: 8-bit integer.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Icmpv6Code(u8);

impl Icmpv6Code {
    pub fn new(value: u8) -> Self {
        Icmpv6Code(value)
    }
}

impl FlowMatchFieldRepr for Icmpv6Code {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        Icmpv6Code::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ICMPV6_CODE
    }
}

/// The type in the ICMPv6 header.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly, OXM_OF_IP_PROTO must match 58 exactly.
///
/// Format: 8-bit integer.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Icmpv6Type(u8);

impl Icmpv6Type {
    pub fn new(value: u8) -> Self {
        Icmpv6Type(value)
    }
}

impl FlowMatchFieldRepr for Icmpv6Type {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        Icmpv6Type::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ICMPV6_TYPE
    }
}

/// The target address in an IPv6 Neighbor Discovery message.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly, OXM_OF_IP_PROTO must match 58 exactly. OXM_OF_ICMPV6_TYPE must be either 135 or 136.
///
/// Format: 128-bit IPv6 address.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6NdTarget([u8; 16]);

impl Ipv6NdTarget {
    fn new(value: [u8; 16]) -> Self {
        Ipv6NdTarget(value)
    }
}

impl FlowMatchFieldRepr for Ipv6NdTarget {
    type Value = [u8; 16];

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();

        let mut value = [0; 16];
        value.as_mut().copy_from_slice(&buf[0..16]);
        Ipv6NdTarget::new(value)
    }

    fn value_len(&self) -> usize {
        16
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0[..]);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IPV6_ND_TARGET
    }
}

/// The source link-layer address option in an IPv6 Neighbor Discovery message.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly, OXM_OF_IP_PROTO must match 58 exactly. OXM_OF_ICMPV6_TYPE must be exactly 135.
///
/// Format: 48-bit Ethernet MAC address.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6NdSll(EthernetAddress);

impl Ipv6NdSll {
    pub fn new(value: EthernetAddress) -> Self {
        Ipv6NdSll(value)
    }
}

impl FlowMatchFieldRepr for Ipv6NdSll {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        Ipv6NdSll::new(EthernetAddress::from_bytes(&buf[0..6]))
    }

    fn value_len(&self) -> usize {
        6
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.0.as_bytes());
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IPV6_ND_SLL
    }
}

/// The target link-layer address option in an IPv6 Neighbor Discovery message.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly, OXM_OF_IP_PROTO must match 58 exactly. OXM_OF_ICMPV6_TYPE must be exactly 136.
///
/// Format: 48-bit Ethernet MAC address.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6NdTll(EthernetAddress);

impl Ipv6NdTll {
    pub fn new(value: EthernetAddress) -> Self {
        Ipv6NdTll(value)
    }
}

impl FlowMatchFieldRepr for Ipv6NdTll {
    type Value = EthernetAddress;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        Ipv6NdTll::new(EthernetAddress::from_bytes(&buf[0..6]))
    }

    fn value_len(&self) -> usize {
        6
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.0.as_bytes());
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IPV6_ND_TLL
    }
}

/// The LABEL in the first MPLS shim header.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
///
/// Format: 32-bit integer in network byte order with 12 most-significant bits forced to 0. Only the lower 20 bits have meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MplsLabel(u32);

impl MplsLabel {
    pub fn new(value: u32) -> Self {
        MplsLabel(value & 0x000f_ffff)
    }
}

impl FlowMatchFieldRepr for MplsLabel {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        MplsLabel::new(NetworkEndian::read_u32(packet.value()))
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 0x000f_ffff;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::MPLS_LABEL
    }
}

/// The TC in the first MPLS shim header.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
///
/// Format: 8-bit integer with 5 most-significant bits forced to 0. Only the lower 3 bits have meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MplsTc(u8);

impl MplsTc {
    pub fn new(value: u8) -> Self {
        MplsTc(value & 0b0000_0111)
    }
}

impl FlowMatchFieldRepr for MplsTc {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        MplsTc::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 0b0000_0111;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::MPLS_TC
    }
}

/// The BoS bit in the first MPLS shim header.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
///
/// Format: 8-bit integer with 7 most-significant bits forced to 0. Only the lowest bit have a meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MplsBos(u8);

impl MplsBos {
    pub fn new(value: u8) -> Self {
        MplsBos(value & 1)
    }
}

impl FlowMatchFieldRepr for MplsBos {
    type Value = u8;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        MplsBos::new(packet.value()[0])
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = self.0;
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value & 1;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::MPLS_BOS
    }
}

/// IEEE 802.1ah UCA.
///
/// For a packet with a PBB header, this is the UCA (Use Customer Address) from the outermost service tag.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x88E7 exactly.
///
/// Format: 8-bit integer with 7 most-significant bits forced to 0. Only the lower 1 bit has meaning.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PbbUca(bool);

impl PbbUca {
    pub fn new(value: bool) -> Self {
        PbbUca(value)
    }
}

impl FlowMatchFieldRepr for PbbUca {
    type Value = bool;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        PbbUca::new(bytes[0] & 1 == 1)
    }

    fn value_len(&self) -> usize {
        1
    }

    fn emit_value(&self, buf: &mut [u8]) {
        if self.0 {
            buf[0] = 1;
        } else {
            buf[0] = 0;
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::PBB_UCA
    }
}

/// IEEE 802.1ah I-SID.
///
/// For a packet with a PBB header, this is the I-SID from the outermost service tag.
///
/// Prereqs: OXM_OF_ETH_TYPE must match 0x88E7 exactly.
///
/// Format: 24-bit integer in network byte order.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PbbIsid {
    value: u32,
    mask: Option<u32>,
}

impl PbbIsid {
    pub fn new(value: u32, mask: Option<u32>) -> Self {
        PbbIsid {
            value: value & 0x00ff_ffff,
            mask: mask.and_then(|mask| Some(mask & 0x00ff_ffff)),
        }
    }
}

impl FlowMatchFieldRepr for PbbIsid {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = (u32::from(bytes[0]) << 16) + (u32::from(bytes[1]) << 8) + u32::from(bytes[2]);
        let mask = if packet.has_mask() {
            Some((u32::from(bytes[3]) << 16) + (u32::from(bytes[4]) << 8) + u32::from(bytes[5]))
        } else {
            None
        };
        PbbIsid::new(value, mask)
    }

    fn value_len(&self) -> usize {
        3
    }

    fn emit_value(&self, buf: &mut [u8]) {
        buf[0] = ((self.value >> 16) & 0x0000_00ff) as u8;
        buf[1] = ((self.value >> 8) & 0x0000_00ff) as u8;
        buf[2] = (self.value & 0x0000_00ff) as u8;

        if let Some(mask) = self.mask {
            buf[3] = ((mask >> 16) & 0x0000_00ff) as u8;
            buf[4] = ((mask >> 8) & 0x0000_00ff) as u8;
            buf[5] = (mask & 0x0000_00ff) as u8;
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = 0x00ff_ffff & value
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::PBB_ISID
    }
}

impl FlowMatchFieldMaskedRepr for PbbIsid {
    type Mask = u32;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask & 0x00ff_ffff)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}

/// The IPv6 Extension Header pseudo-field.
///
/// Prereqs: either OXM_OF_ETH_TYPE must match 0x86dd exactly, or PACKET_TYPE must match (1,0x86dd) exactly.
///
/// Format: 16-bit integer with 7 most-significant bits forced to 0. Only the lower 9 bits have meaning.
///
/// Masking: Maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ipv6ExtensionHeader {
    value: u16,
    mask: Option<u16>,
}

impl Ipv6ExtensionHeader {
    pub fn new(value: u16, mask: Option<u16>) -> Self {
        Ipv6ExtensionHeader {
            value: value & 0x01ff,
            mask: mask.and_then(|mask| Some(mask & 0x1ff)),
        }
    }
}

impl FlowMatchFieldRepr for Ipv6ExtensionHeader {
    type Value = u16;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let buf = packet.value();
        let value = NetworkEndian::read_u16(&buf[..2]);
        if packet.has_mask() {
            Ipv6ExtensionHeader::new(value, Some(NetworkEndian::read_u16(&buf[2..4])))
        } else {
            Ipv6ExtensionHeader::new(value, None)
        }
    }

    fn value_len(&self) -> usize {
        2
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u16(buf, self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u16(&mut buf[2..4], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = 0x1ff & value
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::IPV6_EXTENSION_HEADER
    }
}

impl FlowMatchFieldMaskedRepr for Ipv6ExtensionHeader {
    type Mask = u16;

    fn set_mask(&mut self, mask: Self::Mask) {
        self.mask = Some(mask & 0x1ff)
    }

    fn unset_mask(&mut self) {
        self.mask = None
    }
}
