use byteorder::{ByteOrder, NetworkEndian};

use port::PortNumber;

use super::FlowMatchFieldRepr;
use super::Packet;
use super::consts;

/// Output port from action set Metadata.
///
/// Metadata representing the forwarding decision in the action set. If the action set contains an output action, this field equals the output port. Else, the field equals its initial value, OFPP_UNSET.
///
/// Prereqs: None.
///
/// Format: 32-bit integer in network byte order.
///
/// Masking: Not maskable.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ActionSetOutput(PortNumber);
impl ActionSetOutput {
    pub fn new(value: PortNumber) -> Self {
        ActionSetOutput(value)
    }
}

impl FlowMatchFieldRepr for ActionSetOutput {
    type Value = PortNumber;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        ActionSetOutput::new(PortNumber::from(NetworkEndian::read_u32(packet.value())))
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.0.into())
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::ACTION_SET_OUTPUT
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InPort(u32);

impl InPort {
    pub fn new(value: u32) -> Self {
        InPort(value)
    }
}

impl FlowMatchFieldRepr for InPort {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        InPort::new(NetworkEndian::read_u32(packet.value()))
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.0)
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IN_PORT
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InPhysicalPort(u32);

impl InPhysicalPort {
    pub fn new(value: u32) -> Self {
        InPhysicalPort(value)
    }
}

impl FlowMatchFieldRepr for InPhysicalPort {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        InPhysicalPort::new(NetworkEndian::read_u32(packet.value()))
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.0)
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::IN_PHYSICAL_PORT
    }
}

///Table metadata.
///
/// Prereqs: None.
///
/// Format: 64-bit integer in network byte order.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Metadata {
    value: u64,
    mask: Option<u64>,
}

impl Metadata {
    pub fn new(value: u64, mask: Option<u64>) -> Self {
        Metadata {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for Metadata {
    type Value = u64;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = NetworkEndian::read_u64(&bytes[0..8]);
        let mask = if packet.has_mask() {
            Some(NetworkEndian::read_u64(&bytes[8..16]))
        } else {
            None
        };

        Metadata::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            16
        } else {
            8
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u64(buf, self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u64(&mut buf[8..], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::METADATA
    }
}

/// Logical Port Metadata.
///
/// Metadata associated with a logical port. If the logical port performs encapsulation and decapsulation, this is the demultiplexing field from the encapsulation header. For example, for a packet received via GRE tunnel including a (32-bit) key, the key is stored in the low 32-bits and the high bits are zeroed. For a MPLS logical port, the low 20 bits represent the MPLS Label. For a VxLAN logical port, the low 24 bits represent the VNI. If the packet is not received through a logical port, the value is 0.
///
/// Prereqs: None.
///
/// Format: 64-bit integer in network byte order.
///
/// Masking: Arbitrary masks.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TunnelId {
    value: u64,
    mask: Option<u64>,
}

impl TunnelId {
    pub fn new(value: u64, mask: Option<u64>) -> Self {
        TunnelId {
            value: value,
            mask: mask,
        }
    }
}

impl FlowMatchFieldRepr for TunnelId {
    type Value = u64;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        let bytes = packet.value();
        let value = NetworkEndian::read_u64(&bytes[0..8]);
        let mask = if packet.has_mask() {
            Some(NetworkEndian::read_u64(&bytes[8..16]))
        } else {
            None
        };

        TunnelId::new(value, mask)
    }

    fn value_len(&self) -> usize {
        if self.mask.is_some() {
            16
        } else {
            8
        }
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u64(buf, self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u64(&mut buf[8..], mask);
        }
    }

    fn set_value(&mut self, value: Self::Value) {
        self.value = value;
    }

    fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    fn code() -> u8 {
        consts::TUNNEL_ID
    }
}

/// Packet type.
///
/// Packet type to identify packets. This is the canonical header type of the outermost header. If not specified, default to Ethernet header type.
///
/// Prereqs: None.
///
/// Format: 16-bit integer for namespace followed by 16 bit interget for ns_type.
///
/// Masking: Not maskable. */
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketType(u32);

impl PacketType {
    pub fn new(value: u32) -> Self {
        PacketType(value)
    }
}

impl FlowMatchFieldRepr for PacketType {
    type Value = u32;

    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self {
        PacketType::new(NetworkEndian::read_u32(packet.value()))
    }

    fn value_len(&self) -> usize {
        4
    }

    fn emit_value(&self, buf: &mut [u8]) {
        NetworkEndian::write_u32(buf, self.0);
    }

    fn set_value(&mut self, value: Self::Value) {
        self.0 = value;
    }

    fn has_mask(&self) -> bool {
        false
    }

    fn code() -> u8 {
        consts::PACKET_TYPE
    }
}
