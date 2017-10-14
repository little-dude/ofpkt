mod consts;
pub mod header;
pub mod pipeline;

use {Error, Result};
use super::{Packet, CLASS_OPEN_FLOW_BASIC, OXM_HEADER_LEN};
use self::header::*;
use self::pipeline::*;

trait FlowMatchFieldRepr {
    type Value;

    /// Parse an OXM field buffer and return the corresponding flow match field representation
    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Self;
    fn value_len(&self) -> usize;
    /// Write this flow match field representation value in the given buffer.
    fn emit_value(&self, buf: &mut [u8]);
    /// Set the value of this flow match field.
    fn set_value(&mut self, value: Self::Value);
    /// Return the `oxm_field` value that correspond to this flow match field.
    fn code() -> u8;
    /// Return `true` if this flow match field representation has a mask
    fn has_mask(&self) -> bool;
    /// Write the bytes stream corresponding to this flow match field representation in the given buffer.
    fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if self.buffer_len() > buf.len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buf);
        packet.set_class(CLASS_OPEN_FLOW_BASIC);
        packet.set_field(Self::code());
        packet.set_length(self.value_len() as u8);
        if self.has_mask() {
            packet.set_mask()
        } else {
            packet.unset_mask()
        }
        self.emit_value(packet.value_mut());
        Ok(())
    }

    /// Return the length of the OXM field that correspond to this flow match field representation
    fn buffer_len(&self) -> usize {
        self.value_len() + OXM_HEADER_LEN
    }
}

trait FlowMatchFieldMaskedRepr {
    type Mask;
    /// Set the mask
    fn set_mask(&mut self, mask: Self::Mask);
    /// Unset the mask
    fn unset_mask(&mut self);
}

/// Represent a flow match field. A flow match field is an OXM field with `oxm_class` set to
/// [`CLASS_OPEN_FLOW_BASIC`](constant.CLASS_OPEN_FLOW_BASIC.html)
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FlowMatchField {
    InPort(InPort),
    InPhysicalPort(InPhysicalPort),
    Metadata(Metadata),
    EthernetDestination(EthernetDestination),
    EthernetSource(EthernetSource),
    VlanId(VlanId),
    VlanPriority(VlanPriority),
    IpDscp(IpDscp),
    IpEcn(IpEcn),
    IpProtocol(IpProtocol),
    Ipv4Source(Ipv4Source),
    Ipv4Destination(Ipv4Destination),
    TcpSource(TcpSource),
    TcpDestination(TcpDestination),
    UdpSource(UdpSource),
    UdpDestination(UdpDestination),
    SctpSource(SctpSource),
    SctpDestination(SctpDestination),
    IcmpType(IcmpType),
    IcmpCode(IcmpCode),
    ArpOpCode(ArpOpCode),
    ArpSpa(ArpSpa),
    ArpTpa(ArpTpa),
    ArpSha(ArpSha),
    ArpTha(ArpTha),
    Ipv6Source(Ipv6Source),
    Ipv6Destination(Ipv6Destination),
    Ipv6FlowLabel(Ipv6FlowLabel),
    Icmpv6Type(Icmpv6Type),
    Icmpv6Code(Icmpv6Code),
    Ipv6NdTarget(Ipv6NdTarget),
    Ipv6NdSll(Ipv6NdSll),
    Ipv6NdTll(Ipv6NdTll),
    MplsLabel(MplsLabel),
    MplsTc(MplsTc),
    MplsBos(MplsBos),
    PbbUca(PbbUca),
    TcpFlags(TcpFlags),
    ActionSetOutput(ActionSetOutput),
    PbbIsid(PbbIsid),
    TunnelId(TunnelId),
    Ipv6ExtensionHeader(Ipv6ExtensionHeader),
    PacketType(PacketType),
}

impl FlowMatchField {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Result<Self> {
        let match_field = match packet.field() {
            consts::IN_PORT               => FlowMatchField::InPort(InPort::parse(packet)),
            consts::IN_PHYSICAL_PORT      => FlowMatchField::InPhysicalPort(InPhysicalPort::parse(packet)),
            consts::METADATA              => FlowMatchField::Metadata(Metadata::parse(packet)),
            consts::ETHERNET_DESTINATION  => FlowMatchField::EthernetDestination(EthernetDestination::parse(packet)),
            consts::ETHERNET_SOURCE       => FlowMatchField::EthernetSource(EthernetSource::parse(packet)),
            consts::VLAN_ID               => FlowMatchField::VlanId(VlanId::parse(packet)),
            consts::VLAN_PRIORITY         => FlowMatchField::VlanPriority(VlanPriority::parse(packet)),
            consts::IP_DSCP               => FlowMatchField::IpDscp(IpDscp::parse(packet)),
            consts::IP_ECN                => FlowMatchField::IpEcn(IpEcn::parse(packet)),
            consts::IP_PROTOCOL           => FlowMatchField::IpProtocol(IpProtocol::parse(packet)),
            consts::IPV4_SOURCE           => FlowMatchField::Ipv4Source(Ipv4Source::parse(packet)),
            consts::IPV4_DESTINATION      => FlowMatchField::Ipv4Destination(Ipv4Destination::parse(packet)),
            consts::TCP_SOURCE            => FlowMatchField::TcpSource(TcpSource::parse(packet)),
            consts::TCP_DESTINATION       => FlowMatchField::TcpDestination(TcpDestination::parse(packet)),
            consts::UDP_SOURCE            => FlowMatchField::UdpSource(UdpSource::parse(packet)),
            consts::UDP_DESTINATION       => FlowMatchField::UdpDestination(UdpDestination::parse(packet)),
            consts::SCTP_SOURCE           => FlowMatchField::SctpSource(SctpSource::parse(packet)),
            consts::SCTP_DESTINATION      => FlowMatchField::SctpDestination(SctpDestination::parse(packet)),
            consts::ICMP_TYPE             => FlowMatchField::IcmpType(IcmpType::parse(packet)),
            consts::ICMP_CODE             => FlowMatchField::IcmpCode(IcmpCode::parse(packet)),
            consts::ARP_OP_CODE           => FlowMatchField::ArpOpCode(ArpOpCode::parse(packet)),
            consts::ARP_SPA               => FlowMatchField::ArpSpa(ArpSpa::parse(packet)),
            consts::ARP_TPA               => FlowMatchField::ArpTpa(ArpTpa::parse(packet)),
            consts::ARP_SHA               => FlowMatchField::ArpSha(ArpSha::parse(packet)),
            consts::ARP_THA               => FlowMatchField::ArpTha(ArpTha::parse(packet)),
            consts::IPV6_SOURCE           => FlowMatchField::Ipv6Source(Ipv6Source::parse(packet)),
            consts::IPV6_DESTINATION      => FlowMatchField::Ipv6Destination(Ipv6Destination::parse(packet)),
            consts::IPV6_FLOW_LABEL       => FlowMatchField::Ipv6FlowLabel(Ipv6FlowLabel::parse(packet)),
            consts::ICMPV6_TYPE           => FlowMatchField::Icmpv6Type(Icmpv6Type::parse(packet)),
            consts::ICMPV6_CODE           => FlowMatchField::Icmpv6Code(Icmpv6Code::parse(packet)),
            consts::IPV6_ND_TARGET        => FlowMatchField::Ipv6NdTarget(Ipv6NdTarget::parse(packet)),
            consts::IPV6_ND_SLL           => FlowMatchField::Ipv6NdSll(Ipv6NdSll::parse(packet)),
            consts::IPV6_ND_TLL           => FlowMatchField::Ipv6NdTll(Ipv6NdTll::parse(packet)),
            consts::MPLS_LABEL            => FlowMatchField::MplsLabel(MplsLabel::parse(packet)),
            consts::MPLS_TC               => FlowMatchField::MplsTc(MplsTc::parse(packet)),
            consts::MPLS_BOS              => FlowMatchField::MplsBos(MplsBos::parse(packet)),
            consts::PBB_ISID              => FlowMatchField::PbbIsid(PbbIsid::parse(packet)),
            consts::TUNNEL_ID             => FlowMatchField::TunnelId(TunnelId::parse(packet)),
            consts::IPV6_EXTENSION_HEADER => FlowMatchField::Ipv6ExtensionHeader(Ipv6ExtensionHeader::parse(packet)),
            consts::PBB_UCA               => FlowMatchField::PbbUca(PbbUca::parse(packet)),
            consts::TCP_FLAGS             => FlowMatchField::TcpFlags(TcpFlags::parse(packet)),
            consts::ACTION_SET_OUTPUT     => FlowMatchField::ActionSetOutput(ActionSetOutput::parse(packet)),
            consts::PACKET_TYPE           => FlowMatchField::PacketType(PacketType::parse(packet)),
            _                             => return Err(Error::BadOxmField),
        };
        Ok(match_field)
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn buffer_len(&self) -> usize {
        match *self {
            FlowMatchField::InPort(ref field)              => field.buffer_len(),
            FlowMatchField::InPhysicalPort(ref field)      => field.buffer_len(),
            FlowMatchField::Metadata(ref field)            => field.buffer_len(),
            FlowMatchField::EthernetDestination(ref field) => field.buffer_len(),
            FlowMatchField::EthernetSource(ref field)      => field.buffer_len(),
            FlowMatchField::VlanId(ref field)              => field.buffer_len(),
            FlowMatchField::VlanPriority(ref field)        => field.buffer_len(),
            FlowMatchField::IpDscp(ref field)              => field.buffer_len(),
            FlowMatchField::IpEcn(ref field)               => field.buffer_len(),
            FlowMatchField::IpProtocol(ref field)          => field.buffer_len(),
            FlowMatchField::Ipv4Source(ref field)          => field.buffer_len(),
            FlowMatchField::Ipv4Destination(ref field)     => field.buffer_len(),
            FlowMatchField::TcpSource(ref field)           => field.buffer_len(),
            FlowMatchField::TcpDestination(ref field)      => field.buffer_len(),
            FlowMatchField::UdpSource(ref field)           => field.buffer_len(),
            FlowMatchField::UdpDestination(ref field)      => field.buffer_len(),
            FlowMatchField::SctpSource(ref field)          => field.buffer_len(),
            FlowMatchField::SctpDestination(ref field)     => field.buffer_len(),
            FlowMatchField::IcmpType(ref field)            => field.buffer_len(),
            FlowMatchField::IcmpCode(ref field)            => field.buffer_len(),
            FlowMatchField::ArpOpCode(ref field)           => field.buffer_len(),
            FlowMatchField::ArpSpa(ref field)              => field.buffer_len(),
            FlowMatchField::ArpTpa(ref field)              => field.buffer_len(),
            FlowMatchField::ArpSha(ref field)              => field.buffer_len(),
            FlowMatchField::ArpTha(ref field)              => field.buffer_len(),
            FlowMatchField::Ipv6Source(ref field)          => field.buffer_len(),
            FlowMatchField::Ipv6Destination(ref field)     => field.buffer_len(),
            FlowMatchField::Ipv6FlowLabel(ref field)       => field.buffer_len(),
            FlowMatchField::Icmpv6Type(ref field)          => field.buffer_len(),
            FlowMatchField::Icmpv6Code(ref field)          => field.buffer_len(),
            FlowMatchField::Ipv6NdTarget(ref field)        => field.buffer_len(),
            FlowMatchField::Ipv6NdSll(ref field)           => field.buffer_len(),
            FlowMatchField::Ipv6NdTll(ref field)           => field.buffer_len(),
            FlowMatchField::MplsLabel(ref field)           => field.buffer_len(),
            FlowMatchField::MplsTc(ref field)              => field.buffer_len(),
            FlowMatchField::MplsBos(ref field)             => field.buffer_len(),
            FlowMatchField::PbbIsid(ref field)             => field.buffer_len(),
            FlowMatchField::TunnelId(ref field)            => field.buffer_len(),
            FlowMatchField::Ipv6ExtensionHeader(ref field) => field.buffer_len(),
            FlowMatchField::PbbUca(ref field)              => field.buffer_len(),
            FlowMatchField::TcpFlags(ref field)            => field.buffer_len(),
            FlowMatchField::ActionSetOutput(ref field)     => field.buffer_len(),
            FlowMatchField::PacketType(ref field)          => field.buffer_len(),
        }
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        match *self {
            FlowMatchField::InPort(ref field)              => field.emit(buffer),
            FlowMatchField::InPhysicalPort(ref field)      => field.emit(buffer),
            FlowMatchField::Metadata(ref field)            => field.emit(buffer),
            FlowMatchField::EthernetDestination(ref field) => field.emit(buffer),
            FlowMatchField::EthernetSource(ref field)      => field.emit(buffer),
            FlowMatchField::VlanId(ref field)              => field.emit(buffer),
            FlowMatchField::VlanPriority(ref field)        => field.emit(buffer),
            FlowMatchField::IpDscp(ref field)              => field.emit(buffer),
            FlowMatchField::IpEcn(ref field)               => field.emit(buffer),
            FlowMatchField::IpProtocol(ref field)          => field.emit(buffer),
            FlowMatchField::Ipv4Source(ref field)          => field.emit(buffer),
            FlowMatchField::Ipv4Destination(ref field)     => field.emit(buffer),
            FlowMatchField::TcpSource(ref field)           => field.emit(buffer),
            FlowMatchField::TcpDestination(ref field)      => field.emit(buffer),
            FlowMatchField::UdpSource(ref field)           => field.emit(buffer),
            FlowMatchField::UdpDestination(ref field)      => field.emit(buffer),
            FlowMatchField::SctpSource(ref field)          => field.emit(buffer),
            FlowMatchField::SctpDestination(ref field)     => field.emit(buffer),
            FlowMatchField::IcmpType(ref field)            => field.emit(buffer),
            FlowMatchField::IcmpCode(ref field)            => field.emit(buffer),
            FlowMatchField::ArpOpCode(ref field)           => field.emit(buffer),
            FlowMatchField::ArpSpa(ref field)              => field.emit(buffer),
            FlowMatchField::ArpTpa(ref field)              => field.emit(buffer),
            FlowMatchField::ArpSha(ref field)              => field.emit(buffer),
            FlowMatchField::ArpTha(ref field)              => field.emit(buffer),
            FlowMatchField::Ipv6Source(ref field)          => field.emit(buffer),
            FlowMatchField::Ipv6Destination(ref field)     => field.emit(buffer),
            FlowMatchField::Ipv6FlowLabel(ref field)       => field.emit(buffer),
            FlowMatchField::Icmpv6Type(ref field)          => field.emit(buffer),
            FlowMatchField::Icmpv6Code(ref field)          => field.emit(buffer),
            FlowMatchField::Ipv6NdTarget(ref field)        => field.emit(buffer),
            FlowMatchField::Ipv6NdSll(ref field)           => field.emit(buffer),
            FlowMatchField::Ipv6NdTll(ref field)           => field.emit(buffer),
            FlowMatchField::MplsLabel(ref field)           => field.emit(buffer),
            FlowMatchField::MplsTc(ref field)              => field.emit(buffer),
            FlowMatchField::MplsBos(ref field)             => field.emit(buffer),
            FlowMatchField::PbbIsid(ref field)             => field.emit(buffer),
            FlowMatchField::TunnelId(ref field)            => field.emit(buffer),
            FlowMatchField::Ipv6ExtensionHeader(ref field) => field.emit(buffer),
            FlowMatchField::PbbUca(ref field)              => field.emit(buffer),
            FlowMatchField::TcpFlags(ref field)            => field.emit(buffer),
            FlowMatchField::ActionSetOutput(ref field)     => field.emit(buffer),
            FlowMatchField::PacketType(ref field)          => field.emit(buffer),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg_attr(rustfmt, rustfmt_skip)]
    static BYTES: [u8; 8] = [
        // first oxm tlv
        0x80, 0x00, // class = 0x8000 = openflow basic
        0x00, // field (0=in_port), no mask
        0x04, // length = 4
        0x00, 0x00, 0xab, 0xcd, // value = 43981
    ];

    #[test]
    fn test_parse() {
        let parsed = FlowMatchField::parse(&Packet::new(&BYTES)).unwrap();
        let expected = FlowMatchField::InPort(InPort::new(0xabcd));
        assert_eq!(parsed, expected);
    }
}
