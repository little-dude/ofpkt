/// Switch input port
pub const IN_PORT: u8 = 0;
/// Switch physical input port
pub const IN_PHYSICAL_PORT: u8 = 1;
/// Metadata passed between tables
pub const METADATA: u8 = 2;
/// Ethernet destination address
pub const ETHERNET_DESTINATION: u8 = 3;
/// Ethernet source address
pub const ETHERNET_SOURCE: u8 = 4;
/// Ethernet frame type
pub const ETHERNET_TYPE: u8 = 5;
/// VLAN id
pub const VLAN_ID: u8 = 6;
/// VLAN priority
pub const VLAN_PRIORITY: u8 = 7;
/// IP DSCP (6 bits in TOS field)
pub const IP_DSCP: u8 = 8;
/// IP ECN (2 bites in TOS field)
pub const IP_ECN: u8 = 9;
/// IP protocol
pub const IP_PROTOCOL: u8 = 10;
/// IPv4 source address
pub const IPV4_SOURCE: u8 = 11;
/// IPv4 destination address
pub const IPV4_DESTINATION: u8 = 12;
/// TCP source port
pub const TCP_SOURCE: u8 = 13;
/// TCP destination port
pub const TCP_DESTINATION: u8 = 14;
/// UDP source port
pub const UDP_SOURCE: u8 = 15;
/// UDP destination port
pub const UDP_DESTINATION: u8 = 16;
/// SCTP source port
pub const SCTP_SOURCE: u8 = 17;
/// SCTP destination port
pub const SCTP_DESTINATION: u8 = 18;
/// ICMP type
pub const ICMP_TYPE: u8 = 19;
/// ICMP code
pub const ICMP_CODE: u8 = 20;
/// ARP op code
pub const ARP_OP_CODE: u8 = 21;
/// ARP source protocol address
pub const ARP_SPA: u8 = 22;
/// ARP target protocol address
pub const ARP_TPA: u8 = 23;
/// ARP source hardware address
pub const ARP_SHA: u8 = 24;
/// ARP target hardware address
pub const ARP_THA: u8 = 25;
/// IPv6 source address
pub const IPV6_SOURCE: u8 = 26;
/// IPv6 destination address
pub const IPV6_DESTINATION: u8 = 27;
/// IPv6 flow label
pub const IPV6_FLOW_LABEL: u8 = 28;
/// ICMPv6 type
pub const ICMPV6_TYPE: u8 = 29;
/// ICMPv6 code
pub const ICMPV6_CODE: u8 = 30;
/// Target address for IPv6 ND
pub const IPV6_ND_TARGET: u8 = 31;
/// Source link-layer for IPv6 ND
pub const IPV6_ND_SLL: u8 = 32;
/// Destination link-layer for IPv6 ND
pub const IPV6_ND_TLL: u8 = 33;
/// MPLS label
pub const MPLS_LABEL: u8 = 34;
/// MPLS TC
pub const MPLS_TC: u8 = 35;
/// MPLS BoS bit
pub const MPLS_BOS: u8 = 36;
/// PBB I-SID
pub const PBB_ISID: u8 = 37;
/// Logical port metadata
pub const TUNNEL_ID: u8 = 38;
/// IPv6 extension header
pub const IPV6_EXTENSION_HEADER: u8 = 39;
/// PBB UCA header field
pub const PBB_UCA: u8 = 41;
/// TCP flags
pub const TCP_FLAGS: u8 = 42;
/// Output port from action set matadata
pub const ACTION_SET_OUTPUT: u8 = 43;
/// Packet type value
pub const PACKET_TYPE: u8 = 44;
