//! Implementation of OXM (OpenFlow eXtensible Match)
//!
//! An OXM TLV (Type-Length-Value) packet is made of a 32 bytes header and a variable size value.
//!
//!
//! # Message structure
//!
//!
//! ```no_rust
//! 0                       16             23  24             32
//! +------------------------+-------------+----+-------------+
//! |       oxm_class        |  oxm_field  | HM |  oxm_length |
//! +------------------------+-------------+----+-------------+
//! |                     value and/or mask                   |
//! |                      (variable size)                    |
//! +---------------------------------------------------------+
//! ```
//!
//! ## `oxm_class`
//!
//! The class can take multiple values (see the [`CLASS_XXX`](#constants) consts), but only three
//! are valid:
//!
//! - [`CLASS_OPEN_FLOW_BASIC`](constant.CLASS_OPEN_FLOW_BASIC.html) which correspond to a regular
//!   flow match field. Such fields are represented by the [`FlowMatchField`](enum.FlowMatchField.html)
//!   enum.
//! - [`CLASS_PACKET_REGISTERS`](constant.CLASS_PACKET_REGISTERS.html)
//! - [`CLASS_EXPERIMENTER`](constant.CLASS_EXPERIMENTER.html)
//!
//! ## `oxm_field`
//!
//! The `oxm_field` is a class-specific value identifying one of the match types within the match
//! class.
//!
//! The combination of `oxm_class` and `oxm_field` (the most-significant 23 bits of the header) are
//! collectively `oxm_type`. The `oxm_type` normally designates a protocol header field, such as
//! the Ethernet type, but it can also refer to a packet pipeline field, such as the switch port on
//! which a packet arrived.
//!
//! ## `HM` (Has Mask)
//!
//! A 1 bit flag. If set to 1, half the payload represents a value, and half represents a mask. If
//! set to 0, the whole payload represents a value.
//!
//! ## `oxm_length`
//!
//! Length of the payload in bytes (so the total length of the packet is 4 + `oxm_length`
//!

use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};

mod packet;
pub use self::packet::Packet;

mod fields;
pub use self::fields::FlowMatchField;
pub use self::fields::header::*;
pub use self::fields::pipeline::*;

mod flow_match;
pub use self::flow_match::PacketRepr as FlowMatch;

/// Backward compatibility with NXM
pub const CLASS_NXM0: u16 = 0x0000;
/// Backward compatibility with NXM
pub const CLASS_NXM1: u16 = 0x0001;
/// Basic class for OpenFlow
pub const CLASS_OPEN_FLOW_BASIC: u16 = 0x8000;
/// Packet registers (pipeline fields)
pub const CLASS_PACKET_REGISTERS: u16 = 0x8001;
/// Experimenter class
pub const CLASS_EXPERIMENTER: u16 = 0xFFFF;

const OXM_HEADER_LEN: usize = 4;

/// Represent an OXM field
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Oxm<E> {
    /// Represent an flow match field OXM field (_i.e._ with `oxm_class` equal to
    /// [`CLASS_OPEN_FLOW_BASIC`](constant.CLASS_OPEN_FLOW_BASIC.html)
    FlowMatchField(FlowMatchField),
    /// Represent an experimented OXM packet (_i.e._ with `oxm_class` equal to
    /// [`CLASS_EXPERIMENTER`](constant.CLASS_EXPERIMENTER.html)
    Experimenter(E),
    /// Represent a packet registers OXM packet (_i.e._ with `oxm_class` equal to
    /// [`CLASS_PACKET_REGISTERS`](constant.CLASS_PACKET_REGISTERS.html)
    PacketRegisters(PacketRegisters),
}

impl<E: Repr> Repr for Oxm<E> {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;

        match packet.class() {
            CLASS_OPEN_FLOW_BASIC => Ok(Oxm::FlowMatchField(FlowMatchField::parse(&packet)?)),
            CLASS_PACKET_REGISTERS => Ok(Oxm::PacketRegisters(PacketRegisters::parse(&packet)?)),
            CLASS_EXPERIMENTER => Ok(Oxm::Experimenter(E::parse(packet.into_inner())?)),
            CLASS_NXM0 | CLASS_NXM1 => Err(Error::UnsupportedOxmClass),
            _ => Err(Error::BadOxmClass),
        }
    }

    fn buffer_len(&self) -> usize {
        match *self {
            Oxm::FlowMatchField(ref repr) => repr.buffer_len(),
            Oxm::PacketRegisters(ref repr) => repr.buffer_len(),
            Oxm::Experimenter(ref repr) => repr.buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        match *self {
            Oxm::FlowMatchField(ref repr) => repr.emit(buffer),
            Oxm::PacketRegisters(ref repr) => repr.emit(buffer),
            Oxm::Experimenter(ref repr) => repr.emit(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRegisters {
    pub field: u8,
    pub value: u64,
    pub mask: Option<u64>,
}

impl PacketRegisters {
    fn parse<'a, T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Result<Self> {
        // check that the length field should be 8 or 16 depending on whether there is a mask.
        let len_field = packet.length();
        if len_field != 8 && len_field != 16 {
            return Err(Error::Malformed);
        }
        // We know that the length is correct per above check,
        // and that the inner buffer has enough bytes since `Packet.check_len()` is called
        // before this method is called.
        let buf = packet.value();
        let value = NetworkEndian::read_u64(&buf[0..8]);
        let mask = if packet.has_mask() {
            Some(NetworkEndian::read_u64(&buf[8..16]))
        } else {
            None
        };
        Ok(PacketRegisters {
            field: packet.field(),
            value: value,
            mask: mask,
        })
    }

    fn buffer_len(&self) -> usize {
        if self.mask.is_some() {
            // 4 bytes header + 8 bytes value + 8 bytes mask
            20
        } else {
            // 4 bytes header + 8 bytes value
            12
        }
    }

    fn emit(&self, buf: &mut [u8]) -> Result<()> {
        if self.buffer_len() > buf.len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buf);
        packet.set_class(CLASS_PACKET_REGISTERS);
        packet.set_field(self.field);
        packet.set_length(self.buffer_len() as u8);
        if self.mask.is_some() {
            packet.set_mask();
        } else {
            packet.unset_mask();
        }
        let buf = packet.value_mut();
        NetworkEndian::write_u64(&mut buf[0..8], self.value);
        if let Some(mask) = self.mask {
            NetworkEndian::write_u64(&mut buf[8..16], mask);
        }
        Ok(())
    }
}
