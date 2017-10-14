//! A read/write wrapper around an OpenFlow packet buffer.
//!
//! ```no_rust
//! +--------+--------+--------+--------+
//! |version |  type  |     length      |
//! +--------+--------+--------+--------+
//! |                xid                |
//! +--------+--------+--------+--------+
//! |              payload              |
//! +--------+--------+--------+--------+
//! ```
//!
//! - The version field indicates the version of OpenFlow which this message belongs
//! - The length field gives the message length, including the header itself.
//! - The xid, or transaction identifier, is a unique value used to match requests to responses.
//!
use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};
use error;
use hello;
use features_reply;
use set_config;
use packet_in;
use get_config_reply;

enum_with_unknown! {
    /// OpenFlow version
    pub doc enum Version(u8) {
        /// OpenFlow 1.0
        OpenFlow1Dot0 = 1,
        /// OpenFlow 1.1
        OpenFlow1Dot1 = 2,
        /// OpenFlow 1.2
        OpenFlow1Dot2 = 3,
        /// OpenFlow 1.3
        OpenFlow1Dot3 = 4,
        /// OpenFlow 1.4
        OpenFlow1Dot4 = 5,
        /// OpenFlow 1.5
        OpenFlow1Dot5 = 6,
        /// OpenFlow 1.6
        OpenFlow1Dot6 = 7
    }
}

enum_with_unknown! {
    /// OpenFlow version
    pub doc enum Kind(u8) {

        ///
        Hello               = 0,
        ///
        Error               = 1,
        ///
        EchoRequest         = 2,
        ///
        EchoReply           = 3,
        ///
        Experimenter        = 4,

        ///
        FeaturesRequest     = 5,
        ///
        FeaturesReply       = 6,
        ///
        GetConfigRequest    = 7,
        ///
        GetConfigReply      = 8,
        ///
        SetConfig           = 9,

        ///
        PacketIn            = 10,
        ///
        FlowRemoved         = 11,
        ///
        PortStatus          = 12,

        ///
        PacketOut           = 13,
        ///
        FlowMod             = 14,
        ///
        GroupMod            = 15,
        ///
        PortMod             = 16,
        ///
        TableMod            = 17,

        ///
        MultipartRequest    = 18,
        ///
        MultipartReply      = 19,

        ///
        BarrierRequest      = 20,
        ///
        BarrierReply        = 21,

        ///
        RoleRequest         = 24,
        ///
        RoleReply           = 25,

        ///
        GetAsynRequest      = 26,
        ///
        GetAsyncReply       = 27,
        ///
        SetAsync            = 28,

        ///
        MeterMod            = 29,

        ///
        RoleStatus          = 30,

        ///
        TableStatus         = 31,

        ///
        RequestForward      = 32,

        ///
        BundleControler     = 33,
        ///
        BundleAddMessage    = 34
    }
}

/// A wrapper around a buffer that represent an OpenFlow packet. `Packet` provides getters and
/// setters for each of the OpenFlow packet fields.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use field::*;

    pub const VERSION: usize = 0;
    pub const KIND: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const XID: Field = 4..8;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with OpenFlow packet structure.
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < self.header_len() as usize {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> Version {
        let data = self.buffer.as_ref();
        Version::from(data[field::VERSION])
    }

    /// Return the type field. The type field indicates what type of message is present and how to
    /// interpret the payload. Message types are documented in the [Kind] enum.
    ///
    /// [Kind]: enum.Kind.html
    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.buffer.as_ref();
        Kind::from(data[field::KIND])
    }

    /// Return the length field. The length field indicates the payload length.
    #[inline]
    pub fn length(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the xid field. The xid, or transaction identifier, is a unique value used to match
    /// requests to responses
    #[inline]
    pub fn xid(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::XID])
    }

    /// Return the header length.
    pub fn header_len(&self) -> usize {
        field::XID.end
    }
}

impl<'a, T: AsRef<[u8]>> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: Version) {
        let data = self.buffer.as_mut();
        data[field::VERSION] = value.into()
    }

    /// Set the type field.
    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        let data = self.buffer.as_mut();
        data[field::KIND] = value.into()
    }

    /// Set the length.
    #[inline]
    pub fn set_length(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the xid field.
    #[inline]
    pub fn set_xid(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::XID], value)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    // FIXME: should we provide a `payload_checked` to avoid panic, if the length is wrong in the
    // header?

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize..self.length() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    // FIXME: should we provide a `payload_mut_checked` to avoid panic, if the length is wrong in
    // the header?

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.length() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

/// A high-level representation of an OpenFlow packet header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRepr<E> {
    pub version: Version,
    pub length: u16,
    pub kind: Kind,
    pub xid: u32,
    pub payload: PayloadRepr<E>,
}

impl<E: Repr> PacketRepr<E> {
    /// Set the length field automatically based on the payload
    pub fn set_length_auto(&mut self) {
        // FIXME: this might panic. In practice I don't think it will happen but still.
        self.length = self.buffer_len() as u16;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PayloadRepr<E> {
    EchoRequest(Vec<u8>),
    EchoReply(Vec<u8>),
    Error(error::PacketRepr),
    FeaturesRequest,
    FeaturesReply(features_reply::PacketRepr),
    Hello(hello::PacketRepr),
    GetConfigRequest,
    GetConfigReply(get_config_reply::PacketRepr),
    SetConfig(set_config::PacketRepr),
    PacketIn(packet_in::PacketRepr<E>),
}

impl<E: Repr> PayloadRepr<E> {
    fn parse(kind: Kind, buffer: &[u8]) -> Result<Self> {
        use self::PayloadRepr::*;
        Ok(match kind {
            Kind::Error => Error(error::PacketRepr::parse(buffer)?),
            Kind::Hello => Hello(hello::PacketRepr::parse(buffer)?),
            Kind::EchoRequest => EchoRequest(buffer.to_vec()),
            Kind::EchoReply => EchoReply(buffer.to_vec()),
            Kind::FeaturesRequest => FeaturesRequest,
            Kind::FeaturesReply => FeaturesReply(features_reply::PacketRepr::parse(buffer)?),
            Kind::GetConfigRequest => GetConfigRequest,
            Kind::GetConfigReply => GetConfigReply(get_config_reply::PacketRepr::parse(buffer)?),
            Kind::SetConfig => SetConfig(set_config::PacketRepr::parse(buffer)?),
            Kind::PacketIn => PacketIn(packet_in::PacketRepr::parse(buffer)?),
            _ => return Err(self::Error::Unrecognized),
        })
    }
    fn buffer_len(&self) -> usize {
        use self::PayloadRepr::*;
        match *self {
            Error(ref repr) => repr.buffer_len(),
            Hello(ref repr) => repr.buffer_len(),
            EchoRequest(ref vec) | EchoReply(ref vec) => vec.len(),
            FeaturesRequest | GetConfigRequest => 0,
            FeaturesReply(ref repr) => repr.buffer_len(),
            GetConfigReply(ref repr) => repr.buffer_len(),
            SetConfig(ref repr) => repr.buffer_len(),
            PacketIn(ref repr) => repr.buffer_len(),
        }
    }
    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        use self::PayloadRepr::*;
        match *self {
            Error(ref repr) => repr.emit(buffer),
            Hello(ref repr) => repr.emit(buffer),
            EchoRequest(ref vec) | EchoReply(ref vec) => if buffer.len() < vec.len() {
                Err(self::Error::Exhausted)
            } else {
                Ok(buffer.copy_from_slice(vec.as_slice()))
            },
            FeaturesRequest | GetConfigRequest => Ok(()),
            FeaturesReply(ref repr) => repr.emit(buffer),
            GetConfigReply(ref repr) => repr.emit(buffer),
            SetConfig(ref repr) => repr.emit(buffer),
            PacketIn(ref repr) => repr.emit(buffer),
        }
    }
}

impl<E: Repr> Repr for PacketRepr<E> {
    /// Parse an OpenFlow packet and return a high-level representation.
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(PacketRepr {
            version: packet.version(),
            kind: packet.kind(),
            length: packet.length(),
            xid: packet.xid(),
            payload: PayloadRepr::parse(packet.kind(), packet.payload())?,
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    fn buffer_len(&self) -> usize {
        field::XID.end + self.payload.buffer_len()
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 4
    /// packet.
    ///
    /// # Panics
    ///
    /// TODO
    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Packet::new_checked(buffer)?;
        let PacketRepr {
            version,
            kind,
            length,
            xid,
            ref payload,
        } = *self;
        packet.set_version(version);
        packet.set_kind(kind);
        packet.set_length(length);
        packet.set_xid(xid);
        payload.emit(packet.payload_mut())?;
        Ok(())
    }
}
