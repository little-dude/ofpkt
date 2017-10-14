use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};
use super::Oxm;

mod field {
    #![allow(non_snake_case)]

    use field::*;

    pub const MATCH_TYPE: Field = 0..2;
    pub const LENGTH: Field = 2..4;

    pub fn OXM_FIELDS(length: usize) -> Field {
        LENGTH.end..length
    }

    pub fn PADDING(length: usize) -> Field {
        length..(((length + 7) / 8) * 8)
    }
}

enum_with_unknown! {
    /// OpenFlow version
    pub doc enum MatchType(u16) {
        /// Deprecated
        STANDARD = 0,
        /// OpenFlow eXtensible Match
        OXM = 1
    }
}


/// A wrapper to read and write a buffer representing an flow match packet.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Packet<T> {
    inner: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Return a new flow match packet parser/encoder for the given buffer
    fn new(buf: T) -> Self {
        Packet { inner: buf }
    }

    /// Return a new flow match packet parse/encoder for the given buffer, and make sure not getter or
    /// setter will panic.
    fn new_checked(buf: T) -> Result<Self> {
        let packet = Packet { inner: buf };
        packet.check_len()?;
        Ok(packet)
    }

    fn check_len(&self) -> Result<()> {
        if self.inner.as_ref().len() < field::LENGTH.end {
            return Err(Error::Exhausted);
        }
        if self.inner.as_ref().len() < field::PADDING(self.length() as usize).end {
            return Err(Error::Exhausted);
        }
        Ok(())
    }

    /// Return the `match_type` field
    fn match_type(&self) -> MatchType {
        NetworkEndian::read_u16(&self.inner.as_ref()[field::MATCH_TYPE]).into()
    }

    /// Return the `length` field
    fn length(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[field::LENGTH])
    }

    /// Parse and return the OXM fields
    fn oxm_fields<E: Repr>(&self) -> Result<Vec<Oxm<E>>> {
        let length = self.length() as usize;
        let bytes = &self.inner.as_ref()[field::OXM_FIELDS(length)];
        let mut oxm_fields = Vec::new();
        let mut offset = 0;
        loop {
            match Oxm::parse(&bytes[offset..]) {
                Ok(repr) => {
                    offset += repr.buffer_len();
                    oxm_fields.push(repr);
                }
                Err(Error::Truncated) => return Ok(oxm_fields),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Setter for the `match_type` field
    fn set_match_type(&mut self, value: MatchType) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[field::MATCH_TYPE], value.into());
    }

    /// Setter for the `length` field.
    fn set_length(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[field::LENGTH], value);
    }

    /// Set the `oxm_fields` field. Note that the length field must be set already, otherwise, this
    /// will panic.
    fn set_oxm_fields<E: Repr>(&mut self, value: &[Oxm<E>]) -> Result<()> {
        let oxm_fields_len = self.length() as usize;
        let buf = &mut self.inner.as_mut()[field::OXM_FIELDS(oxm_fields_len)];
        let mut offset = 0;
        for field in value {
            field.emit(&mut buf[offset..offset + field.buffer_len()])?;
            offset += field.buffer_len();
        }
        Ok(())
    }

    /// Add necessary padding to enusre 8 bytes alignment. Note that the length field must be set
    /// already when setting the padding.
    fn set_padding(&mut self) {
        let len = self.length() as usize;
        let buf = &mut self.inner.as_mut()[field::PADDING(len)];
        for byte in buf {
            *byte = 0;
        }
    }
}

/// Represent a "flow match packet" that is used in messages such as "packet in".
///
/// ```no_rust
/// +---------------+---------------+
/// |   match type  |     length    |
/// +---------------+---------------+
/// |          oxm fields           |
/// |   (variable       +-----------+
/// |     length)       |  padding  |
/// +-------------------+-----------+
/// ```
///
/// - The `match type` field can only take one valid value `0x0002`
/// - The `length` is the length of the oxm fields only
/// - The `padding` field is for 8 bytes alignment
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRepr<E>(pub Vec<Oxm<E>>);

impl<E: Repr> PacketRepr<E> {
    fn fields_len(&self) -> usize {
        self.0.iter().fold(0, |acc, field| acc + field.buffer_len())
    }
}

impl<E: Repr> Repr for PacketRepr<E> {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        match packet.match_type() {
            MatchType::OXM => Ok(PacketRepr(packet.oxm_fields()?)),
            _ => Err(Error::BadMatchType),
        }
    }

    fn buffer_len(&self) -> usize {
        field::PADDING(self.fields_len()).end
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Packet::new(buffer);
        packet.set_match_type(MatchType::OXM);
        packet.set_length(4 + self.fields_len() as u16);
        packet.set_oxm_fields(&self.0)?;
        packet.set_padding();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use oxm::{FlowMatchField, InPort, Oxm, TunnelId, VlanId};

    // a dummy Oxm Experimenter type.
    // needed because openflow::PacketRepr is generic of it.
    #[derive(Debug, PartialEq, Eq, Clone)]
    struct OxmExperimenter;

    impl Repr for OxmExperimenter {
        fn parse(_buffer: &[u8]) -> Result<Self> {
            unreachable!()
        }
        fn buffer_len(&self) -> usize {
            unreachable!()
        }
        fn emit(&self, _buffer: &mut [u8]) -> Result<()> {
            unreachable!()
        }
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    static BYTES: [u8; 32] = [
        // header
        0x00, 0x01,             // match type (1 = oxm)
        0x00, 0x1e,             // length = 30

        // first oxm tlv (len = 8)
        0x80, 0x00,             // class = 0x8000 = openflow basic
        0x00,                   // field (0=in_port), no mask
        0x04,                   // value length = 4
        0x00, 0x00, 0xab, 0xcd, // value = 43981

        // second oxm tlv (len = 12)
        0x80, 0x00,             // class = 0x8000 = openflow basic
        38 << 1,                // field = 38 = tunnel id no mask
        0x08,                   // value length = 8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x50, // value = 500000

        // third oxm tlv (len = 6)
        0x80, 0x00,             // class = 0x8000 = openflow basic
        6 << 1,                 // field = 6 = vlan id, no mask
        0x02,                   // length = 2
        0x07, 0x77,             // value length = 0x0777

        // padding (flow match packets have padding for 8 bytes alignment)
        0x00, 0x00
    ];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&BYTES[..]);
        assert_eq!(packet.match_type(), MatchType::OXM);
        assert_eq!(packet.length(), 30);

        assert_eq!(field::OXM_FIELDS(30), 4..30);
        assert_eq!(field::PADDING(30), 30..32);
    }

    #[test]
    fn test_padding_field() {
        assert_eq!(field::PADDING(4), 4..8);
        assert_eq!(field::PADDING(4), 4..8);
        assert_eq!(field::PADDING(8), 8..8);
        assert_eq!(field::PADDING(15), 15..16);
        assert_eq!(field::PADDING(24), 24..24);
        assert_eq!(field::PADDING(25), 25..32);
    }

    #[test]
    fn test_parse() {
        let parsed = PacketRepr::<OxmExperimenter>::parse(&BYTES).unwrap();
        let expected = PacketRepr::<OxmExperimenter>(vec![
            Oxm::FlowMatchField(FlowMatchField::InPort(InPort::new(0xabcd))),
            Oxm::FlowMatchField(FlowMatchField::TunnelId(TunnelId::new(50_000, None))),
            Oxm::FlowMatchField(FlowMatchField::VlanId(VlanId::new(0x0777, None))),
        ]);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_emit() {
        let repr = PacketRepr::<OxmExperimenter>(vec![
            Oxm::FlowMatchField(FlowMatchField::InPort(InPort::new(0xabcd))),
            Oxm::FlowMatchField(FlowMatchField::TunnelId(TunnelId::new(50_000, None))),
            Oxm::FlowMatchField(FlowMatchField::VlanId(VlanId::new(0x0777, None))),
        ]);
        assert_eq!(repr.buffer_len(), 32);

        let mut bytes = [0xff; 32];
        repr.emit(&mut bytes).unwrap();
        assert_eq!(&bytes[..], &BYTES[..]);
    }
}
