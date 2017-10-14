//! Types representing Hello elements
use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};
use hello::bitmap::{Bitmap, BitmapRepr};

enum_with_unknown! {
    /// Represent the type of payload of the Hello message element.
    pub doc enum Kind(u16) {
        /// Represent a bitmap payload. A bitmap represents a set of OpenFlow versions that are
        /// supported by the endpoint. Version numbers index the bitmap. For example an endpoint
        /// that supports OpenFlow 1.0 (`0x01`) and OpenFlow 1.3 (`0x04`) would set the bits at
        /// indices 1 and 4 to 1 so the bitmap would be `00000000 00000000 00000000 00010010`
        /// (_i.e_ `0x12`)
        ///
        /// For versions 1 to 31, only one bitmap is needed. Above, multiple bitmaps are needed.
        Bitmap = 1
    }
}

/// A buffer representing a Hello element. It provides convenient getters and setters for each fields of the element.
///
/// ```no_rust
/// +--------+--------+--------+--------+
/// |     type        |      length     |
/// +--------+--------+--------+--------+
/// |              payload              |
/// +--------+--------+--------+--------+
/// ```
///
/// - type tells the type of payload. See [Kind] for the different types.
/// - length is the total length of the element, including the header.
///
/// [Kind]: enum.Kind.html
///
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Element<T: AsRef<[u8]>> {
    pub inner: T,
}

mod field {
    use field::*;

    pub const KIND: Field = 0..2;
    pub const LENGTH: Field = 2..4;
    pub const PAYLOAD: Rest = 4..;
}

impl<T: AsRef<[u8]>> Element<T> {
    /// Imbue a raw octet buffer with OpenFlow Hello message structure.
    pub fn new(buffer: T) -> Self {
        Element { inner: buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let buf = Self::new(buffer);
        buf.check_len()?;
        Ok(buf)
    }

    /// Return the length field.
    #[inline]
    pub fn length(&self) -> u16 {
        let data = self.inner.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the type field.
    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.inner.as_ref();
        NetworkEndian::read_u16(&data[field::KIND]).into()
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_header_len]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let buffer_len = self.inner.as_ref().len();
        if buffer_len < field::LENGTH.end || buffer_len < self.length() as usize {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Element<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let data = self.inner.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Element<T> {
    /// Set the type field
    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        let data = self.inner.as_mut();
        NetworkEndian::write_u16(&mut data[field::KIND], value.into())
    }

    /// Set the length field.
    #[inline]
    pub fn set_length(&mut self, value: u16) {
        let data = self.inner.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Element<&'a mut T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.inner.as_mut();
        &mut data[field::PAYLOAD]
    }
}

/// Represent the payload of a Hello element.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ElementData {
    /// Represent a bitmap payload
    Bitmap(BitmapRepr),
    /// Represent an unknown payload
    Unknown(Vec<u8>),
}

impl ElementData {
    pub fn emit<T>(&self, buffer: &mut T)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        match *self {
            ElementData::Bitmap(ref bitmap) => bitmap.emit(&mut Bitmap::new(buffer)),
            ElementData::Unknown(ref slice) => buffer.as_mut().copy_from_slice(slice.as_slice()),
        }
    }

    pub fn length(&self) -> usize {
        match *self {
            ElementData::Bitmap(_) => 4,
            ElementData::Unknown(ref bytes) => bytes.len(),
        }
    }
}

/// Represent a Hello element. Several Hello elements form a Hello message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ElementRepr {
    pub kind: Kind,
    pub payload: ElementData,
}

impl Repr for ElementRepr {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Element::new_checked(buffer)?;
        let kind = packet.kind();
        let payload = match kind {
            Kind::Bitmap => {
                let bitmap_buf = Bitmap::new(packet.payload());
                let bitmap_repr = BitmapRepr::parse(&bitmap_buf)?;
                ElementData::Bitmap(bitmap_repr)
            }
            _ => ElementData::Unknown(packet.payload().to_vec()),
        };
        Ok(ElementRepr {
            kind: kind,
            payload: payload,
        })
    }

    fn buffer_len(&self) -> usize {
        self.payload.length() + 4
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Element::new_checked(buffer)?;
        packet.set_kind(self.kind);
        // FIXME: In theory this could panic. Not sure in practice if there is a risk.
        packet.set_length(self.buffer_len() as u16);
        Ok(self.payload.emit(packet.payload_mut()))
    }
}

#[cfg(test)]
mod test {
    use openflow::Version;
    use hello::bitmap::{Bitmap, BitmapRepr};
    use super::{Element, ElementData, ElementRepr, Kind, Repr};

    #[cfg_attr(rustfmt, rustfmt_skip)]
    static BYTES: [u8; 8] = [
        0x00, 0x01,             // type
        0x00, 0x08,             // length
        0x00, 0x00, 0x00, 0x12, // bitmap
    ];

    #[test]
    fn test_deconstruct() {
        let buf = Element::new(&BYTES[..]);
        assert_eq!(buf.kind(), Kind::Bitmap);
        assert_eq!(buf.length(), 8);

        let bitmap_buf = Bitmap::new(buf.payload());
        assert_eq!(bitmap_buf.bitmap(), 0x12);

        let mut versions = bitmap_buf.iter_versions();
        assert_eq!(versions.next(), Some(Version::OpenFlow1Dot0));
        assert_eq!(versions.next(), Some(Version::OpenFlow1Dot3));
        assert_eq!(versions.next(), None);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0; 8];
        let mut buf = Element::new(&mut bytes);
        buf.set_kind(Kind::Bitmap);
        buf.set_length(8);
        {
            let mut payload_buf = Bitmap::new(buf.payload_mut());
            payload_buf.set_bitmap_from_versions(&[Version::OpenFlow1Dot0, Version::OpenFlow1Dot3]);
        }
        assert_eq!(&buf.into_inner()[..], &BYTES[..]);
    }


    fn element_repr() -> ElementRepr {
        ElementRepr {
            kind: Kind::Bitmap,
            payload: ElementData::Bitmap(BitmapRepr(0x12)),
        }
    }

    #[test]
    fn test_parse() {
        let repr = ElementRepr::parse(&BYTES).unwrap();
        assert_eq!(repr, element_repr());
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0; 8];
        element_repr().emit(&mut bytes).unwrap();
        assert_eq!(&bytes[..], &BYTES[..]);
    }
}
