//! Types to parse and emit Hello messages

mod bitmap;
mod element;

use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};
pub use self::bitmap::{Bitmap, BitmapRepr};
pub use self::element::{Element, ElementData, ElementRepr, Kind};


/// An octet buffer representing a Hello message. A Hello message is made of multiple Hello
/// elements.
///
/// ```no_rust
/// +--------+--------+--------+--------+
/// |     type        |      length     |
/// +--------+--------+--------+--------+
/// |              payload              |
/// +--------+--------+--------+--------+
/// |     type        |      length     |
/// +--------+--------+--------+--------+
/// |              payload              |
/// +--------+--------+--------+--------+
/// |                etc.               |
/// |                                   |
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    inner: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with OpenFlow Hello message structure.
    pub fn new(buffer: T) -> Self {
        Packet { inner: buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.inner
    }

    // FIXME: the iterator should probably return Result<Element> so that we now if it's truncated.
    pub fn iter_elements(&self) -> ElementsIterator<&T> {
        ElementsIterator {
            offset: 0,
            inner: &self.inner,
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IntoIterator for Packet<&'a T> {
    type Item = Element<&'a [u8]>;
    type IntoIter = ElementsIterator<&'a T>;

    fn into_iter(self) -> Self::IntoIter {
        ElementsIterator {
            offset: 0,
            inner: self.into_inner(),
        }
    }
}

// FIXME: I initially wanted to define it as
//
// ```rust
//      pub struct PacketRepr<'a, 'b: 'a> { elements: ManagedSlice<'a, ElementRepr<'b>> }
//  ```
//
// unfortunately lifetimes complicate a lot the implementation of the codec, because the trait
// looks like
//
//      pub trait Decoder {
//          type Item;
//          type Error: From<Error>;
//          fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error>;
//      }
//
// Having lifetimes in the packet representation means the `Item` will have lifetimes. Something
// like:
//
//      struct Message<'a, 'b: 'a> {
//          header: openflow::PacketRepr,
//          payload: Payload<'a, 'b>,
//      }
//      enum Payload<'a, 'b: 'a> {
//          Hello(hello::PacketRepr<'a, 'b>),
//          // ...
//      }
//      struct Codec;
//      impl<'a, 'b> Decoder for Codec {
//          type Item = Message<'a, 'b>;
//          type Error = io::Error;
//          fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>> { ...  }
//      }
//
// Unfortunately, that does not work, because 'a and 'b are unbounded. If I understand correctly,
// this would be possible with higher kinded types.
//
// See:
// https://users.rust-lang.org/t/lifetimes-on-associated-types/2728/3
// https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRepr(Vec<ElementRepr>);

impl PacketRepr {
    pub fn new(elements: Vec<ElementRepr>) -> Self {
        PacketRepr(elements)
    }
}

impl Repr for PacketRepr {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new(buffer);
        let mut elements = Vec::new();
        for element in packet.iter_elements() {
            let parsed = ElementRepr::parse(element.into_inner())?;
            elements.push(parsed);
        }
        Ok(PacketRepr::new(elements))
    }

    fn buffer_len(&self) -> usize {
        self.0
            .iter()
            .fold(0, |acc, element| acc + element.buffer_len()) as usize
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        if self.buffer_len() > buffer.len() {
            return Err(Error::Exhausted);
        }
        let mut offset: usize = 0;
        for element in &self.0 {
            let length = element.buffer_len();
            element.emit(&mut buffer[offset..offset + length])?;
            offset += length;
        }
        Ok(())
    }
}

/// An iterator over the Hello elements of a Hello message
pub struct ElementsIterator<T> {
    offset: usize,
    inner: T,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Iterator for ElementsIterator<&'a T> {
    type Item = Element<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        // make sure we have enough bytes to parse at least a Hello Element header
        let remaining_len = self.inner.as_ref()[self.offset..].len();
        if remaining_len < 4 {
            return None;
        }

        // Read the length field of the Hello Element header. This gives us the total length of the
        // element.
        let length_field = &self.inner.as_ref()[self.offset + 2..self.offset + 4];
        let element_length = NetworkEndian::read_u16(length_field) as usize;
        // Return None if we don't have enough bytes left in the buffer to read the Hello Element.
        // That means the element is truncated, which ideally would trigger an error, but in an
        // iterator, all we can do is return None.
        if remaining_len < element_length {
            return None;
        }

        let bytes = &self.inner.as_ref()[self.offset..self.offset + element_length];
        let element = Element::new(bytes);
        self.offset += element_length;
        Some(element)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use openflow;

    // a dummy Oxm Experimenter type.
    // needed because openflow::PacketRepr is generic of it.
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
    static BYTES: [u8; 24] = [
        // openflow header
        0x05,                   // version
        0x00,                   // type = Hello
        0x00, 0x18,             // length = 24 (openflow f header = 8, bitmap elements = 8 each)
        0xaa, 0xbb, 0xcc, 0xdd, // xid
        // bitmap element
        0x00, 0x01,             // type
        0x00, 0x08,             // length
        0x00, 0x00, 0x00, 0x12, // bitmap
        // bitmap element
        0x00, 0x01,             // type
        0x00, 0x08,             // length
        0x00, 0x00, 0x00, 0x12, // bitmap
    ];

    #[test]
    fn test_deconstruct() {
        let ofpkt = openflow::Packet::new(&BYTES[..]);
        let hello_buf = Packet::new(ofpkt.payload());
        let mut hello_elements = hello_buf.into_iter();

        let element = hello_elements.next().unwrap();
        assert_eq!(element.kind(), Kind::Bitmap);
        assert_eq!(element.length(), 8);

        let element = hello_elements.next().unwrap();
        assert_eq!(element.kind(), Kind::Bitmap);
        assert_eq!(element.length(), 8);

        assert_eq!(hello_elements.next().is_none(), true);
    }

    // FIXME: I don't think we can easily construct the packet with an iterator here because
    // the iterator can't know how big each element will be.
    // #[test]
    #[test]
    fn test_construct() {
        let mut buf = [0; 24];
        let mut packet = openflow::Packet::new(&mut buf);
        packet.set_version(openflow::Version::OpenFlow1Dot4);
        packet.set_kind(openflow::Kind::Hello);
        packet.set_length(24);
        packet.set_xid(0xaabbccdd);
        // We borrow the packet mutably to set its payload, so this borrow needs to end before we
        // call packet.into_inner(), hence this ugly scope.
        {
            let payload = packet.payload_mut();
            for i in 0..2 {
                let mut elem_buf = Element::new(&mut payload[i * 8..i * 8 + 8]);
                elem_buf.set_kind(Kind::Bitmap);
                elem_buf.set_length(8);
                let mut elem_payload = Bitmap::new(elem_buf.payload_mut());
                elem_payload.set_bitmap_from_versions(&[
                    openflow::Version::OpenFlow1Dot0,
                    openflow::Version::OpenFlow1Dot3,
                ]);
            }
        }

        assert_eq!(&packet.into_inner()[..], &BYTES[..]);
    }

    fn hello_element_repr() -> ElementRepr {
        ElementRepr {
            kind: Kind::Bitmap,
            payload: ElementData::Bitmap(BitmapRepr(0x12)),
        }
    }

    #[test]
    fn test_parse() {
        let repr = openflow::PacketRepr::<OxmExperimenter>::parse(&BYTES).unwrap();
        if let openflow::PayloadRepr::Hello(hello) = repr.payload {
            assert_eq!(hello.0.len(), 2);
            assert_eq!(hello.0[0], hello_element_repr());
            assert_eq!(hello.0[1], hello_element_repr());
        } else {
            panic!("not a Hello payload");
        }
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0; 24];
        let repr = openflow::PacketRepr::<OxmExperimenter> {
            version: openflow::Version::OpenFlow1Dot4,
            kind: openflow::Kind::Hello,
            length: 0x18,
            xid: 0xaabbccdd,
            payload: openflow::PayloadRepr::Hello(
                PacketRepr(vec![hello_element_repr(), hello_element_repr()]),
            ),
        };
        repr.emit(&mut bytes).unwrap();
        assert_eq!(&bytes[..], &BYTES[..]);
    }
}
