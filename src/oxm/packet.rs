use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};

mod field {
    use field::*;
    pub const CLASS: Field = 0..2;
    pub const FIELD: usize = 2;
    pub const MASK: usize = 2;
    pub const LENGTH: usize = 3;
    pub const VALUE: Rest = 4..;
}

/// A wrapper to read and write a buffer representing an OXM field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T> {
    inner: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Return a new OXM packet parser/encoder for the given buffer
    pub fn new(buf: T) -> Self {
        Packet { inner: buf }
    }

    /// Return the inner buffer
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Return a new OXM field parser/encoder for the given buffer, and make sure not getter or
    /// setter will panic.
    pub fn new_checked(buf: T) -> Result<Self> {
        let packet = Packet { inner: buf };
        packet.check_len()?;
        Ok(packet)
    }

    /// Return the `oxm_class` field
    pub fn class(&self) -> u16 {
        NetworkEndian::read_u16(&self.inner.as_ref()[field::CLASS])
    }

    /// Return the `oxm_field` field
    pub fn field(&self) -> u8 {
        (self.inner.as_ref()[field::FIELD] & 0xfe) >> 1
    }

    /// Return `true` is the payload has a mask, `false` otherwise
    pub fn has_mask(&self) -> bool {
        self.inner.as_ref()[field::MASK] & 0x01 == 1
    }

    /// Return the `oxm_length` field
    pub fn length(&self) -> u8 {
        self.inner.as_ref()[field::LENGTH]
    }

    /// Check wheter any getter or setter may panic (for example if the underlying buffer is to
    /// small.
    pub fn check_len(&self) -> Result<()> {
        let len = self.inner.as_ref().len();
        if len < field::LENGTH || len < self.length() as usize + field::LENGTH {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return the OXM value. If the packet has the `HM` field is set, half the buffer corresponds
    /// to the actual value, and half corresponds to a mask. Otherwise, the whole slice correspond
    /// to the value
    pub fn value(&self) -> &'a [u8] {
        &self.inner.as_ref()[field::VALUE]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Setter for the `oxm_class` field
    pub fn set_class(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.inner.as_mut()[field::CLASS], value);
    }

    /// Setter for the `oxm_field` field. Note that the least significant bit of the `value`
    /// argument is ignored since this field is 7 bits long.
    pub fn set_field(&mut self, value: u8) {
        self.inner.as_mut()[field::FIELD] = value << 1 | (self.inner.as_ref()[field::FIELD] & 1);
    }

    /// Set the `HM` field
    pub fn set_mask(&mut self) {
        self.inner.as_mut()[field::MASK] |= 1;
    }

    /// Unset the `HM` field.
    pub fn unset_mask(&mut self) {
        self.inner.as_mut()[field::MASK] &= 0xfe;
    }

    /// Setter for the `oxm_length` field
    pub fn set_length(&mut self, value: u8) {
        self.inner.as_mut()[field::LENGTH] = value;
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Get a mutable pointer to the OXM value.
    pub fn value_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[field::VALUE]
    }
}
