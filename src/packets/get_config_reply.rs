use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};


/// Indicate whether IP fragments should be treated normally, dropped, or reassem-bled.  “Normal”
/// handling of fragments means that an attempt should be made to pass the fragments through the
/// OpenFlow tables. If any field is not present (e.g., the TCP/UDP ports didn’t fit), then the
/// packet should not match any entry that has that field set.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
// FIXME: The specs says this field is a bitmap but that seems weird since:
//      - the different values seem to exclude each other
//      - values are 0, 1, 2, 3 instead of 1, 2, 4, 8
pub enum Flags {
    /// Match packets, regardless of state
    FragmentNormal,
    /// Drop fragmented packets
    FragmentDrop,
    /// Reassemble fragmented packets
    FragmentReassemble,
    /// Mask for fragmentation
    FragmentMask,
    /// An invalid flags
    Invalid(u16),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use field::*;
    pub const FLAGS: Field = 0..2;
    pub const MISS_SEND_LEN: Field = 2..4;
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::MISS_SEND_LEN.end {
            Err(Error::Truncated)
        // } else if len > field::MISS_SEND_LEN.end {
        //     Err(Error::Malformed)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `flags` field.
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        match NetworkEndian::read_u16(&data[field::FLAGS]) {
            0 => Flags::FragmentNormal,
            1 => Flags::FragmentDrop,
            2 => Flags::FragmentReassemble,
            3 => Flags::FragmentMask,
            f => Flags::Invalid(f),
        }
    }

    /// Return the `miss_send_len` field.
    pub fn miss_send_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::MISS_SEND_LEN])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the `flags` field.
    pub fn set_flags(&mut self, value: Flags) {
        let value = match value {
            Flags::FragmentNormal => 0,
            Flags::FragmentDrop => 1,
            Flags::FragmentReassemble => 2,
            Flags::FragmentMask => 3,
            Flags::Invalid(f) => f,
        };
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::FLAGS], value)
    }

    /// Set the `miss_send_len` field.
    pub fn set_miss_send_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::MISS_SEND_LEN], value)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PacketRepr {
    /// Flags
    pub flags: Flags,
    /// The amount of bytes of a packet to capture for sending with a PacketIn message
    pub miss_send_len: u16,
}

impl Repr for PacketRepr {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(PacketRepr {
            flags: packet.flags(),
            miss_send_len: packet.miss_send_len(),
        })
    }

    fn buffer_len(&self) -> usize {
        field::MISS_SEND_LEN.end
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Packet::new_checked(buffer)?;
        packet.set_flags(self.flags);
        packet.set_miss_send_len(self.miss_send_len);
        Ok(())
    }
}
