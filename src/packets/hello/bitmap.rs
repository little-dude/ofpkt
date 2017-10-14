//! Types to parse and emit version bitmaps used in Hello messages.

use {Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use openflow::Version;


/// A buffer representing a bitmap.
#[derive(Debug)]
pub struct Bitmap<T: AsRef<[u8]>> {
    inner: T,
}

impl<T: AsRef<[u8]>> Bitmap<T> {
    /// Imbue a raw octet buffer with a bitmap buffer structure.
    pub fn new(buffer: T) -> Self {
        Bitmap { inner: buffer }
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

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.inner.as_ref().len();
        if len < 4 {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the bitmap, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Return an iterator that iterates over the version contained in this bitmap
    #[inline]
    pub fn iter_versions(&self) -> BitmapIterator {
        let data = self.inner.as_ref();
        BitmapIterator::new(NetworkEndian::read_u32(&data[0..4]))
    }

    /// Return the bitmap
    #[inline]
    pub fn bitmap(&self) -> u32 {
        let data = self.inner.as_ref();
        NetworkEndian::read_u32(&data[0..4])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Bitmap<T> {
    /// Set the bitmap.
    #[inline]
    pub fn set_bitmap(&mut self, value: u32) {
        let data = self.inner.as_mut();
        NetworkEndian::write_u32(&mut data[0..4], value)
    }

    // Compute the bitmap from the given versions and set it.
    pub fn set_bitmap_from_versions(&mut self, versions: &[Version]) {
        let mut bitmap: u32 = 0;
        for version in versions {
            // FIXME: this will panic for version > 31
            bitmap |= (1 as u32) << u8::from(*version) as usize;
        }
        self.set_bitmap(bitmap)
    }
}

/// A high level representation of a bitmap.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct BitmapRepr(pub u32);

impl BitmapRepr {
    /// Parse a bitmap buffer and return a high-level representation.
    pub fn parse<T>(buffer: &Bitmap<T>) -> Result<Self>
    where
        T: AsRef<[u8]>,
    {
        Ok(BitmapRepr(buffer.bitmap()))
    }

    /// Return the length of a buffer that will be emitted from this high-level representation.
    pub fn length(&self) -> usize {
        4
    }

    /// Emit a high-level representation of a bitmap into a buffer.
    pub fn emit<T>(&self, buffer: &mut Bitmap<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        buffer.set_bitmap(self.0)
    }
}


/// An iterator over all the OpenFlow versions contained in a bitmap.
#[derive(Clone, Debug, Copy, Default)]
pub struct BitmapIterator {
    bitmap: u32,
    shift: usize,
}

impl BitmapIterator {
    fn new(bitmap: u32) -> Self {
        BitmapIterator {
            bitmap: bitmap,
            shift: 0,
        }
    }
}

impl Iterator for BitmapIterator {
    type Item = Version;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.shift += 1;
            if self.shift == 32 {
                return None;
            } else {
                let shifted_bitmap = self.bitmap >> self.shift;
                if shifted_bitmap == 0 {
                    return None;
                } else if (shifted_bitmap & 1) == 1 {
                    return Some(Version::from(self.shift as u8));
                }
            }
        }
    }
}
