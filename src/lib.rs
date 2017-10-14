extern crate byteorder;
extern crate core;
extern crate smoltcp;

use core::fmt;
use std::error::Error as StdError;

mod field {
    use core::ops;
    pub type Field = ops::Range<usize>;
    pub type Rest = ops::RangeFrom<usize>;
}

// TODO: Custom error for complex message types like OXM

/// The error type for the networking stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming packet was recognized but was self-contradictory.
    /// E.g. a TCP packet with both SYN and FIN flags set.
    Malformed,
    /// An OXM field could not be parsed because the "class" field in the header is invalid
    BadOxmClass,
    /// An OXM field could not be parsed because the "class" field in the header is not supported.
    /// This library does not support the legacy Nicisra eXtensible Match typically.
    UnsupportedOxmClass,
    /// An OXM field could not be parsed because the "field" field in the header is invalid
    BadOxmField,
    /// The the match type field in a flow match header is invalid
    BadMatchType,
    #[doc(hidden)] __Nonexhaustive,
}

/// The result type for the networking stack.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Exhausted => "buffer space exhausted",
            Error::Truncated => "truncated packet",
            Error::Unrecognized => "unrecognized packet",
            Error::Malformed => "malformed packet",
            Error::BadOxmClass => "unknown oxm class",
            Error::UnsupportedOxmClass => "unsupported oxm class",
            Error::BadOxmField => "unknown oxm field",
            Error::BadMatchType => "unknown match type",
            Error::__Nonexhaustive => unreachable!(),
        }
    }

    fn cause(&self) -> Option<&StdError> {
        None
    }
}

pub trait Repr
where
    Self: Sized,
{
    /// Parse a packet and return a high-level representation.
    fn parse(buffer: &[u8]) -> Result<Self>;

    /// Return the length of a packet that will be emitted from this high-level representation.
    fn buffer_len(&self) -> usize;

    /// Emit a high-level representation into a buffer
    fn emit(&self, buffer: &mut [u8]) -> Result<()>;
}

#[macro_use]
mod macros;
mod port;
pub mod oxm;
mod packets;

pub use packets::openflow::{Packet, PacketRepr, PayloadRepr};
pub use packets::*;
