//! # Packet in
//!
//! ```no_rust
//!  0      7        15       23       31
//! +--------+--------+--------+--------+
//! |           buffer id               |
//! +--------+--------+--------+--------+
//! |  frame length   | reason |table_id|
//! +--------+--------+--------+--------+
//! |               cookie              |
//! |                                   |
//! +--------+--------+--------+--------+
//! |       Flow match fields           |
//! | (variable length, 8 bytes aligned)|
//! |                                   |
//! +--------+--------+--------+--------+
//! |     padding     |      frame      |
//! +--------+--------+                 +
//! |       (variable length)           |
//! +--------+--------+--------+--------+
//! ```
use oxm::FlowMatch;
use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};

enum_with_unknown! {
    pub doc enum Reason(u8) {
        /// No matching flow (table-miss flow entry).
        TableMiss = 0,
        /// Output to controller in apply-actions.
        ApplyAction = 1,
        /// Packet has invalid TTL
        InvalidTtl = 2,
        /// Output to controller in action set.
        ActionSet = 3,
        /// Output to controller in group bucket.
        Group = 4,
        /// Output to controller in packet-out.
        PacketOut = 5
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    #![allow(non_snake_case)]
    use field::*;
    pub const BUFFER_ID: Field = 0..4;
    pub const FRAME_LENGTH: Field = 4..6;
    pub const REASON: usize = 6;
    pub const TABLE_ID: usize = 7;
    pub const COOKIE: Field = 8..16;

    // We have no way to know how long the flow_match field is, so we can't know where the padding
    // and the frame are. We have to parse the flow_match field first, and then parse the rest of
    // the message.
    pub const FLOW_MATCH_AND_AFTER: Rest = 16..;

    pub fn FLOW_MATCH(flow_match_len: usize) -> Field {
        (COOKIE.end + flow_match_len)..(COOKIE.end + flow_match_len)
    }

    pub fn PADDING(flow_match_len: usize) -> Field {
        FLOW_MATCH(flow_match_len).end..(FLOW_MATCH(flow_match_len).end + 2)
    }

    pub fn FRAME(flow_match_len: usize) -> Rest {
        PADDING(flow_match_len).end..
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    pub fn check_len(&self, flow_match_len: usize) -> Result<()> {
        if self.buffer.as_ref().len() < field::FRAME(flow_match_len).start {
            return Err(Error::Exhausted);
        }
        Ok(())
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the `buffer_id` field.
    pub fn buffer_id(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::BUFFER_ID])
    }

    /// Return the `frame_length` field.
    pub fn frame_length(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FRAME_LENGTH])
    }

    /// Return the `reason` field.
    pub fn reason(&self) -> Reason {
        let data = self.buffer.as_ref();
        Reason::from(data[field::REASON])
    }

    /// Return the `table_id` field.
    pub fn table_id(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TABLE_ID]
    }

    /// Return the `cookie` field.
    pub fn cookie(&self) -> u64 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u64(&data[field::COOKIE])
    }

    /// Return the whole buffer after the `cookie` field. That includes the `flow_match` field, the
    /// `padding` field, and the `frame` field.
    pub fn flow_match_and_after(&self) -> &[u8] {
        &self.buffer.as_ref()[field::FLOW_MATCH_AND_AFTER]
    }

    /// Return the flow match field
    pub fn flow_match(&self, flow_match_len: usize) -> &[u8] {
        &self.buffer.as_ref()[field::FLOW_MATCH(flow_match_len)]
    }

    /// Return the `padding` field.
    pub fn padding(&self, flow_match_len: usize) -> &[u8] {
        &self.buffer.as_ref()[field::PADDING(flow_match_len)]
    }

    /// Return the `frame` field.
    pub fn frame(&self, flow_match_len: usize) -> &[u8] {
        &self.buffer.as_ref()[field::FRAME(flow_match_len)]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the `buffer_id` field.
    pub fn set_buffer_id(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::BUFFER_ID], value)
    }

    /// Set the `frame_length` field.
    pub fn set_frame_length(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::FRAME_LENGTH], value)
    }

    /// Set the `reason` field.
    pub fn set_reason(&mut self, value: Reason) {
        self.buffer.as_mut()[field::REASON] = value.into();
    }

    /// Set the `table_id` field.
    pub fn set_table_id(&mut self, value: u8) {
        self.buffer.as_mut()[field::TABLE_ID] = value;
    }

    pub fn set_cookie(&mut self, value: u64) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u64(&mut data[field::COOKIE], value)
    }

    pub fn set_flow_match(&mut self, value: &[u8]) {
        self.buffer.as_mut()[field::FLOW_MATCH(value.len())].copy_from_slice(value)
    }

    pub fn set_padding(&mut self, flow_match_len: usize) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::PADDING(flow_match_len)], 0)
    }

    /// Set the `frame` field.
    pub fn set_frame(&mut self, flow_match_len: usize, value: &[u8]) {
        self.buffer.as_mut()[field::FRAME(flow_match_len)].copy_from_slice(value);
    }
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRepr<E> {
    /// The `buffer_id` is an opaque value used by the datapath to identify a buffered packet. If
    /// the packet associated with the packet-in message is buffered, the `buffer_id` must be an
    /// identifier unique on the current connection referring to that packet on the switch. If the
    /// packet is not buffered - either because of no available buffers, or because of being
    /// explicitly requested via OFPCML_NO_BUFFER - the buffer_id must be OFP_NO_BUFFER.
    pub buffer_id: u32,
    /// The `frame_length` is the full length of the packet that triggered the packet-in message.
    /// The actual length of the `frame` field in the message may be less than `frame_length` in
    /// case the packet had been truncated due to buffering.  The field `frame_length` must always
    /// correspond to the packet prior to buffering and truncation.
    pub frame_length: u16,
    /// The reason field indicates which context triggered the packet-in message.
    pub reason: Reason,
    pub table_id: u8,
    /// The `cookie` field contains the cookie of the flow entry that caused the packet to be
    /// sent to the controller. This field must be set to (`0xffff_ffff_ffff_ffff`) if a
    /// cookie cannot be associated with a particular flow. For example, if the packet-in
    /// was generated in a group bucket or from the action set.
    pub cookie: u64,
    /// The `flow_match` field is a set of OXM TLVs containing the pipeline fields associated
    /// with a packet. The pipeline fields values cannot be determined from the packet data, and
    /// include for example the input port and the metadata value. The OXM TLVs must include the
    /// Packet Type Match Field to identify the packet type included in the data field, unless the
    /// packet is Ethernet. The set of OXM TLVs must include all pipeline fields associated with
    /// that packet, supported by the switch and which value is not all-bits-zero. The field
    /// OXM_OF_ACTSET_OUTPUT should be ommited from this set. If OXM_OF_IN_PHY_PORT has the same
    /// value as OXM_OF_IN_PORT, it should be omitted from this set. The set of OXM TLVs may
    /// optionally include pipeline fields whose value is all-bits-zero. The set of OXM TLVs may
    /// also optionally include packet header fields. Most switches should not include those
    /// optional fields, to minimise the size of the packet-in, and therefore the controller should
    /// not depend on their presence and should extract header fields from the data field. The set
    /// of OXM TLVs must reflect the packet’s headers and context when the event that triggers the
    /// packet-in message occurred, they should include all modifications made in the course of
    /// previous processing.  The port referenced by the OXM_OF_IN_PORT TLV is the packet ingress
    /// port used for matching flow entries and must be a valid standard OpenFlow port (see
    /// 7.2.3.9). The port referenced by the OXM_OF_IN_PHY_PORT TLV is the underlying physical port
    ///   (see 7.2.3.9).
    pub flow_match: FlowMatch<E>,
    /// The frame that triggered this packet in message.
    pub frame: Vec<u8>,
}

impl<E: Repr> Repr for PacketRepr<E> {
    fn parse(buffer: &[u8]) -> Result<Self> {
        // the buffer must be at least big enough for a message with an empty `flow_match` field
        // and an empty `frame` field.
        if buffer.len() < field::PADDING(0).end {
            return Err(Error::Exhausted);
        }
        let packet = Packet::new(buffer);
        let flow_match = FlowMatch::parse(packet.flow_match_and_after())?;
        let flow_match_len = flow_match.buffer_len();
        packet.check_len(flow_match_len)?;
        Ok(PacketRepr {
            buffer_id: packet.buffer_id(),
            frame_length: packet.frame_length(),
            table_id: packet.table_id(),
            cookie: packet.cookie(),
            reason: packet.reason(),
            flow_match: flow_match,
            frame: packet.frame(flow_match_len).to_vec(),
        })
    }

    fn buffer_len(&self) -> usize {
        field::COOKIE.end + self.flow_match.buffer_len() + 2 + self.frame.len()
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }
        let mut packet = Packet::new(buffer);
        packet.set_buffer_id(self.buffer_id);
        packet.set_frame_length(self.frame_length);
        packet.set_reason(self.reason);
        packet.set_table_id(self.table_id);
        let flow_match_len = self.flow_match.buffer_len();
        packet.set_padding(flow_match_len);
        packet.set_frame(flow_match_len, &self.frame);
        Ok(())
    }
}
