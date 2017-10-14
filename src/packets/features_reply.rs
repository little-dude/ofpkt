use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};
/// Flow statistics capability
const CAP_FLOW_STATS: u32 = 1;
/// Table statistics capbility.
const CAP_TABLE_STATS: u32 = 1 << 1;
/// Port statistics capability.
const CAP_PORT_STATS: u32 = 1 << 2;
/// Group statistics capability.
const CAP_GROUP_STATS: u32 = 1 << 3;
/// Can reassemble IP fragments.
const CAP_IP_REASSEMBLY: u32 = 1 << 5;
/// Queue statistics capability.
const CAP_QUEUE_STATS: u32 = 1 << 6;
/// Switch will block looping ports.
const CAP_PORT_BLOCKED: u32 = 1 << 8;
/// Switch supports bundles.
const CAP_BUNDLES: u32 = 1 << 9;
/// Switch supports flow monitoring.
const CAP_FLOW_MONITORING: u32 = 1 << 10;

/// Capabilities supported by the datapath
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Capabilities(u32);

impl Capabilities {
    pub fn new(bitmap: u32) -> Self {
        Capabilities(bitmap)
    }

    pub fn flow_stats(&self) -> bool {
        (self.0 & CAP_FLOW_STATS) == CAP_FLOW_STATS
    }

    pub fn set_flow_stats(&mut self) {
        self.0 |= CAP_FLOW_STATS
    }

    pub fn table_stats(&self) -> bool {
        (self.0 & CAP_TABLE_STATS) == CAP_TABLE_STATS
    }

    pub fn set_table_stats(&mut self) {
        self.0 |= CAP_TABLE_STATS
    }

    pub fn port_stats(&self) -> bool {
        (self.0 & CAP_PORT_STATS) == CAP_PORT_STATS
    }

    pub fn set_port_stats(&mut self) {
        self.0 |= CAP_PORT_STATS
    }

    pub fn group_stats(&self) -> bool {
        (self.0 & CAP_GROUP_STATS) == CAP_GROUP_STATS
    }

    pub fn set_group_stats(&mut self) {
        self.0 |= CAP_GROUP_STATS
    }

    pub fn ip_reassembly(&self) -> bool {
        (self.0 & CAP_IP_REASSEMBLY) == CAP_IP_REASSEMBLY
    }

    pub fn set_ip_reassembly(&mut self) {
        self.0 |= CAP_IP_REASSEMBLY
    }

    pub fn queue_stats(&self) -> bool {
        (self.0 & CAP_QUEUE_STATS) == CAP_QUEUE_STATS
    }

    pub fn set_queue_stats(&mut self) {
        self.0 |= CAP_QUEUE_STATS
    }

    pub fn port_blocked(&self) -> bool {
        (self.0 & CAP_PORT_BLOCKED) == CAP_PORT_BLOCKED
    }

    pub fn set_port_blocked(&mut self) {
        self.0 |= CAP_PORT_BLOCKED
    }

    pub fn bundles(&self) -> bool {
        (self.0 & CAP_BUNDLES) == CAP_BUNDLES
    }

    pub fn set_bundles(&mut self) {
        self.0 |= CAP_BUNDLES
    }

    pub fn flow_monitoring(&self) -> bool {
        (self.0 & CAP_FLOW_MONITORING) == CAP_FLOW_MONITORING
    }

    pub fn set_flow_monitoring(&mut self) {
        self.0 |= CAP_FLOW_MONITORING
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use field::*;
    pub const DATAPATH_ID: Field = 0..8;
    pub const N_BUFFERS: Field = 8..12;
    pub const N_TABLES: usize = 12;
    pub const AUX_ID: usize = 13;
    // pub const PADDING: Field = 14..16;
    pub const CAPABILITIES: Field = 16..20;
    pub const RESERVED: Field = 20..24;
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
        if len < field::RESERVED.end {
            Err(Error::Truncated)
        } else if len > field::RESERVED.end {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the datapath_id field.
    pub fn datapath_id(&self) -> u64 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u64(&data[field::DATAPATH_ID])
    }

    /// Return the `n_buffers` field
    pub fn n_buffers(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::N_BUFFERS])
    }

    /// Return the `n_tables` field.
    pub fn n_tables(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::N_TABLES]
    }

    /// Return the `auxiliary_id` field.
    pub fn auxiliary_id(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::AUX_ID]
    }

    /// Return the `capabilities` field.
    pub fn capabilities(&self) -> Capabilities {
        let data = self.buffer.as_ref();
        Capabilities(NetworkEndian::read_u32(&data[field::CAPABILITIES]))
    }

    /// Return the `reserved` field
    pub fn reserved(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::RESERVED])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the datapath_id field.
    pub fn set_datapath_id(&mut self, value: u64) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u64(&mut data[field::DATAPATH_ID], value)
    }

    /// Set the `n_buffers` field
    pub fn set_n_buffers(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::N_BUFFERS], value)
    }

    /// Set the `n_tables` field.
    pub fn set_n_tables(&mut self, value: u8) {
        self.buffer.as_mut()[field::N_TABLES] = value;
    }

    /// Set the `auxiliary_id` field.
    pub fn set_auxiliary_id(&mut self, value: u8) {
        self.buffer.as_mut()[field::AUX_ID] = value;
    }

    /// Set the `capabilities` field.
    pub fn set_capabilities(&mut self, value: Capabilities) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::CAPABILITIES], value.0)
    }

    /// Set the `reserved` field
    pub fn set_reserved(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RESERVED], value)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PacketRepr {
    /// Datapath unique ID. The lower 48-bits are for a MAC address, while the upper 16-bits are implementer-defined.
    pub datapath_id: u64,
    /// Max packets buffered at once.
    pub n_buffers: u32,
    /// Number of tables supported by datapath.
    pub n_tables: u8,
    /// Identify auxiliary connections.
    pub auxiliary_id: u8,
    /// Bitmap of support "ofp_capabilities".
    pub capabilities: Capabilities,
    /// Reserved bytes
    pub reserved: u32,
}


impl Repr for PacketRepr {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let packet = Packet::new_checked(buffer)?;
        Ok(PacketRepr {
            datapath_id: packet.datapath_id(),
            n_buffers: packet.n_buffers(),
            n_tables: packet.n_tables(),
            auxiliary_id: packet.auxiliary_id(),
            capabilities: packet.capabilities(),
            reserved: packet.reserved(),
        })
    }

    fn buffer_len(&self) -> usize {
        field::RESERVED.end
    }

    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        let mut packet = Packet::new_checked(buffer)?;
        packet.set_datapath_id(self.datapath_id);
        packet.set_n_buffers(self.n_buffers);
        packet.set_n_tables(self.n_tables);
        packet.set_auxiliary_id(self.auxiliary_id);
        packet.set_capabilities(self.capabilities);
        packet.set_reserved(self.reserved);
        Ok(())
    }
}
