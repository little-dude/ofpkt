/// OpenFlow port numbers
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PortNumber {
    /// maximum number of physical and logical switch ports
    Max,
    /// Output port not set in action-set.
    Unset,
    /// Send the packet out the input port.
    InPort,
    /// Submit the packet to the first flow table. This destination port can only be used in
    /// packet-out messages.
    Table,
    /// Forward using non OpenFlow pipeline.
    Normal,
    /// Flood using non OpenFlow pipeline.
    Flood,
    /// Flood through all standard ports except input port.
    All,
    /// Send to controller
    Controller,
    /// Local OpenFlow "port"
    Local,
    /// Special value used in some requests when no port is specified (i.e. wildcarded)
    Any,
    /// A regular port number
    Regular(u32),
}

impl ::core::convert::From<u32> for PortNumber {
    fn from(value: u32) -> Self {
        match value {
            0xffff_ff00 => PortNumber::Max,
            0xffff_fff7 => PortNumber::Unset,
            0xffff_fff8 => PortNumber::InPort,
            0xffff_fff9 => PortNumber::Table,
            0xffff_fffa => PortNumber::Normal,
            0xffff_fffb => PortNumber::Flood,
            0xffff_fffc => PortNumber::All,
            0xffff_fffd => PortNumber::Controller,
            0xffff_fffe => PortNumber::Local,
            0xffff_ffff => PortNumber::Any,
            other => PortNumber::Regular(other),
        }
    }
}

impl ::core::convert::From<PortNumber> for u32 {
    fn from(value: PortNumber) -> Self {
        match value {
            PortNumber::Max => 0xffff_ff00,
            PortNumber::Unset => 0xffff_fff7,
            PortNumber::InPort => 0xffff_fff8,
            PortNumber::Table => 0xffff_fff9,
            PortNumber::Normal => 0xffff_fffa,
            PortNumber::Flood => 0xffff_fffb,
            PortNumber::All => 0xffff_fffc,
            PortNumber::Controller => 0xffff_fffd,
            PortNumber::Local => 0xffff_fffe,
            PortNumber::Any => 0xffff_ffff,
            PortNumber::Regular(other) => other,
        }
    }
}
