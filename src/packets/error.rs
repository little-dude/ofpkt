//! Types representing OpenFlow Error messages.
//!
use {Error, Repr, Result};
use byteorder::{ByteOrder, NetworkEndian};

enum_with_unknown! {
    /// Represent the type of the error
    pub doc enum Kind(u16) {
        /// Hello protocol failed
        HelloFailed = 0,
        /// Request was not understood.
        BadRequest = 1,
        /// Error in action description.
        BadAction = 2,
        /// Error in instruction list.
        BadInstruction = 3,
        /// Error in match.
        BadMatch = 4,
        /// Problem modifying flow entry.
        FlowModFailed = 5,
        /// Problem modifying group entry.
        GroupModFailed = 6,
        /// Port mod request failed.
        PortModFailed = 7,
        /// Table mod request failed.
        TableModFailed = 8,
        /// Queue operation failed.
        QueueOpFailed = 9,
        /// Switch config request failed.
        SwitchConfigFailed = 10,
        /// Controller Role request failed.
        RoleRequestFailed = 11,
        /// Error in meter.
        MeterModFailed = 12,
        /// Setting table features failed.
        TableFeaturesFailed = 13,
        /// Some property is invalid.
        BadProperty = 14,
        /// Asynchronous config request failed.
        AsyncConfigFailed = 15,
        /// Setting flow monitor failed.
        FlowMonitorFailed = 16,
        /// Bundle operation failed.
        BundleFailed = 17,
        /// Experimenter error messages.
        Experimenter = 0xffff
    }
}

enum_with_unknown! {
    /// The code associated to an `HelloFailed` error
    pub doc enum HelloFailedCode(u16) {
        /// No compatible version.
        Incompatible = 0,
        /// Permissions error.
        Eperm = 1
    }
}

enum_with_unknown! {
    /// The code associated to an `HelloFailed` error
    pub doc enum BadRequestCode(u16) {
        /// ofp_header.version not supported.
        BadVersion = 0,
        /// ofp_header.type not supported.
        BadType = 1,
        /// ofp_multipart_request.type supported.
        BadMultipart = 2,
        /// Experimenter id not supported (in ofp_experimenter_header or ofp_multipart_request or ofp_multipart_reply).
        BadExperimenter = 3,
        /// Experimenter type not supported.
        BadExpType = 4,
        /// Permissions error.
        Permissions = 5,
        /// Wrong request length for type.
        BadLength  = 6,
        /// Specified buffer has already been used.
        BufferEmpty = 7,
        /// Specified buffer does not exist.
        BufferUnknown = 8,
        /// Specified table-id invalid or does exist.
        BadTableId = 9,
        /// Denied because controller is slave.
        IsSlave = 10,
        /// Invalid port or missing port.
        BadPort = 11,
        /// Invalid packet in packet-out.
        BadPacket = 12,
        /// ofp_multipart_request overflowed the assigned buffer. */
        MultipartBufferOverflow = 13,
        /// Timeout during multipart request.
        MultipartRequestTimeout = 14,
        /// Timeout during multipart reply.
        MultipartReplyTimeout = 15,
        /// Switch received a OFPMP_BUNDLE_FEATURES request and failed to update the scheduling tolerance.
        MultipartBadSched = 16,
        /// Match fields must include only pipeline fields.
        PipelineFieldsOnly = 17,
        /// Unspecified error.
        Unknown = 18
    }
}

enum_with_unknown! {
    /// The code associated to a `BadAction` error
    pub doc enum BadActionCode(u16) {
        /// Unknown or unsupported action type.
        BadType = 0,
        /// Length problem in actions.
        BadLength = 1,
        /// Unknown experimenter id specified.
        BadExperimenterId = 2,
        /// Unknown action for experimenter id.
        BadExperimenterType = 3,
        /// Problem validating output port.
        BadOutPort = 4,
        /// Bad action argument.
        BadArgument = 5,
        /// Permissions error.
        Permissions = 6,
        /// Can't handle this many actions.
        TooMany = 7,
        /// Problem validating output queue.
        BadQueue = 8,
        /// Invalid group id in group action.
        BadOutGroup = 9,
        /// Action can't apply for this match, or Set-Field missing prerequisite.
        MatchInconsistent = 10,
        /// Action order is unsupported for the action list in an Apply-Actions instruction */
        UnsupportedOrder = 11,
        /// Actions uses an unsupported tag/encap.
        BadTag = 12,
        /// Unsupported type in SET_FIELD action.
        BadSetType = 13,
        /// Length problem in SET_FIELD action.
        BadSetLength = 14,
        /// Bad argument in SET_FIELD action.
        BadSetArgument = 15,
        /// Bad mask in SET_FIELD action.
        BadSetMask = 16,
        /// Invalid meter id in meter action.
        BadMeterId = 17
    }
}

enum_with_unknown! {
    /// The code associated to a `BadInstruction` error
    pub doc enum BadInstructionCode(u16) {
        /// Unknown instruction.
        UnknownInstruction = 0,
        /// Switch or table does not support the instruction.
        UnsupportedInstruction = 1,
        /// Invalid Table-ID specified.
        BadTableId = 2,
        /// Metadata value unsupported by datapath.
        UnsupportedMetadata = 3,
        /// Metadata mask value unsupported by datapath.
        UnsupportedMetadataMask = 4,
        /// Unknown experimenter id specified.
        BadExperimenterId = 5,
        /// Unknown instruction for experimenter id.
        BadExperimenterType = 6,
        /// Length problem in instructions.
        BadLength = 7,
        /// Permissions error.
        Permissions = 8,
        /// Duplicate instruction.
        DuplicateInstruction = 9
    }
}

enum_with_unknown! {
    /// The code associated to a `BadMatch` error
    pub doc enum BadMatchCode(u16) {
        /// Unsupported match type specified by the match
        BadType = 0,
        /// Length problem in match.
        BadLength = 1,
        /// Match uses an unsupported tag/encap.
        BadTag = 2,
        /// Unsupported datalink addr mask - switch does not support arbitrary datalink address mask.
        BadDataLinkAddressMask = 3,
        /// Unsupported network addr mask - switch does not support arbitrary network address mask.
        BadNetworkAddressMask = 4,
        /// Unsupported combination of fields masked or omitted in the match.
        BadWildcards = 5,
        /// Unsupported field type in the match.
        BadField = 6,
        /// Unsupported value in a match field.
        BadValue = 7,
        /// Unsupported mask specified in the match.
        BadMask = 8,
        /// A prerequisite was not met.
        BadPrerequities = 9,
        /// A field type was duplicated.
        DupplicateField = 10,
        /// Permissions error.
        Permissions = 11
    }
}

enum_with_unknown! {
    /// The code associated to a `FlowModFailed` error
    pub doc enum FlowModFailedCode(u16) {
        /// Unspecified error.
        Unknown = 0,
        /// Flow not added because table was full.
        TableFull = 1,
        /// Table does not exist.
        BadTableId = 2,
        /// Attempted to add overlapping flow with CHECK_OVERLAP flag set.
        Overlap = 3,
        /// Permissions error.
        Permissions = 4,
        /// Flow not added because of unsupported idle/hard timeout.
        BadTimeout = 5,
        /// Unsupported or unknown command.
        BadCommand = 6,
        /// Unsupported or unknown flags.
        BadFlags = 7,
        /// Problem in table synchronisation.
        CantSync = 8,
        /// Unsupported priority value.
        BadPriority = 9,
        /// Synchronised flow entry is read only.
        IsSync = 10
    }
}

enum_with_unknown! {
    /// The code associated to a `GroupModFailed` error
    pub doc enum GroupModFailedCode(u16) {
        /// Group not added because a group ADD attempted to replace an already-present group.
        GroupExists = 0,
        /// Group not added because Group specified is invalid.
        InvalidGroup = 1,
        /// Switch does not support unequal load sharing with select groups.
        WeightUnsupported = 2,
        /// The group table is full.
        OutOfGroups = 3,
        /// The maximum number of action buckets for a group has been exceeded.
        OutOfBuckets = 4,
        /// Switch does not support groups that forward to groups.
        ChainingUnsupported = 5,
        /// This group cannot watch the watch_port or watch_group specified.
        WatchUnsupported = 6,
        /// Group entry would cause a loop.
        Loop = 7,
        /// Group not modified because a group MODIFY attempted to modify a non-existent group.
        UnknownGroup = 8,
        /// Group not deleted because another group is forwarding to it.
        ChainedGroup = 9,
        /// Unsupported or unknown group type.
        BadType = 10,
        /// Unsupported or unknown command.
        BadCommand = 11,
        /// Error in bucket.
        BadBucket = 12,
        /// Error in watch port/group.
        BadWatch = 13,
        /// Permissions error.
        Permissions = 14,
        /// Invalid bucket identifier used in INSERT BUCKET or REMOVE BUCKET command.
        UnknownBucket = 15,
        /// Can't insert bucket because a bucket already exist with that bucket-id.
        BucketExists = 16
    }
}

enum_with_unknown! {
    /// The code associated to a `PortModFailed` error
    pub doc enum PortModFailedCode(u16) {
        /// Specified port number does not exist.
        BadPort = 0,
        /// Specified hardware address does not match the port number
        BadHardwareAddress = 1,
        /// Specified config is invalid.
        BadConfig = 2,
        /// Specified advertise is invalid.
        BadAdvertise = 3,
        /// Permissions error.
        Permissions = 4
    }
}

enum_with_unknown! {
    /// The code associated to a `TableModfailed` error
    pub doc enum TableModFailedCode(u16) {
        /// Specified table does not exist.
        BadTable = 0,
        /// Specified config is invalid.
        BadConfig = 1,
        /// Permissions error.
        Permissions = 2
    }
}

enum_with_unknown! {
    /// The code associated to a `QueueOpFailed` error
    pub doc enum QueueOpFailedCode(u16) {
        /// Invalid port (or port does not exist).
        BadPort = 0,
        /// Queue does not exist.
        BadQueue = 1,
        /// Permissions error.
        Permissions = 2
    }
}

enum_with_unknown! {
    /// The code associated to a `SwitchConfigFailed` error
    pub doc enum SwitchConfigFailedCode(u16) {
        /// Specified flags is invalid.
        BadFlags = 0,
        /// Specified miss send len is invalid.
        BadLength = 1,
        /// Permissions error.
        Permissions = 2
    }
}

enum_with_unknown! {
    /// The code associated to a `RoleRequestFailed` error
    pub doc enum RoleRequestFailedCode(u16) {
        /// Stale Message: old generation_id.
        Stale = 0,
        /// Controller role change unsupported.
        Unsupported = 1,
        /// Invalid role.
        BadRole = 2,
        /// Switch doesn't support changing ID.
        IdUnsupported = 3,
        /// Requested ID is in use.
        IdInUse = 4
    }
}

enum_with_unknown! {
    /// The code associated to a `MeterModFailed` error
    pub doc enum MeterModFailedCode(u16) {
        /// Unspecified error.
        Unknown = 0,
        /// Meter not added because a Meter ADD attempted to replace an existing Meter.
        MeterExists = 1,
        /// Meter not added because Meter specified is invalid, or invalid meter in meter action.
        InvalidMeter = 2,
        /// Meter not modified because a Meter MODIFY attempted to modify a non-existent Meter, or bad meter in meter action.
        UnknownMeter = 3,
        /// Unsupported or unknown command.
        BadCommand = 4,
        /// Flag configuration unsupported.
        BadFlags = 5,
        /// Rate unsupported.
        BadRate = 6,
        /// Burst size unsupported.
        BadBurst = 7,
        /// Band unsupported.
        BadBand = 8,
        /// Band value unsupported.
        BadBandValue = 9,
        /// No more meters available.
        OutOfMeters = 10,
        /// The maximum number of properties for a meter has been exceeded.
        OutOfBands = 11
    }
}

enum_with_unknown! {
    /// The code associated to a `TableFeaturesFailed` error
    pub doc enum TableFeaturesFailedCode(u16) {
        /// Specified table does not exist.
        BadTable = 0,
        /// Invalid metadata mask.
        BadMetadata = 1,
        /// Permissions error.
        Permissions = 5,
        /// Invalid capability field.
        BadCapability = 6,
        /// Invalid max_entries field.
        BadMaxEntries = 7,
        /// Invalid features field.
        BadFeatures = 8,
        /// Invalid command.
        BadCommand = 9,
        /// Can't handle this many flow tables.
        TooMany = 10
    }
}

enum_with_unknown! {
    /// The code associated to a `BadProperty` error
    pub doc enum BadPropertyCode(u16) {
        /// Unknown or unsupported property type.
        BadType = 0,
        /// Length problem in property.
        BadLength = 1,
        /// Unsupported property value.
        BadValue = 2,
        /// Can't handle this many properties.
        TooMany = 3,
        /// A property type was duplicated.
        DuplicateType = 4,
        /// Unknown experimenter id specified.
        BadExperimenterId = 5,
        /// Unknown exp_type for experimenter id.
        BadExperimenterType = 6,
        /// Unknown value for experimenter id.
        BadExperimenterValue = 7,
        /// Permissions error.
        Permissions = 8
    }
}

enum_with_unknown! {
    /// The code associated to a `AsyncConfigFailed` error
    pub doc enum AsyncConfigFailedCode(u16) {
        /// One mask is invalid.
        Invalid = 0,
        /// Requested configuration not supported.
        Unsupported = 1,
        /// Permissions error.
        Permissions = 2
    }
}

enum_with_unknown! {
    /// The code associated to a `FlowMonitorFailed` error
    pub doc enum FlowMonitorFailedCode(u16) {
        /// Unspecified error.
        Unknown = 0,
        /// Monitor not added because a Monitor ADD attempted to replace an existing Monitor.
        MonitorExists = 1,
        /// Monitor not added because Monitor specified is invalid.
        InvalidMonitor = 2,
        /// Monitor not modified because a Monitor MODIFY attempted to modify a non-existent Monitor.
        UnknownMonitor = 3,
        /// Unsupported or unknown command.
        BadCommand = 4,
        /// Flag configuration unsupported.
        BadFlags = 5,
        /// Specified table does not exist.
        BadTableId = 6,
        /// Error in output port/group.
        BadOutput = 7
    }
}

enum_with_unknown! {
    /// The code associated to a `BundleFailed` error
    pub doc enum BundleFailedCode(u16) {
        /// Unspecified error.
        Unknown = 0,
        /// Permissions error.
        Permissions = 1,
        /// Bundle ID doesn't exist.
        BadId = 2,
        /// Bundle ID already exist.
        BundleExist = 3,
        /// Bundle ID is closed.
        BundleClosed = 4,
        /// Too many bundles IDs.
        OutOfBundles = 5,
        /// Unsupported or unknown message control type.
        BadType = 6,
        /// Unsupported, unknown, or inconsistent flags.
        BadFlags = 7,
        /// Length problem in included message.
        MsgBadLength = 8,
        /// Inconsistent or duplicate XID.
        MsgBadXid = 9,
        /// Unsupported message in this bundle.
        MsgUnsupported = 10,
        /// Unsupported message combination in this bundle.
        MsgConflict = 11,
        /// Can't handle this many messages in bundle.
        MsgTooMany = 12,
        /// One message in bundle failed.
        MsgFailed = 13,
        /// Bundle is taking too long.
        Timeout = 14,
        /// Bundle is locking the resource.
        BundleInProgress = 15,
        /// Scheduled commit was received and scheduling is not supported.
        SchedNotSupported = 16,
        /// Scheduled commit time exceeds upper bound.
        SchedFuture = 17,
        /// Scheduled commit time exceeds lower bound.
        SchedPast = 18
    }
}

/// ```no_rust
/// +--------+--------+--------+--------+
/// |       type      |      code       |
/// +--------+--------+--------+--------+
/// |               data                |
/// +--------+--------+--------+--------+
/// ```
///
/// An error message can be sent by either the switch or the controller and indicates the failure
/// of an operation. The simplest failure pertain to malformed messages or failed version
/// negotiation, while more complex scenarios desbie some failure in state change at the switch.
/// All error messages begin with the standard OpenFlow header, containing the appropriate version
/// and type values, followed by the error structure.
///
/// The data has variable length, and is interpreted based on the type of error.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    pub inner: T,
}

mod field {
    use field::*;

    pub const KIND: Field = 0..2;
    pub const CODE: Field = 2..4;
    pub const DATA: Rest = 4..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with OpenFlow Hello message structure.
    pub fn new(buffer: T) -> Self {
        Packet { inner: buffer }
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

    /// Return the type field.
    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.inner.as_ref();
        NetworkEndian::read_u16(&data[field::KIND]).into()
    }

    /// Return the code field.
    #[inline]
    pub fn code(&self) -> u16 {
        let data = self.inner.as_ref();
        NetworkEndian::read_u16(&data[field::CODE])
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_header_len]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let buffer_len = self.inner.as_ref().len();
        if buffer_len < Self::header_len() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    pub fn header_len() -> usize {
        field::CODE.end
    }

    /// Return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.inner.as_ref();
        &data[field::DATA]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.inner.as_mut();
        &mut data[field::DATA]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the type field
    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        let data = self.inner.as_mut();
        NetworkEndian::write_u16(&mut data[field::KIND], value.into())
    }

    /// Set the code field.
    #[inline]
    pub fn set_code(&mut self, value: u16) {
        let data = self.inner.as_mut();
        NetworkEndian::write_u16(&mut data[field::CODE], value)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let data = self.inner.as_mut();
        &mut data[field::DATA]
    }
}

/// Represent the type and error of an Error message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Header {
    /// Hello protocol failed
    HelloFailed(HelloFailedCode),
    /// Request was not understood.
    BadRequest(BadRequestCode),
    /// Error in action description.
    BadAction(BadActionCode),
    /// Error in instruction list.
    BadInstruction(BadInstructionCode),
    /// Error in match.
    BadMatch(BadMatchCode),
    /// Problem modifying flow entry.
    FlowModFailed(FlowModFailedCode),
    /// Problem modifying group entry.
    GroupModFailed(GroupModFailedCode),
    /// Port mod request failed.
    PortModFailed(PortModFailedCode),
    /// Table mod request failed.
    TableModFailed(TableModFailedCode),
    /// Queue operation failed.
    QueueOpFailed(QueueOpFailedCode),
    /// Switch config request failed.
    SwitchConfigFailed(SwitchConfigFailedCode),
    /// Controller Role request failed.
    RoleRequestFailed(RoleRequestFailedCode),
    /// Error in meter.
    MeterModFailed(MeterModFailedCode),
    /// Setting table features failed.
    TableFeaturesFailed(TableFeaturesFailedCode),
    /// Some property is invalid.
    BadProperty(BadPropertyCode),
    /// Asynchronous config request failed.
    AsyncConfigFailed(AsyncConfigFailedCode),
    /// Setting flow monitor failed.
    FlowMonitorFailed(FlowMonitorFailedCode),
    /// Bundle operation failed.
    BundleFailed(BundleFailedCode),
    /// Experimenter error messages.
    Experimenter(u16),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketRepr {
    pub header: Header,
    pub data: Vec<u8>,
}

impl Repr for PacketRepr {
    fn buffer_len(&self) -> usize {
        self.data.len() + Packet::<&[u8]>::header_len()
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn parse(buffer: &[u8]) -> Result<Self> {
        use self::Kind::*;

        let packet = Packet::new_checked(buffer)?;
        let code = packet.code();
        let header = match packet.kind() {
            HelloFailed         => Header::HelloFailed(HelloFailedCode::from(code)),
            BadRequest          => Header::BadRequest(BadRequestCode::from(code)),
            BadAction           => Header::BadAction(BadActionCode::from(code)),
            BadInstruction      => Header::BadInstruction(BadInstructionCode::from(code)),
            BadMatch            => Header::BadMatch(BadMatchCode::from(code)),
            FlowModFailed       => Header::FlowModFailed(FlowModFailedCode::from(code)),
            GroupModFailed      => Header::GroupModFailed(GroupModFailedCode::from(code)),
            PortModFailed       => Header::PortModFailed(PortModFailedCode::from(code)),
            TableModFailed      => Header::TableModFailed(TableModFailedCode::from(code)),
            QueueOpFailed       => Header::QueueOpFailed(QueueOpFailedCode::from(code)),
            SwitchConfigFailed  => Header::SwitchConfigFailed(SwitchConfigFailedCode::from(code)),
            RoleRequestFailed   => Header::RoleRequestFailed(RoleRequestFailedCode::from(code)),
            MeterModFailed      => Header::MeterModFailed(MeterModFailedCode::from(code)),
            TableFeaturesFailed => Header::TableFeaturesFailed(TableFeaturesFailedCode::from(code)),
            BadProperty         => Header::BadProperty(BadPropertyCode::from(code)),
            AsyncConfigFailed   => Header::AsyncConfigFailed(AsyncConfigFailedCode::from(code)),
            FlowMonitorFailed   => Header::FlowMonitorFailed(FlowMonitorFailedCode::from(code)),
            BundleFailed        => Header::BundleFailed(BundleFailedCode::from(code)),
            Experimenter        => Header::Experimenter(code),
            _Unknown(_)         => return Err(Error::Malformed),
        };
        let repr = PacketRepr {
            header: header,
            data: packet.payload().to_vec(),
        };
        Ok(repr)
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    /// Emit a high-level representation into an error message into a buffer
    fn emit(&self, buffer: &mut [u8]) -> Result<()> {
        use self::Header::*;

        if buffer.len() < self.buffer_len() {
            return Err(Error::Exhausted);
        }

        let mut packet = Packet::new(buffer);

        let (kind, code) = match self.header {
            HelloFailed(code)           => (Kind::HelloFailed,          u16::from(code)),
            BadRequest(code)            => (Kind::BadRequest,           u16::from(code)),
            BadAction(code)             => (Kind::BadAction,            u16::from(code)),
            BadInstruction(code)        => (Kind::BadInstruction,       u16::from(code)),
            BadMatch(code)              => (Kind::BadMatch,             u16::from(code)),
            FlowModFailed(code)         => (Kind::FlowModFailed,        u16::from(code)),
            GroupModFailed(code)        => (Kind::GroupModFailed,       u16::from(code)),
            PortModFailed(code)         => (Kind::PortModFailed,        u16::from(code)),
            TableModFailed(code)        => (Kind::TableModFailed,       u16::from(code)),
            QueueOpFailed(code)         => (Kind::QueueOpFailed,        u16::from(code)),
            SwitchConfigFailed(code)    => (Kind::SwitchConfigFailed,   u16::from(code)),
            RoleRequestFailed(code)     => (Kind::RoleRequestFailed,    u16::from(code)),
            MeterModFailed(code)        => (Kind::MeterModFailed,       u16::from(code)),
            TableFeaturesFailed(code)   => (Kind::TableFeaturesFailed,  u16::from(code)),
            BadProperty(code)           => (Kind::BadProperty,          u16::from(code)),
            AsyncConfigFailed(code)     => (Kind::AsyncConfigFailed,    u16::from(code)),
            FlowMonitorFailed(code)     => (Kind::FlowMonitorFailed,    u16::from(code)),
            BundleFailed(code)          => (Kind::BundleFailed,         u16::from(code)),
            Experimenter(code)          => (Kind::Experimenter,         code),
        };
        packet.set_kind(kind);
        packet.set_code(code);
        packet.payload_mut().copy_from_slice(self.data.as_slice());
        Ok(())
    }
}
