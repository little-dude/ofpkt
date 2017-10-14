extern crate ofpkt;

use std::fs::File;
use std::io::Read;
use ofpkt::openflow;
use ofpkt::oxm;
use ofpkt::{Repr, Result};


// dummy OxmExperimenter field, since openflow::PacketRepr is generic over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

type PacketRepr = openflow::PacketRepr<OxmExperimenter>;

fn load_packet(name: &str) -> Vec<u8> {
    let mut file = File::open(format!("./tests/data/{}", name)).unwrap();
    let mut buf = vec![];
    let _ = file.read_to_end(&mut buf).unwrap();
    buf
}

fn emit_and_compare(repr: &PacketRepr, name: &str) {
    let pkt = load_packet(name);
    let mut buf: Vec<u8> = vec![0; repr.buffer_len()];
    repr.emit(buf.as_mut()).unwrap();
    assert_eq!(&buf[..], &pkt[..]);
}

mod parse {
    use super::*;
    use ofpkt::openflow::{Kind, PayloadRepr, Version};
    use ofpkt::Repr;

    #[test]
    fn hello() {
        use ofpkt::hello;

        let pkt = load_packet("hello");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::Hello,
            xid: 0,
            payload: PayloadRepr::Hello(hello::PacketRepr::new(vec![
                hello::ElementRepr {
                    kind: hello::Kind::Bitmap,
                    payload: hello::ElementData::Bitmap(hello::BitmapRepr(64)),
                },
            ])),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn echo_request() {
        let pkt = load_packet("echo_request");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::EchoRequest,
            xid: 0,
            payload: PayloadRepr::EchoRequest(vec![]),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn echo_reply() {
        let pkt = load_packet("echo_reply");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::EchoReply,
            xid: 0,
            payload: PayloadRepr::EchoReply(vec![]),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn features_request() {
        let pkt = load_packet("features_request");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::FeaturesRequest,
            xid: 0,
            payload: PayloadRepr::FeaturesRequest,
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn features_reply() {
        use ofpkt::features_reply;

        let pkt = load_packet("features_reply");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::FeaturesReply,
            xid: 0,
            payload: PayloadRepr::FeaturesReply(features_reply::PacketRepr {
                datapath_id: 1,
                n_buffers: 255,
                n_tables: 255,
                auxiliary_id: 0,
                capabilities: features_reply::Capabilities::new(79),
                reserved: 0,
            }),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn error() {
        use ofpkt::error;

        let pkt = load_packet("error_msg");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::Error,
            xid: 0,
            payload: PayloadRepr::Error(ofpkt::error::PacketRepr {
                header: error::Header::BadMatch(error::BadMatchCode::BadField),
                data: vec![0x06, 0x0e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
            }),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn get_config_request() {
        let pkt = load_packet("get_config_request");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::GetConfigRequest,
            xid: 0,
            payload: PayloadRepr::GetConfigRequest,
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn set_config() {
        use ofpkt::set_config;

        let pkt = load_packet("set_config");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::SetConfig,
            xid: 0,
            payload: PayloadRepr::SetConfig(set_config::PacketRepr {
                flags: set_config::Flags::FragmentNormal,
                miss_send_len: 128,
            }),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }

    #[test]
    fn packet_in() {
        use ofpkt::packet_in;

        let pkt = load_packet("packet_in");
        let repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: pkt.len() as u16,
            kind: Kind::PacketIn,
            xid: 0,
            payload: PayloadRepr::PacketIn(packet_in::PacketRepr {
                buffer_id: 200,
                table_id: 100,
                cookie: 0,
                reason: packet_in::Reason::TableMiss,
                flow_match: oxm::FlowMatch::<OxmExperimenter>(vec![
                    oxm::Oxm::FlowMatchField(oxm::FlowMatchField::InPort(oxm::InPort::new(43_981))),
                    oxm::Oxm::FlowMatchField(oxm::FlowMatchField::TunnelId(
                        oxm::TunnelId::new(50_000, None),
                    )),
                    oxm::Oxm::PacketRegisters(oxm::PacketRegisters {
                        field: 31, // corresponds to tun_ipv4_src in ryu
                        value: (192 << 24) + (168 << 16) + (2 << 8) + 3,
                        mask: None,
                    }),
                    oxm::Oxm::PacketRegisters(oxm::PacketRegisters {
                        field: 32, // corresponds to tun_ipv4_dst in ryu
                        value: (192 << 24) + (168 << 16) + (2 << 8) + 4,
                        mask: None,
                    }),
                ]),
                frame: vec![0x68, 0x6f, 0x67, 0x65],
                frame_length: 1000,
            }),
        };
        assert_eq!(PacketRepr::parse(&pkt).unwrap(), repr);
    }
}

mod encode {
    use super::*;
    use ofpkt::openflow::{Kind, PayloadRepr, Version};

    #[test]
    fn hello() {
        use ofpkt::hello;

        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::Hello,
            xid: 0,
            payload: PayloadRepr::Hello(hello::PacketRepr::new(vec![
                hello::ElementRepr {
                    kind: hello::Kind::Bitmap,
                    payload: hello::ElementData::Bitmap(hello::BitmapRepr(64)),
                },
            ])),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "hello");
    }

    #[test]
    fn echo_request() {
        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::EchoRequest,
            xid: 0,
            payload: PayloadRepr::EchoRequest(vec![]),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "echo_request");
    }

    #[test]
    fn echo_reply() {
        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::EchoReply,
            xid: 0,
            payload: PayloadRepr::EchoReply(vec![]),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "echo_reply");
    }

    #[test]
    fn features_request() {
        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::FeaturesRequest,
            xid: 0,
            payload: PayloadRepr::FeaturesRequest,
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "features_request");
    }

    #[test]
    fn error() {
        use ofpkt::error;

        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::Error,
            xid: 0,
            payload: PayloadRepr::Error(ofpkt::error::PacketRepr {
                header: error::Header::BadMatch(error::BadMatchCode::BadField),
                data: vec![0x06, 0x0e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
            }),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "error_msg");
    }

    #[test]
    fn features_reply() {
        use ofpkt::features_reply;

        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::FeaturesReply,
            xid: 0,
            payload: PayloadRepr::FeaturesReply(features_reply::PacketRepr {
                datapath_id: 1,
                n_buffers: 255,
                n_tables: 255,
                auxiliary_id: 0,
                capabilities: features_reply::Capabilities::new(79),
                reserved: 0,
            }),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "features_reply");
    }

    #[test]
    fn get_config_request() {
        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::GetConfigRequest,
            xid: 0,
            payload: PayloadRepr::GetConfigRequest,
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "get_config_request");
    }

    #[test]
    fn get_config_reply() {
        use ofpkt::get_config_reply;

        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::GetConfigReply,
            xid: 0,
            payload: PayloadRepr::GetConfigReply(get_config_reply::PacketRepr {
                flags: get_config_reply::Flags::FragmentNormal,
                miss_send_len: 128,
            }),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "get_config_reply");
    }

    #[test]
    fn set_config() {
        use ofpkt::set_config;

        let mut repr = PacketRepr {
            version: Version::OpenFlow1Dot5,
            length: 0,
            kind: Kind::SetConfig,
            xid: 0,
            payload: PayloadRepr::SetConfig(set_config::PacketRepr {
                flags: set_config::Flags::FragmentNormal,
                miss_send_len: 128,
            }),
        };
        repr.set_length_auto();
        emit_and_compare(&repr, "set_config");
    }
}
