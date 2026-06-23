pub const ProtocolKCP: u8 = 0x00;
pub const ProtocolConnCtrl: u8 = 0xff;
pub const ConnCtrlClose: u8 = 0x01;

pub const KcpMuxFrameOpen: u8 = 0x00;
pub const KcpMuxFrameData: u8 = 0x01;
pub const KcpMuxFrameClose: u8 = 0x02;
pub const KcpMuxFrameCloseAck: u8 = 0x03;
