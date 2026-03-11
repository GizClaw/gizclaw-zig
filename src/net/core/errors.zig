pub const ConnError = error{
    MissingLocalKey,
    MissingTransport,
    MissingRemotePK,
    MissingRemoteAddr,
    InvalidState,
    NotEstablished,
    InvalidReceiverIndex,
    InvalidRemotePK,
    HandshakeIncomplete,
    HandshakeFailed,
    HandshakeTimeout,
    ConnTimeout,
    ConnClosed,
    SessionExpired,
    SessionError,
    HandshakeError,
    MessageError,
    MessageTooLarge,
    TransportError,
    OutOfMemory,
    UnsupportedProtocol,
    UnsupportedService,
};

pub const DialError = error{
    HandshakeTimeout,
    MissingRemotePK,
    HandshakeError,
    TransportError,
    MessageError,
    InvalidReceiverIndex,
    OutOfMemory,
};

pub const ManagerError = error{
    IndexInUse,
    OutOfMemory,
    NoFreeIndex,
};
