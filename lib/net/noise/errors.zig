pub const KeyError = error{
    InvalidLength,
    InvalidHex,
    InvalidPublicKey,
};

pub const CipherError = error{
    InvalidCiphertext,
    AuthenticationFailed,
};

pub const MessageError = error{
    TooShort,
    InvalidType,
    InvalidVarint,
    InvalidAddress,
    Oversize,
};

pub const HandshakeError = error{
    Finished,
    NotReady,
    InvalidMessage,
    MissingLocalStatic,
    MissingRemoteStatic,
    WrongTurn,
    UnsupportedPattern,
    PayloadNotAllowed,
};

pub const SessionError = error{
    NotEstablished,
    ReplayDetected,
    NonceExhausted,
    AuthenticationFailed,
    InvalidCiphertext,
};
