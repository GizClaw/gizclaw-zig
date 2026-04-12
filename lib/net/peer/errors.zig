pub const Error = error{
    NilListener,
    NilConn,
    InvalidHandle,
    Closed,
    ConnClosed,
    StreamClosed,
};
