const dep = @import("dep");

const net = dep.net;

pub const Error = error{
    InvalidHandle,
    ListenerClosed,
};

pub fn isClosed(err: anyerror) bool {
    return switch (err) {
        error.Closed,
        error.ConnClosed,
        error.StreamClosed,
        error.StreamNotFound,
        error.ListenerClosed,
        => true,
        else => false,
    };
}

pub fn toConnReadError(err: anyerror) net.Conn.ReadError {
    return switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.ShortRead => error.ShortRead,
        error.ConnectionReset => error.ConnectionReset,
        error.ConnectionRefused => error.ConnectionRefused,
        error.BrokenPipe => error.BrokenPipe,
        error.TimedOut => error.TimedOut,
        error.StreamClosed,
        error.StreamNotFound,
        error.ConnClosed,
        error.ListenerClosed,
        error.Closed,
        => error.ConnectionReset,
        else => error.Unexpected,
    };
}

pub fn toConnWriteError(err: anyerror) net.Conn.WriteError {
    return switch (err) {
        error.ConnectionRefused => error.ConnectionRefused,
        error.ConnectionReset => error.ConnectionReset,
        error.BrokenPipe => error.BrokenPipe,
        error.TimedOut => error.TimedOut,
        error.StreamClosed,
        error.StreamNotFound,
        error.ConnClosed,
        error.ListenerClosed,
        error.Closed,
        => error.BrokenPipe,
        else => error.Unexpected,
    };
}

pub fn toListenerAcceptError(err: anyerror) net.Listener.AcceptError {
    return switch (err) {
        error.Closed,
        error.ConnClosed,
        error.StreamClosed,
        error.StreamNotFound,
        error.ListenerClosed,
        => error.Closed,
        error.QueueEmpty,
        error.AcceptQueueEmpty,
        error.TimedOut,
        => error.WouldBlock,
        error.OutOfMemory => error.OutOfMemory,
        error.PermissionDenied => error.PermissionDenied,
        else => error.Unexpected,
    };
}
