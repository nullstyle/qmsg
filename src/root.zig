//! qmsg is a Zig-native messaging/application framework built around
//! subjects, message patterns, bounded queues, and transport adapters.
//!
//! The current implementation focuses on allocator-explicit core types,
//! in-process transport, and initial nng-like pattern APIs. QUIC and PASETO
//! integrations are represented by stable boundaries but remain optional.

const std = @import("std");

pub const message = @import("message.zig");
pub const subject = @import("subject.zig");
pub const envelope = @import("envelope.zig");
pub const queue = @import("queue.zig");
pub const transport = @import("transport/root.zig");
pub const socket = @import("socket.zig");
pub const auth = @import("auth.zig");
pub const session = @import("session.zig");
pub const node = @import("node.zig");
pub const app = @import("app.zig");
pub const protocol = @import("protocol/root.zig");

pub const Message = message.Message;
pub const OutgoingMessage = message.OutgoingMessage;
pub const Header = message.Header;
pub const Flags = message.Flags;
pub const MessageId = message.MessageId;

pub const SubjectFilter = subject.Filter;
pub const SubjectRouter = subject.Router;

pub const Pattern = socket.Pattern;
pub const Socket = socket.Socket;
pub const SocketOptions = socket.SocketOptions;
pub const Request = socket.Request;
pub const QueueOptions = queue.QueueOptions;
pub const OnFull = queue.OnFull;

pub const InprocNetwork = transport.inproc.Network;
pub const Endpoint = transport.Endpoint;
pub const TransportKind = transport.Kind;

pub const AuthConfig = auth.AuthConfig;
pub const Authorization = auth.Authorization;
pub const SubjectPolicy = auth.SubjectPolicy;

pub const Session = session.Session;
pub const SessionId = session.SessionId;
pub const App = app.App;
pub const AppOptions = app.AppOptions;
pub const Context = app.Context;
pub const TlsConfig = app.TlsConfig;

pub const Error = error{
    InvalidSubject,
    InvalidSubjectFilter,
    InvalidPattern,
    InvalidEndpoint,
    EndpointInUse,
    EndpointNotFound,
    InvalidState,
    InvalidMessage,
    HeaderLimitExceeded,
    HeaderBytesLimitExceeded,
    MessageTooLarge,
    QueueFull,
    FlowControlled,
    WouldBlock,
    DeadlineExceeded,
    Canceled,
    PeerClosed,
    ConnectionLost,
    StreamReset,
    MalformedFrame,
    UnexpectedFrame,
    VersionMismatch,
    UnsupportedTransport,
    UnsupportedCredential,
    UnknownKey,
    Unauthorized,
    AuthenticationRequired,
    TokenTooLarge,
    ReplayedCredential,
    CredentialExpired,
    CredentialNotYetValid,
};

pub const Limits = struct {
    pub const default_max_message_size: usize = 1024 * 1024;
    pub const default_max_headers: usize = 32;
    pub const default_max_header_bytes: usize = 16 * 1024;
};

test {
    std.testing.refAllDecls(@This());
}
