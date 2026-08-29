//! qmsg is a Zig-native messaging/application framework built around
//! subjects, message patterns, bounded queues, and transport adapters.
//!
//! The current implementation focuses on allocator-explicit core types,
//! in-process transport, initial nng-like pattern APIs, and qmsg-owned QUIC
//! integration surfaces. PASETO integration remains optional.

const std = @import("std");

pub const message = @import("message.zig");
pub const subject = @import("subject.zig");
pub const envelope = @import("envelope.zig");
pub const queue = @import("queue.zig");
pub const transport = @import("transport/root.zig");
pub const socket = @import("socket.zig");
pub const auth = @import("auth.zig");
pub const auth_paseto = @import("auth_paseto.zig");
pub const session = @import("session.zig");
pub const node = @import("node.zig");
pub const app = @import("app.zig");
pub const protocol = @import("protocol/root.zig");
pub const control = @import("control.zig");

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
pub const ErrorReply = socket.ErrorReply;
pub const ReplyKey = socket.ReplyKey;
pub const QueueOptions = queue.QueueOptions;
pub const OnFull = queue.OnFull;
pub const QueueStats = queue.QueueStats;
pub const PubSubRegistry = protocol.pubsub.Registry;
pub const PubSubSubscriptionSet = protocol.pubsub.SubscriptionSet;
pub const PubSubPeerId = protocol.pubsub.PeerId;

pub const InprocNetwork = transport.inproc.Network;
pub const Endpoint = transport.Endpoint;
pub const TransportKind = transport.Kind;

pub const AuthConfig = auth.AuthConfig;
pub const Authorization = auth.Authorization;
pub const SubjectPolicy = auth.SubjectPolicy;
pub const PasetoAuth = auth_paseto;

pub const Session = session.Session;
pub const SessionId = session.SessionId;
pub const App = app.App;
pub const AppOptions = app.AppOptions;
pub const Context = app.Context;
pub const ErrorPolicy = app.ErrorPolicy;
pub const InprocRepOptions = app.InprocRepOptions;
pub const RunOnceResult = app.RunOnceResult;
pub const QuicDispatcher = app.QuicDispatcher;
pub const QuicDispatchOptions = app.QuicDispatchOptions;
pub const TlsConfig = app.TlsConfig;
pub const NodeEvent = node.Event;
pub const NodeStats = node.Stats;
pub const NodeServerDispatch = node.NodeServerDispatch;
pub const RequestFailure = node.RequestFailure;
pub const classifyRequestError = node.classifyRequestError;
pub const MessageDropped = node.MessageDropped;
pub const RequestEvent = node.RequestEvent;
pub const ReplyEvent = node.ReplyEvent;
pub const RequestFailedEvent = node.RequestFailedEvent;
pub const DeliveryEvent = node.DeliveryEvent;
pub const InprocRepEndpoint = node.InprocRepEndpoint;
pub const InprocDial = node.InprocDial;
pub const InprocDialOptions = node.InprocDialOptions;
pub const InprocPubEndpoint = node.InprocPubEndpoint;
pub const InprocPubOptions = node.InprocPubOptions;
pub const InprocDialId = node.InprocDialId;
pub const InprocPubId = node.InprocPubId;
pub const QuicRequestEvent = node.QuicRequestEvent;
pub const QuicReplyEvent = node.QuicReplyEvent;
pub const QuicDeliveryEvent = node.QuicDeliveryEvent;
pub const QuicRequestFailedEvent = node.QuicRequestFailedEvent;
pub const EmbeddedDispatch = transport.quic_embedded.EmbeddedDispatch;
pub const EmbeddedSeat = transport.quic_embedded.EmbeddedSeat;
pub const EmbeddedDelivery = transport.quic_embedded.Delivery;
pub const isQmsgAlpn = transport.quic_embedded.isQmsgAlpn;
pub const embeddedDriverSizing = transport.quic_embedded.driverSizing;
pub const QuicListenOptions = node.QuicListenOptions;
pub const QuicDialOptions = node.QuicDialOptions;
pub const QuicSessionOptions = node.QuicSessionOptions;
pub const QuicListenerId = node.QuicListenerId;
pub const QuicSessionId = node.QuicSessionId;
pub const QuicSendMeta = socket.QuicSendMeta;
pub const QuicSendFn = socket.QuicSendFn;
pub const QuicAcceptsFn = socket.QuicAcceptsFn;
pub const QuicPeer = socket.QuicPeer;
pub const QuicSessionDriver = socket.QuicSessionDriver;
pub const QuicSocketEndpoint = socket.QuicSocketEndpoint;
pub const QuicSocketSession = socket.QuicSession;
pub const QuicSocketAttachment = node.QuicSocketAttachment;
pub const HelloChallengeConfig = auth.HelloChallengeConfig;
pub const HelloChallengeBinding = auth.HelloChallengeBinding;
pub const HelloChallengeState = auth.HelloChallengeState;
pub const PeerHelloContext = auth.PeerHelloContext;
pub const ProvidedCredential = auth.ProvidedCredential;
pub const CredentialProvider = auth.CredentialProvider;

pub const Error = error{
    InvalidSubject,
    InvalidSubjectFilter,
    InvalidPattern,
    InvalidEndpoint,
    EndpointInUse,
    EndpointNotFound,
    EndpointClosed,
    InvalidState,
    InvalidMessage,
    NoRoute,
    HeaderLimitExceeded,
    HeaderBytesLimitExceeded,
    MessageTooLarge,
    QueueFull,
    FlowControlled,
    WouldBlock,
    NoPeer,
    DuplicateInflightRequest,
    TooManyInflightRequests,
    DeadlineExceeded,
    Canceled,
    PeerClosed,
    ConnectionLost,
    StreamNotFound,
    StreamAlreadyOpen,
    StreamReset,
    MalformedFrame,
    UnknownControlFrame,
    InvalidControlFrame,
    FrameTooLarge,
    PeerIdTooLarge,
    AuthSchemeTooLarge,
    CredentialTooLarge,
    KeyIdHintTooLarge,
    SubjectFilterTooLarge,
    GoawayReasonTooLarge,
    UnexpectedFrame,
    VersionMismatch,
    UnsupportedTransport,
    UnsupportedCredential,
    TooManySessions,
    UnknownKey,
    Unauthorized,
    AuthenticationRequired,
    TokenTooLarge,
    ImplicitAssertionTooLarge,
    ChallengeRequired,
    ChallengeTooLarge,
    ReplayedCredential,
    CredentialExpired,
    CredentialNotYetValid,
    InvalidClaims,
};

pub const Limits = struct {
    pub const default_max_message_size: usize = 1024 * 1024;
    pub const default_max_headers: usize = 32;
    pub const default_max_header_bytes: usize = 16 * 1024;
};

test {
    std.testing.refAllDecls(@This());
}
