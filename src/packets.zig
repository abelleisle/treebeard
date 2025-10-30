/// Header included with all DNS messages
pub const Header = packed struct(u96) {
    /// Transaction ID
    transactionID: u16,

    /// DNS flags indicating the message metadata
    /// Note the swapped byte + bit orders from documentation, this it because
    /// zig packs structs little-endian
    flags: packed struct(u16) {
        // ---------------
        // Byte 0

        /// Recursion Desired, indicates if the client means a recursive query.
        RD: bool,

        /// TrunCation, indicates that this message was truncated due to excessive length.
        TC: bool,

        /// Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
        AA: bool,

        /// The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2).
        OPCODE: Opcode,

        /// Indicates if the message is a query (0) or a reply (1).
        QR: bool,

        // ---------------
        // Byte 1

        /// Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.
        RCODE: ResponseCode,

        /// Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
        CD: bool,

        /// Authentic Data, in a response, indicates if the replying DNS server verified the data.
        AD: bool,

        /// Zero, reserved for future use.
        Z: u1 = 0,

        /// Recursion Available, in a response, indicates if the replying DNS server supports recursion.
        RA: bool,
    },

    /// Number of Questions
    numQuestions: u16,

    /// Number of Answers
    numAnswers: u16,

    /// Number of Authority RRs
    numAuthRR: u16,

    /// Number of Additional RRs
    numAddRR: u16,
};

/// DNS question (query)
pub const Question = packed struct {
    /// Name of the requested resource
    name: []u8,

    /// Type of RR (A, AAAA, MX, TXT, etc.)
    typeRR: u16,

    /// Class code
    classCode: u16,
};

/// Resource Record
pub const Record = packed struct {
    /// Name of the node to which this record pertains
    name: []u8,

    /// Type of RR in numeric form (e.g., 15 for MX RRs)
    typeRR: u16,

    /// Class code
    classCode: u16,

    /// Count of seconds that the RR stays valid (The maximum is 231−1, which is about 68 years)
    ttl: u32,

    /// Length of RDATA field (specified in octets)
    rDataLen: u16,

    /// Additional RR-specific data
    rData: []u8,
};

//--------------------------------------------------
// Header Types

/// Header Opcodes
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
pub const Opcode = enum(u4) { query = 0, inverse = 1, status = 2, _ };

/// Header response codes
/// From: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
pub const ResponseCode = enum(u4) {
    /// No Error
    noError = 0,

    /// Format Error
    formErr = 1,

    /// Server Failure
    servFail = 2,

    /// Non-Existant Domain
    nxDomain = 3,

    /// Not Implemented
    notImp = 4,

    /// Query Refused
    refused = 5,

    /// Name Exists when it should not
    yxDomain = 6,

    /// RR Set Exists when it should not
    yxRRSet = 7,

    /// RR Set that should exist does not
    nxRRSet = 8,

    /// Server not authoritative for zone
    notAuth = 9,

    /// Name not contained in zone
    notZone = 10,

    /// DSO-TYPE Not Implemented
    DSOTypeNotImp = 11,

    /// 12-15 are unassigned
    _,
};
