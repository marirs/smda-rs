#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("logic error: {0} - {1}")]
    LogicError(&'static str, u32),
    #[error("not enough bytes in buffer: {0} - {1}")]
    NotEnoughBytesError(u64, u64),
    #[error("pe base address error")]
    PEBaseAddressError,
    #[error("unsuported pe bitness id: {0}")]
    UnsupportedPEBitnessIDError(u16),
    #[error("invalid rule: {0} - {1}")]
    InvalidRule(u32, String),
    #[error("json format error: {0} - {1}")]
    JsonFormatError(&'static str, u32),
    #[error("operand error")]
    OperandError,
    #[error("collision error: {0}")]
    CollisionError(u64),
    #[error("dereference error: {0}")]
    DereferenceError(u64),
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("{0}")]
    FromSliceError(#[from] std::array::TryFromSliceError),
    #[error("utf convert error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("json parse error: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("decoder error: {0:?}")]
    DecodeError(iced_x86::DecoderError),
    #[error("{0}")]
    RegexError(#[from] regex::Error),
    #[error("{0}")]
    ParseError(#[from] goblin::error::Error),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("PE file has sections that map outside of the intended space")]
    PEOutOfBoundsSectionError,

    #[error("unsupported format")]
    UnsupportedFormatError,
    #[error("Not implemented")]
    NotImplementedError,

    /// Integer overflow/underflow on attacker-controlled arithmetic (e.g. a
    /// PE section header field). Distinct from `LogicError` because it
    /// signals "malformed input" rather than "smda bug".
    #[error("integer overflow in {0} (operands: {1}, {2})")]
    IntegerOverflow(&'static str, u64, u64),

    /// A value declared in the binary exceeds smda's safety cap (e.g. an ELF
    /// `p_memsz` that would require allocating gigabytes). Returning Err
    /// here is preferable to OOM-killing the host process.
    #[error("malformed input: {0} = {1} exceeds cap {2}")]
    MalformedInputError(&'static str, u64, u64),

    /// Analysis exceeded the configured wall-clock budget. Returned only
    /// when the caller used `parse_with_timeout` (or set
    /// `analysis_timeout` on the `Disassembler` directly). Partial state
    /// is discarded.
    #[error("analysis timeout exceeded ({0:?})")]
    AnalysisTimeout(std::time::Duration),
}

/// Cast a u64 from a parsed file field to usize, returning Err on truncation
/// (only matters on 32-bit targets, but cheap and centralises the audit).
#[inline]
pub fn try_usize(label: &'static str, x: u64) -> Result<usize, Error> {
    usize::try_from(x).map_err(|_| Error::IntegerOverflow(label, x, 0))
}

/// `a + b` returning Err on overflow.
#[inline]
pub fn safe_add(label: &'static str, a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::IntegerOverflow(label, a, b))
}

/// `a - b` returning Err on underflow.
#[inline]
pub fn safe_sub(label: &'static str, a: u64, b: u64) -> Result<u64, Error> {
    a.checked_sub(b).ok_or(Error::IntegerOverflow(label, a, b))
}
