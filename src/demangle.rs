//! Symbol demangling helpers (0.4.2 N3).
//!
//! Currently wraps `rustc-demangle` for Rust legacy (`_ZN…`) and v0
//! (`_R…`) mangled names. C++ Itanium and MSVC mangling are not yet
//! covered — adding them would pull in heavier deps (`cpp_demangle`,
//! `msvc-demangler`) and is deferred until a consumer asks for it.
//!
//! All helpers are pure functions that take a `&str` and return an
//! owned `String`. Demangling failures fall through to the raw input
//! unchanged (so non-Rust symbols round-trip safely).

/// Attempt to demangle `raw` as a Rust symbol. Returns the demangled form
/// without hash suffix if the input parses; otherwise returns `raw` as
/// an owned String.
///
/// Cheap to call on every symbol: `rustc_demangle::try_demangle` is a
/// few comparisons and returns `Err` immediately for non-Rust inputs.
#[must_use]
pub fn maybe_demangle(raw: &str) -> String {
    match rustc_demangle::try_demangle(raw) {
        Ok(d) => format!("{:#}", d),
        Err(_) => raw.to_string(),
    }
}
