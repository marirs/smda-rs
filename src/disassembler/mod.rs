//! Architecture-agnostic decoder abstraction (smda-rs 0.6.0).
//!
//! Pre-0.6.0 the analyser reached straight through `DecodedInsn.iced`
//! into iced-x86's `Instruction` for every typed query. That coupling
//! made adding a second ISA impossible without rewriting every analyser
//! callsite. 0.6.0 splits the decoder behind a small trait, makes
//! `DecodedInsn` an enum over (x86, AArch64), and pushes per-arch
//! typed-accessor methods onto the enum.
//!
//! Two backends ship in 0.6.0:
//! - [`X86Decoder`] — wraps `iced_x86::Decoder`. Variable-width
//!   (1–15 bytes), 32 / 64-bit modes.
//! - [`Aarch64Decoder`] — wraps `disarm64::decoder::decode`. Fixed
//!   4-byte instructions, 64-bit only.
//!
//! Analyser callsites use the typed accessors on [`DecodedInsn`]
//! ([`DecodedInsn::mnemonic_enum_x86`], [`DecodedInsn::op_count`], …).
//! Accessors that only make sense on x86 carry an `_x86` suffix and
//! return `Option` — they yield `None` on AArch64. Arch-agnostic helpers
//! ([`DecodedInsn::is_call`], [`DecodedInsn::is_jump`],
//! [`DecodedInsn::is_return`], [`DecodedInsn::is_branch`]) dispatch
//! internally.
//!
//! The x86-only heuristics (jump-table, indirect-call, tail-call,
//! function-candidate alignment, exit-syscall) are gated to skip on
//! AArch64 in 0.6.0; richer AArch64 analyser support arrives in 0.6.1.

use crate::{BinaryInfo, Result};
// `Formatter` brings the `options_mut` / `format` trait methods into
// scope for `IntelFormatter`. iced exposes these via the trait, not as
// inherent methods on the formatter struct.
use iced_x86::{Formatter, IntelFormatter};

// 0.6.1: minimal structured-operand decoders for the AArch64 families
// the jump-table + indirect-call analysers care about. Lives in a
// sibling file so the operand bit-extraction grows independently of
// the trait/decoder plumbing in this module.
pub mod aarch64_ops;

/// Configure an `IntelFormatter` to emit capstone-compatible output:
/// lowercase hex with `0x` prefix, `dword ptr` / `qword ptr` size prefixes,
/// space around `+` / `-` in memory operands, and `, ` between operands.
/// Lives here (not on `function.rs`) so [`DecodedInsn::format_mnemonic`]
/// can use it without `function.rs` ⇄ `disassembler` cycling.
#[must_use]
pub fn capstone_compat_formatter() -> IntelFormatter {
    let mut fmt = IntelFormatter::new();
    let opts = fmt.options_mut();
    opts.set_hex_prefix("0x");
    opts.set_hex_suffix("");
    opts.set_uppercase_hex(false);
    opts.set_small_hex_numbers_in_decimal(false);
    opts.set_add_leading_zero_to_hex_numbers(false);
    opts.set_space_after_operand_separator(true);
    opts.set_space_between_memory_add_operators(true);
    opts.set_space_between_memory_mul_operators(false);
    opts.set_uppercase_mnemonics(false);
    opts.set_uppercase_registers(false);
    opts.set_uppercase_keywords(false);
    opts.set_uppercase_decorators(false);
    opts.set_uppercase_prefixes(false);
    opts.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    fmt
}

/// Architecture-agnostic decoder interface. One implementation per
/// supported ISA. The analyser carries a `Box<dyn Decoder>` (Send +
/// Sync) so it can decode either an x86 byte stream or an AArch64 word
/// stream uniformly.
pub trait Decoder: Send + Sync {
    /// Decode one instruction starting at byte offset `offset` inside
    /// `code`, assuming the instruction's virtual address is `address`.
    /// Returns `(DecodedInsn, consumed_bytes)` on success, `None` on
    /// invalid encoding or short buffer.
    fn decode_at(&self, code: &[u8], offset: usize, address: u64) -> Option<(DecodedInsn, usize)>;

    /// For fixed-width ISAs (AArch64 → `Some(4)`, RISC-V → `Some(2/4)`
    /// once supported), return the encoded width. `None` for variable-
    /// width ISAs (x86). Used by the candidate scanner to align the
    /// gap-walk on fixed-width archs.
    fn fixed_instruction_size(&self) -> Option<usize>;
}

// --- x86 backend ----------------------------------------------------------

/// x86 / x86-64 decoder backend. Bitness is fixed at construction
/// (32 or 64).
#[derive(Debug, Clone, Copy)]
pub struct X86Decoder {
    pub bitness: u32,
}

impl X86Decoder {
    #[must_use]
    pub fn new(bitness: u32) -> Self {
        Self { bitness }
    }
}

impl Decoder for X86Decoder {
    fn decode_at(&self, code: &[u8], offset: usize, address: u64) -> Option<(DecodedInsn, usize)> {
        let buf = code.get(offset..)?;
        if buf.is_empty() {
            return None;
        }
        let mut dec =
            iced_x86::Decoder::with_ip(self.bitness, buf, address, iced_x86::DecoderOptions::NONE);
        if !dec.can_decode() {
            return None;
        }
        let pos_before = dec.position();
        let insn = dec.decode();
        if insn.is_invalid() {
            return None;
        }
        let len = dec.position() - pos_before;
        Some((
            DecodedInsn::X86(IcedInsn {
                offset: insn.ip(),
                length: len as u32,
                iced: insn,
            }),
            len,
        ))
    }

    fn fixed_instruction_size(&self) -> Option<usize> {
        None
    }
}

// --- AArch64 backend ------------------------------------------------------

/// AArch64 decoder backend, powered by disarm64. Fixed 4-byte
/// instructions, 64-bit only.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aarch64Decoder;

impl Aarch64Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for Aarch64Decoder {
    fn decode_at(&self, code: &[u8], offset: usize, address: u64) -> Option<(DecodedInsn, usize)> {
        let slice = code.get(offset..offset.checked_add(4)?)?;
        let opcode = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let decoded = disarm64::decoder::decode(opcode)?;
        Some((
            DecodedInsn::Aarch64(ArmInsn {
                offset: address,
                opcode,
                decoded,
            }),
            4,
        ))
    }

    fn fixed_instruction_size(&self) -> Option<usize> {
        Some(4)
    }
}

// --- DecodedInsn enum -----------------------------------------------------

/// One x86 decode + bookkeeping. `Copy` because iced::Instruction is
/// 16 bytes and `Copy`.
#[derive(Debug, Clone, Copy)]
pub struct IcedInsn {
    pub offset: u64,
    pub length: u32,
    pub iced: iced_x86::Instruction,
}

/// One AArch64 decode + bookkeeping. The raw `u32` opcode is retained
/// alongside the structured `disarm64::decoder::Opcode` so analysers
/// can compare bit-patterns directly when the typed surface doesn't
/// expose the field they need.
#[derive(Debug, Clone, Copy)]
pub struct ArmInsn {
    pub offset: u64,
    pub opcode: u32,
    pub decoded: disarm64::decoder::Opcode,
}

/// Carrier passed between the disassembler core and the analysers.
/// Replaces the 0.5.x struct that held a `pub iced` field unconditionally.
///
/// All fixed-width AArch64 instructions are 4 bytes; x86 instructions
/// are 1–15 bytes (the iced max). The accessors on this enum take the
/// place of the old `.iced.X` reach-through pattern.
#[derive(Debug, Clone, Copy)]
pub enum DecodedInsn {
    X86(IcedInsn),
    Aarch64(ArmInsn),
}

impl DecodedInsn {
    // --- arch-agnostic basics --------------------------------------------

    #[inline]
    #[must_use]
    pub fn offset(&self) -> u64 {
        match self {
            DecodedInsn::X86(i) => i.offset,
            DecodedInsn::Aarch64(i) => i.offset,
        }
    }

    #[inline]
    #[must_use]
    pub fn length(&self) -> usize {
        match self {
            DecodedInsn::X86(i) => i.length as usize,
            DecodedInsn::Aarch64(_) => 4,
        }
    }

    /// Look up the raw instruction bytes via the owning `BinaryInfo`.
    pub fn bytes_in<'b>(&self, binary_info: &'b BinaryInfo<'_>) -> Result<&'b [u8]> {
        binary_info.bytes_at(self.offset(), self.length() as u32)
    }

    // --- mnemonic ---------------------------------------------------------

    /// iced `Mnemonic` enum, or `None` on AArch64.
    #[inline]
    #[must_use]
    pub fn mnemonic_enum_x86(&self) -> Option<iced_x86::Mnemonic> {
        match self {
            DecodedInsn::X86(i) => Some(i.iced.mnemonic()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    /// Lower-case mnemonic string for the AArch64 instruction, or
    /// `None` on x86. Allocates per call — pulled via Debug-format
    /// over the disarm64 `Mnemonic` enum, with the `r#` raw-ident
    /// prefix stripped. Stable across disarm64 v0.1.x because the
    /// variant names come from the upstream ARM ARM JSON.
    #[must_use]
    pub fn mnemonic_aarch64(&self) -> Option<String> {
        match self {
            DecodedInsn::X86(_) => None,
            DecodedInsn::Aarch64(a) => Some(aarch64_mnemonic_str(&a.decoded)),
        }
    }

    // --- operand count + typed (x86-only) --------------------------------

    #[inline]
    #[must_use]
    pub fn op_count(&self) -> u32 {
        match self {
            DecodedInsn::X86(i) => i.iced.op_count(),
            // disarm64 doesn't surface an operand count cheaply; treat
            // every AArch64 instruction as opaque from the analyser
            // (legacy x86-only analysers gate before walking operands).
            DecodedInsn::Aarch64(_) => 0,
        }
    }

    #[inline]
    #[must_use]
    pub fn op_kind_x86(&self, i: u32) -> Option<iced_x86::OpKind> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.op_kind(i)),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn op_register_x86(&self, i: u32) -> Option<iced_x86::Register> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.op_register(i)),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn memory_base_x86(&self) -> Option<iced_x86::Register> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.memory_base()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn memory_index_x86(&self) -> Option<iced_x86::Register> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.memory_index()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn memory_segment_x86(&self) -> Option<iced_x86::Register> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.memory_segment()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn memory_displacement64_x86(&self) -> Option<u64> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.memory_displacement64()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn near_branch_target_x86(&self) -> Option<u64> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.near_branch_target()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn flow_control_x86(&self) -> Option<iced_x86::FlowControl> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.flow_control()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub fn code_x86(&self) -> Option<iced_x86::Code> {
        match self {
            DecodedInsn::X86(x) => Some(x.iced.code()),
            DecodedInsn::Aarch64(_) => None,
        }
    }

    // --- arch-agnostic control-flow helpers ------------------------------

    /// True for any call-like flow control. On AArch64 this maps to
    /// `bl` / `blr` mnemonics.
    #[must_use]
    pub fn is_call(&self) -> bool {
        match self {
            DecodedInsn::X86(x) => matches!(
                x.iced.flow_control(),
                iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall
            ),
            DecodedInsn::Aarch64(a) => matches!(
                a.decoded.mnemonic,
                disarm64::decoder::Mnemonic::bl | disarm64::decoder::Mnemonic::blr
            ),
        }
    }

    /// True for any jump-like flow control (excluding returns and
    /// conditional branches — those are exposed separately by
    /// [`Self::is_return`] / the analyser's own conditional path).
    #[must_use]
    pub fn is_jump(&self) -> bool {
        match self {
            DecodedInsn::X86(x) => matches!(
                x.iced.flow_control(),
                iced_x86::FlowControl::UnconditionalBranch | iced_x86::FlowControl::IndirectBranch
            ),
            DecodedInsn::Aarch64(a) => matches!(
                a.decoded.mnemonic,
                disarm64::decoder::Mnemonic::b | disarm64::decoder::Mnemonic::br
            ),
        }
    }

    /// True for return-like control flow. On AArch64: `ret`.
    #[must_use]
    pub fn is_return(&self) -> bool {
        match self {
            DecodedInsn::X86(x) => {
                matches!(x.iced.flow_control(), iced_x86::FlowControl::Return)
            }
            DecodedInsn::Aarch64(a) => {
                matches!(a.decoded.mnemonic, disarm64::decoder::Mnemonic::ret)
            }
        }
    }

    /// True for any branch-family instruction: call, unconditional /
    /// indirect jump, conditional branch, or return. Useful for
    /// arch-agnostic block-ending detection. Conditional branches on
    /// AArch64 (`b.cond`) all share the `b_cond` variant in disarm64's
    /// table — see the helper below.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        match self {
            DecodedInsn::X86(x) => !matches!(
                x.iced.flow_control(),
                iced_x86::FlowControl::Next | iced_x86::FlowControl::Exception
            ),
            DecodedInsn::Aarch64(a) => is_aarch64_branch_mnemonic(a.decoded.mnemonic),
        }
    }

    // --- formatting -------------------------------------------------------

    /// Capstone-compatible mnemonic string. For x86 this goes through
    /// the configured `IntelFormatter`; for AArch64 it returns
    /// disarm64's lower-case mnemonic name.
    #[must_use]
    pub fn format_mnemonic(&self) -> String {
        match self {
            DecodedInsn::X86(x) => {
                use iced_x86::Formatter;
                let mut fmt = capstone_compat_formatter();
                let mut out = String::new();
                fmt.format_mnemonic(&x.iced, &mut out);
                out
            }
            DecodedInsn::Aarch64(a) => aarch64_mnemonic_str(&a.decoded),
        }
    }

    /// Formatted operand string, or `None` for zero-operand
    /// instructions. AArch64 returns the disarm64 `Debug` rendering —
    /// adequate for diagnostics; structured operand access lands in
    /// 0.6.1.
    #[must_use]
    pub fn format_operands(&self) -> Option<String> {
        match self {
            DecodedInsn::X86(x) => {
                if x.iced.op_count() == 0 {
                    return None;
                }
                use iced_x86::Formatter;
                let mut fmt = capstone_compat_formatter();
                let mut out = String::new();
                fmt.format_all_operands(&x.iced, &mut out);
                Some(out)
            }
            DecodedInsn::Aarch64(a) => Some(format!("{:?}", a.decoded.operation)),
        }
    }

    // --- analyser shims --------------------------------------------------

    /// Convenience for callers that need the underlying iced
    /// instruction (e.g. PIC-hash signature emission). Returns `None`
    /// on AArch64.
    #[inline]
    #[must_use]
    pub fn as_iced(&self) -> Option<&iced_x86::Instruction> {
        match self {
            DecodedInsn::X86(x) => Some(&x.iced),
            DecodedInsn::Aarch64(_) => None,
        }
    }
}

/// Internal — render the lower-case mnemonic name from a
/// `disarm64::decoder::Opcode`. disarm64's `Mnemonic` is an enum
/// whose variants use Rust raw-identifier names (`r#b`, `r#abs`, …);
/// we Debug-format and strip the leading `r#` prefix. The empty
/// `r#b_` variant is rewritten to `b.cond` for downstream-friendly
/// rendering.
fn aarch64_mnemonic_str(op: &disarm64::decoder::Opcode) -> String {
    let dbg = format!("{:?}", op.mnemonic);
    let stripped = dbg.strip_prefix("r#").unwrap_or(&dbg);
    if stripped == "b_" {
        return "b.cond".to_string();
    }
    stripped.to_string()
}

/// Internal — true if the disarm64 mnemonic is any branch-family
/// instruction. Used by `DecodedInsn::is_branch`. Kept as a direct
/// enum match for speed (the analyser's per-instruction hot path
/// runs through it).
#[inline]
fn is_aarch64_branch_mnemonic(m: disarm64::decoder::Mnemonic) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(
        m,
        M::b | M::bl | M::br | M::blr | M::ret | M::r#b_ | M::cbz | M::cbnz | M::tbz | M::tbnz
    )
}

// --- AArch64 control-flow helpers (0.6.0) --------------------------------
//
// Direct-branch target extraction. Pre-computes the PC-relative
// destination for B / BL / B.cond / CBZ / CBNZ / TBZ / TBNZ given the
// raw 32-bit instruction word and the instruction's PC (its own VA).
// Indirect branches (BR / BLR), returns (RET / RETAA / RETAB / ERET /
// DRPS), and non-branch opcodes return `None`.
//
// Encodings come from ARM ARM §C6.2 (branch / exception instructions).
// We work directly on the raw u32 (already stashed in `ArmInsn.opcode`)
// because the disarm64 leaf-variant tuples don't surface the imm field
// as a public typed accessor — only the raw bits via the `InsnOpcode`
// trait. Going through the raw word side-steps the trait dance and
// keeps the imm decode self-contained.

/// Sign-extend an unsigned value carried in the low `bits` bits of
/// `value` to a signed `i64`. `bits` must be in `1..=63`.
#[inline]
fn sign_extend(value: u64, bits: u32) -> i64 {
    debug_assert!((1..=63).contains(&bits));
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// AArch64 direct-branch target resolver. Returns `Some(target_va)`
/// for B / BL / B.cond / BC / CBZ / CBNZ / TBZ / TBNZ at the given
/// `pc`; `None` for indirect branches (BR / BLR), returns (RET / …),
/// and any non-branch opcode.
///
/// Encodings (ARM ARM §C6.2):
/// - `BRANCH_IMM` (B / BL): bits \[25:0\] are signed imm26;
///   `target = pc + sign_extend(imm26) << 2`.
/// - `CONDBRANCH` (B.cond / BC.cond): bits \[23:5\] are signed imm19;
///   `target = pc + sign_extend(imm19) << 2`.
/// - `COMPBRANCH` (CBZ / CBNZ): bits \[23:5\] are signed imm19;
///   `target = pc + sign_extend(imm19) << 2`.
/// - `TESTBRANCH` (TBZ / TBNZ): bits \[18:5\] are signed imm14;
///   `target = pc + sign_extend(imm14) << 2`.
#[must_use]
pub fn aarch64_branch_target(opcode: &disarm64::decoder::Opcode, pc: u64) -> Option<u64> {
    // We don't have a public accessor on the leaf-variant tuples
    // (only the trait-based `bits()` on the variants — which would
    // pull in the disarm64_defn trait). Pattern-match the operation
    // family to choose the imm width, then decode straight from the
    // raw u32 that `Aarch64Decoder` already retained on `ArmInsn`.
    // The caller supplies the raw word via a helper below.
    let raw = aarch64_raw_word(opcode)?;
    aarch64_branch_target_raw(opcode, raw, pc)
}

/// Variant of [`aarch64_branch_target`] that takes the raw 32-bit
/// instruction word explicitly. `ArmInsn` carries this on every
/// decode, so analysers can use it directly without paying the
/// trait-dispatch dance in `aarch64_raw_word` (private helper).
#[must_use]
pub fn aarch64_branch_target_raw(
    opcode: &disarm64::decoder::Opcode,
    raw: u32,
    pc: u64,
) -> Option<u64> {
    use disarm64::decoder::Operation;
    let raw = raw as u64;
    let offset = match opcode.operation {
        // B / BL: imm26 in bits[25:0].
        Operation::BRANCH_IMM(_) => {
            let imm26 = raw & 0x03ff_ffff;
            sign_extend(imm26, 26) << 2
        }
        // B.cond / BC.cond and CBZ/CBNZ: imm19 in bits[23:5].
        Operation::CONDBRANCH(_) | Operation::COMPBRANCH(_) => {
            let imm19 = (raw >> 5) & 0x0007_ffff;
            sign_extend(imm19, 19) << 2
        }
        // TBZ / TBNZ: imm14 in bits[18:5].
        Operation::TESTBRANCH(_) => {
            let imm14 = (raw >> 5) & 0x0000_3fff;
            sign_extend(imm14, 14) << 2
        }
        _ => return None,
    };
    Some(pc.wrapping_add(offset as u64))
}

/// Internal — reconstruct the raw 32-bit instruction word from a
/// `disarm64::decoder::Opcode`. The structured operand types don't
/// expose a public typed-imm accessor, but the upstream `InsnOpcode`
/// trait does expose `.bits()` returning the encoded word. We pull
/// that in through a transient import so callers that already have
/// only an `Opcode` (not an `ArmInsn`) can still decode targets.
fn aarch64_raw_word(opcode: &disarm64::decoder::Opcode) -> Option<u32> {
    use disarm64_defn::defn::InsnOpcode;
    Some(opcode.bits())
}

/// True iff the AArch64 instruction is a direct call (BL with PC-
/// relative imm26). BLR (indirect) is excluded — analysers that
/// need both should also check [`DecodedInsn::is_call`].
#[inline]
#[must_use]
pub fn aarch64_is_direct_call(opcode: &disarm64::decoder::Opcode) -> bool {
    matches!(opcode.mnemonic, disarm64::decoder::Mnemonic::bl)
}

/// True iff the AArch64 instruction is an unconditional direct
/// branch (B with PC-relative imm26). `BR <reg>` is excluded —
/// indirect jumps need register tracking, deferred to 0.6.1.
#[inline]
#[must_use]
pub fn aarch64_is_unconditional_branch(opcode: &disarm64::decoder::Opcode) -> bool {
    matches!(opcode.mnemonic, disarm64::decoder::Mnemonic::b)
}

/// True iff the AArch64 instruction is a conditional branch:
/// `B.cond` (CONDBRANCH), `CBZ` / `CBNZ` (COMPBRANCH), or
/// `TBZ` / `TBNZ` (TESTBRANCH). All have direct PC-relative
/// destinations resolvable via [`aarch64_branch_target_raw`].
#[inline]
#[must_use]
pub fn aarch64_is_conditional_branch(opcode: &disarm64::decoder::Opcode) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(
        opcode.mnemonic,
        M::r#b_ | M::cbz | M::cbnz | M::tbz | M::tbnz
    )
}

/// True iff the AArch64 instruction is a return: `RET` (with a
/// register operand) or any of the pointer-auth-protected return
/// variants (`RETAA` / `RETAB`) or `ERET` family. Indirect by
/// definition — these end a function.
#[inline]
#[must_use]
pub fn aarch64_is_return(opcode: &disarm64::decoder::Opcode) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(
        opcode.mnemonic,
        M::ret | M::eret | M::retaa | M::retab | M::eretaa | M::eretab | M::drps
    )
}

/// True iff the AArch64 instruction is an *indirect* branch — `BR <reg>`
/// or any of its pointer-auth-protected variants
/// (`BRAA` / `BRAAZ` / `BRAB` / `BRABZ`). All end the current basic
/// block (and, for the walker, the current function unless another
/// edge re-enters): the destination is a runtime register value, not
/// a PC-relative immediate, so we cannot follow it without register
/// tracking. Distinct from [`aarch64_is_indirect_call`] which falls
/// through to the next instruction.
#[inline]
#[must_use]
pub fn aarch64_is_indirect_branch(opcode: &disarm64::decoder::Opcode) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(
        opcode.mnemonic,
        M::br | M::braa | M::braaz | M::brab | M::brabz
    )
}

/// True iff the AArch64 instruction is an *indirect* call — `BLR <reg>`
/// or any of its pointer-auth-protected variants
/// (`BLRAA` / `BLRAAZ` / `BLRAB` / `BLRABZ`). Returns to the caller
/// via `LR`, so execution falls through to the next instruction.
#[inline]
#[must_use]
pub fn aarch64_is_indirect_call(opcode: &disarm64::decoder::Opcode) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(
        opcode.mnemonic,
        M::blr | M::blraa | M::blraaz | M::blrab | M::blrabz
    )
}

/// True iff the AArch64 instruction is an unconditional trap that
/// terminates straight-line execution: `UDF` (undefined / permanently
/// trapping), `BRK` (software breakpoint), or `HLT` (debug halt).
/// Compilers emit these after `noreturn` calls or as bounds-check
/// poison; the walker must stop here rather than decoding the
/// constant-pool word that typically follows.
#[inline]
#[must_use]
pub fn aarch64_is_trap(opcode: &disarm64::decoder::Opcode) -> bool {
    use disarm64::decoder::Mnemonic as M;
    matches!(opcode.mnemonic, M::udf | M::brk | M::hlt)
}

/// True iff the AArch64 instruction is a supervisor call (`SVC #imm16`,
/// ARM ARM §C6.2.279) — the Linux syscall entry point on AArch64. The
/// walker pairs this with prior-`x8`-immediate tracking to spot
/// `exit` / `exit_group` (syscall numbers 93 / 94) and end the function.
#[inline]
#[must_use]
pub fn aarch64_is_svc(opcode: &disarm64::decoder::Opcode) -> bool {
    matches!(opcode.mnemonic, disarm64::decoder::Mnemonic::svc)
}
