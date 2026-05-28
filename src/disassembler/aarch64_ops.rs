//! Bit-level operand decoders for the AArch64 instruction families the
//! analysers need (jump-table heuristic + indirect-call register
//! tracking). All decoders work directly on the 32-bit instruction word
//! that `Aarch64Decoder` already stashes on `ArmInsn::opcode`, so callers
//! never have to round-trip through `disarm64`'s auto-generated operand-
//! class enums.
//!
//! Encodings are per the ARM Architecture Reference Manual (ARM ARM)
//! §C6.2 — section numbers in each doc comment point at the specific
//! page. Field layouts are unchanged across Armv8.0 → Armv9, so these
//! helpers stay stable across disarm64 v0.1.x bumps.
//!
//! Each helper returns `Option<…>` and yields `None` for any
//! instruction word outside its targeted family — callers therefore
//! get to use a simple `if let Some(…)` cascade instead of a giant
//! match-on-mnemonic. Decoders only validate the bit-pattern they
//! pattern-match on; they do **not** sanity-check operand legality
//! (e.g. SP/XZR ambiguity, qualifier mismatches) — that's the
//! caller's job when it matters.

/// AArch64 GPR number (0..=31). The number 31 means `XZR` / `WZR` /
/// `SP` depending on the instruction context (`Rd` of `ADD` uses SP,
/// `Rd` of `ORR` uses XZR — the difference is encoded by which
/// instruction class you've decoded).
pub type GprNum = u8;

/// `MOV (wide immediate)` flavour as encoded by the `opc` field at
/// bits\[30:29\] of the move-wide-immediate group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MovWideKind {
    /// `MOVN Rd, #imm16 LSL #(hw*16)` — zero the destination,
    /// then NOT the (shifted-immediate) result.
    Movn,
    /// `MOVZ Rd, #imm16 LSL #(hw*16)` — zero the destination,
    /// then write the shifted immediate.
    Movz,
    /// `MOVK Rd, #imm16 LSL #(hw*16)` — keep other bits of the
    /// destination; overwrite the 16-bit slot selected by `hw`.
    Movk,
}

/// `LDR (register offset)` / `LDRX (register offset)` decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdrRegOp {
    /// Destination register (`Rt`).
    pub rt: GprNum,
    /// Base register (`Rn`). SP-legal — context dependent.
    pub rn: GprNum,
    /// Index register (`Rm`).
    pub rm: GprNum,
    /// Shift amount applied to `Rm` before adding to base. 0 (no
    /// shift) or `S` ? log2(size) : 0 per ARM ARM. For LDR
    /// (64-bit) with `S=1` this is 3 (i.e. `LSL #3`).
    pub shift: u8,
    /// Access width in bytes (1, 2, 4, 8 — derived from the
    /// `size` field at bits\[31:30\]).
    pub size_bytes: u8,
}

/// `LDR/STR (unsigned immediate offset)` decode. Used for the LDR
/// half of the `ADRP + ADD + LDR` GOT-thunk pattern (e.g.
/// `LDR x16, [x17, #0x18]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdrUimmOp {
    /// Destination register (`Rt`).
    pub rt: GprNum,
    /// Base register (`Rn`).
    pub rn: GprNum,
    /// Offset added to `Rn` in *bytes* (already scaled by access size).
    pub offset: u64,
    /// Access width in bytes (1, 2, 4, 8).
    pub size_bytes: u8,
    /// `true` for STR, `false` for LDR (bit 22 of the encoding,
    /// inverted — `L=1` means load).
    pub is_store: bool,
}

// --- field extraction helpers ---------------------------------------

#[inline]
fn bits(insn: u32, hi: u8, lo: u8) -> u32 {
    debug_assert!(hi < 32 && lo <= hi);
    let width = hi - lo + 1;
    (insn >> lo) & ((1u32 << width) - 1)
}

#[inline]
fn sign_extend(value: u64, bits: u8) -> i64 {
    debug_assert!(bits > 0 && bits <= 64);
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

// --- PC-relative addressing (§C6.2.10 / §C6.2.11) -------------------

/// `ADRP Rd, label` (§C6.2.11). Encoding:
///   op (1) | immlo (2) | 1 0000 | immhi (19) | Rd (5)
/// where the 21-bit `imm21 = immhi:immlo` is sign-extended, shifted
/// left 12, and added to `pc & !0xFFF`. Returns `(Rd, target_page_va)`
/// on match, `None` otherwise.
#[must_use]
pub fn decode_adrp(insn: u32, pc: u64) -> Option<(GprNum, u64)> {
    // op=1 + fixed 10000 at bits\[28:24\]; mask 0x9F00_0000.
    if (insn & 0x9F00_0000) != 0x9000_0000 {
        return None;
    }
    let immlo = bits(insn, 30, 29) as u64;
    let immhi = bits(insn, 23, 5) as u64;
    let imm21 = (immhi << 2) | immlo;
    let offset = sign_extend(imm21, 21) << 12;
    let page_base = pc & !0xFFFu64;
    let target = page_base.wrapping_add(offset as u64);
    let rd = bits(insn, 4, 0) as GprNum;
    Some((rd, target))
}

// --- arithmetic immediate (§C6.2.5 / §C6.2.296) ---------------------

/// `ADD (immediate)` and `SUB (immediate)` (§C6.2.5 / §C6.2.296).
/// Encoding:
///   sf (1) | op (1) | S (1) | 1 0001 0 | sh (1) | imm12 (12) | Rn (5) | Rd (5)
/// Returns `(Rd, Rn, imm12_shifted, is_sub)` on match, `None`
/// otherwise. `imm12_shifted` already has the `sh=1` left-shift-by-12
/// applied. `S` (flag-setting variants `ADDS`/`SUBS`) is allowed.
#[must_use]
pub fn decode_add_sub_imm(insn: u32) -> Option<(GprNum, GprNum, u64, bool)> {
    // Fixed bits 28:24 = 10001, bit 23 reserved; mask = 0x1F00_0000
    // matches the data-processing-immediate group's add/sub-imm
    // subfamily.
    if (insn & 0x1F00_0000) != 0x1100_0000 {
        return None;
    }
    let sh = bits(insn, 22, 22);
    let imm12 = bits(insn, 21, 10) as u64;
    let imm = if sh == 1 { imm12 << 12 } else { imm12 };
    let rn = bits(insn, 9, 5) as GprNum;
    let rd = bits(insn, 4, 0) as GprNum;
    let is_sub = bits(insn, 30, 30) == 1;
    Some((rd, rn, imm, is_sub))
}

// --- move-wide-immediate (§C6.2.219 / §C6.2.220 / §C6.2.221) --------

/// `MOVN/MOVZ/MOVK Rd, #imm16 LSL #(hw*16)` family. Encoding:
///   sf (1) | opc (2) | 100101 | hw (2) | imm16 (16) | Rd (5)
/// Returns `(Rd, value, kind)` where `value` already has the `hw`
/// left-shift applied (and the bitwise-NOT for MOVN). For MOVK only
/// the 16-bit slot is meaningful — the caller has to merge with the
/// register's prior value.
#[must_use]
pub fn decode_mov_wide(insn: u32) -> Option<(GprNum, u64, MovWideKind)> {
    if (insn & 0x1F80_0000) != 0x1280_0000 {
        return None;
    }
    let opc = bits(insn, 30, 29);
    let kind = match opc {
        0b00 => MovWideKind::Movn,
        0b10 => MovWideKind::Movz,
        0b11 => MovWideKind::Movk,
        // opc=01 is reserved.
        _ => return None,
    };
    let hw = bits(insn, 22, 21) as u8;
    let imm16 = bits(insn, 20, 5) as u64;
    let value = match kind {
        MovWideKind::Movz | MovWideKind::Movk => imm16 << (hw as u64 * 16),
        MovWideKind::Movn => !(imm16 << (hw as u64 * 16)),
    };
    let rd = bits(insn, 4, 0) as GprNum;
    Some((rd, value, kind))
}

// --- register-only move (ORR alias, §C6.2.222) -----------------------

/// `MOV Rd, Rm` (an alias of `ORR Rd, XZR, Rm`). Decoded directly off
/// the ORR (shifted register) encoding when `Rn == 31` and shift = LSL #0.
/// Encoding (ORR shifted):
///   sf (1) | 01 01010 | shift (2) | N (1) | Rm (5) | imm6 (6) | Rn (5) | Rd (5)
/// We require `shift=00`, `N=0`, `imm6=000000`, and `Rn=31` (= XZR).
#[must_use]
pub fn decode_mov_reg(insn: u32) -> Option<(GprNum, GprNum)> {
    if (insn & 0x7FE0_FC00) != 0x2A00_0000 {
        return None;
    }
    let rn = bits(insn, 9, 5) as GprNum;
    if rn != 31 {
        return None;
    }
    let rd = bits(insn, 4, 0) as GprNum;
    let rm = bits(insn, 20, 16) as GprNum;
    Some((rd, rm))
}

// --- loads/stores (§C6.2.181 / §C6.2.347 / §C6.2.182 / §C6.2.348) ---

/// `LDR/STR (register, register offset)` — covers all four integer
/// access widths (`LDRB`/`LDRH`/`LDR W*`/`LDR X*`). Used by:
///   - `LDR Xn, [Xm, Xidx, LSL #3]` — switch table of u64 absolutes
///   - `LDRH Wn, [Xm, Xidx, LSL #1]` — switch table of u16 deltas (JT16)
///   - `LDRB Wn, [Xm, Xidx]` — switch table of u8 deltas (JT8)
///
/// Encoding:
///   size (2) | 111 | V (1) | 00 | opc (2) | 1 | Rm (5) | option (3) | S (1) | 10 | Rn (5) | Rt (5)
/// Returns `Some(LdrRegOp)` for any integer unsigned load (`V=0`, `opc=01`).
/// `size_bytes` reflects the access width (1, 2, 4, or 8).
#[must_use]
pub fn decode_ldr_reg(insn: u32) -> Option<LdrRegOp> {
    // Fixed bits via mask 0x3FE0_0C00 / value 0x3860_0800 isolate the
    // `LDR (register)` family: `opc=01` (unsigned load), `V=0`
    // (integer), fixed `1` at bit 21, fixed `10` at bits 11:10. The
    // size field at bits 31:30 is left to the caller to filter on.
    if (insn & 0x3FE0_0C00) != 0x3860_0800 {
        return None;
    }
    let size = bits(insn, 31, 30);
    let size_bytes: u8 = 1 << size;
    let rt = bits(insn, 4, 0) as GprNum;
    let rn = bits(insn, 9, 5) as GprNum;
    let rm = bits(insn, 20, 16) as GprNum;
    let s = bits(insn, 12, 12);
    let shift = if s == 1 { size } else { 0 };
    Some(LdrRegOp {
        rt,
        rn,
        rm,
        shift: shift as u8,
        size_bytes,
    })
}

/// `LDR/STR (unsigned 12-bit immediate offset)` — used in the
/// `ADRP + ADD + LDR` GOT-thunk pattern, e.g.
/// `LDR x16, [x17, #0x18]`. Encoding:
///   size (2) | 111 | V (1) | 01 | L (1) | 0 | imm12 (12) | Rn (5) | Rt (5)
/// `L=1` for LDR, `L=0` for STR. Returns `Some(LdrUimmOp)` for the
/// integer (`V=0`) family.
#[must_use]
pub fn decode_ldr_str_uimm(insn: u32) -> Option<LdrUimmOp> {
    if (insn & 0x3F00_0000) != 0x3900_0000 {
        return None;
    }
    // V at bit 26 must be 0 (integer, not SIMD/FP).
    if bits(insn, 26, 26) != 0 {
        return None;
    }
    let size = bits(insn, 31, 30);
    let size_bytes: u8 = 1 << size;
    let l = bits(insn, 22, 22);
    let imm12 = bits(insn, 21, 10) as u64;
    let offset = imm12 * (size_bytes as u64); // scale by access width
    let rn = bits(insn, 9, 5) as GprNum;
    let rt = bits(insn, 4, 0) as GprNum;
    Some(LdrUimmOp {
        rt,
        rn,
        offset,
        size_bytes,
        is_store: l == 0,
    })
}

// --- add (extended register) (§C6.2.6) ------------------------------

/// `ADD/SUB (extended register)` (§C6.2.6 / §C6.2.297). Used by GCC
/// switch-statement lowerings of the form
/// `ADD Xd, Xanchor, Wm, SXTB #2` (JT8) or
/// `ADD Xd, Xanchor, Wm, SXTH #2` (JT16) to combine a sign-extended
/// table-byte / -halfword with the function's anchor address.
///
/// Encoding:
///   sf (1) | op (1) | S (1) | 01011 | opt2 (2) | 1 | Rm (5) | option (3) | imm3 (3) | Rn (5) | Rd (5)
/// Mask 0xFF20_0000, value 0x8B20_0000 isolates the 64-bit add-ext
/// shape (`sf=1`, `op=0`, `opt2=00`, fixed `1` at bit 21).
///
/// `option` encodes the extension applied to `Rm`:
///   `000 UXTB`  `001 UXTH`  `010 UXTW`  `011 LSL`
///   `100 SXTB`  `101 SXTH`  `110 SXTW`  `111 SXTX`
/// `imm3` is the LSL amount applied after the extension (0..=4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddExtRegOp {
    pub rd: GprNum,
    pub rn: GprNum,
    pub rm: GprNum,
    /// Raw 3-bit option field; see the doc-comment table above.
    pub option: u8,
    /// LSL amount applied after the extension. 0..=4.
    pub shift: u8,
    /// `true` for SUB-extended (`op=1`), `false` for ADD-extended.
    pub is_sub: bool,
}

#[must_use]
pub fn decode_add_ext_reg(insn: u32) -> Option<AddExtRegOp> {
    if (insn & 0xFF20_0000) != 0x8B20_0000 {
        return None;
    }
    let is_sub = bits(insn, 30, 30) == 1;
    let rm = bits(insn, 20, 16) as GprNum;
    let option = bits(insn, 15, 13) as u8;
    let shift = bits(insn, 12, 10) as u8;
    let rn = bits(insn, 9, 5) as GprNum;
    let rd = bits(insn, 4, 0) as GprNum;
    Some(AddExtRegOp {
        rd,
        rn,
        rm,
        option,
        shift,
        is_sub,
    })
}

/// `ADR Rd, label` (§C6.2.10). Encoding mirrors ADRP but `op=0` and
/// the immediate is **not** shifted left by 12 — gives an exact
/// byte-granular PC-relative target. Compilers use it for the
/// anchor address in JT8/JT16 switch lowerings.
///
/// Encoding:
///   op=0 | immlo (2) | 1 0000 | immhi (19) | Rd (5)
/// Returns `(Rd, target_va)` on match.
#[must_use]
pub fn decode_adr(insn: u32, pc: u64) -> Option<(GprNum, u64)> {
    if (insn & 0x9F00_0000) != 0x1000_0000 {
        return None;
    }
    let immlo = bits(insn, 30, 29) as u64;
    let immhi = bits(insn, 23, 5) as u64;
    let imm21 = (immhi << 2) | immlo;
    let offset = sign_extend(imm21, 21);
    let target = (pc as i64).wrapping_add(offset) as u64;
    let rd = bits(insn, 4, 0) as GprNum;
    Some((rd, target))
}

// --- sign-extended loads (§C6.2.190 — LDRSW register variant) -------

/// `LDRSW Xt, [Xn, Xm{, LSL #2}]` — sign-extended 32-bit load with a
/// register-indexed offset. This is the load typically emitted by
/// Clang / GCC for a switch-statement jump table of 32-bit deltas
/// (each entry is `target - table_base` as `i32`; the consumer
/// sign-extends to 64-bit and adds the table base before branching).
///
/// Encoding:
///   1 0 111 0 00 1 0 1 Rm:5 option:3 S:1 1 0 Rn:5 Rt:5
/// Mask 0xFFE00C00, value 0xB8A00800.
///
/// `S=1` means the `LSL #2` shift is applied (i.e. byte-step = 4
/// matching the i32 access width); `S=0` means no shift. The
/// `option` field encodes the index register's extension (UXTW / LSL
/// / SXTW / SXTX); we only validate the bit-pattern shape and return
/// the index register number — callers that need the extension
/// semantics can re-read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdrswRegOp {
    pub rt: GprNum,
    pub rn: GprNum,
    pub rm: GprNum,
    /// `LSL` shift amount. 0 if `S=0`, else 2 (sign-extended 32-bit
    /// access width = 4, log2 = 2).
    pub shift: u8,
}

#[must_use]
pub fn decode_ldrsw_reg(insn: u32) -> Option<LdrswRegOp> {
    if (insn & 0xFFE0_0C00) != 0xB8A0_0800 {
        return None;
    }
    let rt = bits(insn, 4, 0) as GprNum;
    let rn = bits(insn, 9, 5) as GprNum;
    let rm = bits(insn, 20, 16) as GprNum;
    let s = bits(insn, 12, 12);
    let shift = if s == 1 { 2 } else { 0 };
    Some(LdrswRegOp { rt, rn, rm, shift })
}

// --- unconditional indirect branches (§C6.2.34 / §C6.2.35) ----------

/// `BR/BLR/RET Rn` (§C6.2.34 §C6.2.35 §C6.2.262). The mnemonic is
/// already disambiguated by the walker via `aarch64_is_indirect_branch`
/// / `aarch64_is_indirect_call` / `aarch64_is_return`; this helper
/// just extracts the target register field. Returns `Some(Rn)` for
/// any of those three families (including PAC variants — Rn is at
/// the same bit position).
#[must_use]
pub fn decode_branch_reg(insn: u32) -> Option<GprNum> {
    // Family mask: bits 31:25 = 1101011, bits 23:21 = 000 (unconditional
    // branch — register form). Mask 0xFE9F_FC00, value 0xD61F_0000 covers
    // BR/BLR/RET (opc at bits 24:21 picks the variant). PAC variants
    // share the same Rn field at bits 9:5.
    if (insn & 0xFE1F_FC00) != 0xD61F_0000 {
        return None;
    }
    Some(bits(insn, 9, 5) as GprNum)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity checks built off canonical encodings from real binaries
    // (or the ARM ARM examples). Each insn word is a literal u32 so
    // the test doubles as documentation of what bit-pattern decodes
    // to what semantics.

    #[test]
    fn adrp_decodes_pc_relative_page() {
        // adrp x0, #0x1000 at pc 0x4000 → page 0x5000, Rd=0.
        // imm21=1 → immlo=01 (bits 30:29), immhi=0 (bits 23:5).
        // Encoding: op=1, immlo=01, fixed=10000, immhi=0x0, Rd=00000.
        // Bits: 1 01 10000 0000000000000000000 00000 = 0xb000_0000
        let (rd, target) = decode_adrp(0xb000_0000, 0x4000).expect("adrp shape");
        assert_eq!(rd, 0);
        assert_eq!(target, 0x5000);
    }

    #[test]
    fn adrp_decodes_negative_offset() {
        // Cover the sign-extension path: adrp x1, #-0x1000 at pc 0x8000
        // → target page 0x7000. imm21 = -1 (0x1FFFFF after two's-complement
        // in 21 bits), immhi = 0x7FFFF, immlo = 11.
        // Encoding: bit31=1, bits30:29=11, bits28:24=10000,
        //           bits23:5=0x7FFFF, bits4:0=00001.
        // Bits: 1 11 10000 1111111111111111111 00001 = 0xf0ff_ffe1
        let (rd, target) = decode_adrp(0xf0ff_ffe1, 0x8000).expect("adrp shape");
        assert_eq!(rd, 1);
        assert_eq!(target, 0x7000);
    }

    #[test]
    fn add_imm_unshifted() {
        // add x0, x1, #0x20 → sf=1, op=0, S=0, sh=0, imm12=0x020, Rn=1, Rd=0
        // 1 0 0 10001 0 0 0000_0010_0000 00001 00000 = 0x9100_8020
        let (rd, rn, imm, is_sub) = decode_add_sub_imm(0x9100_8020).expect("add imm shape");
        assert_eq!(rd, 0);
        assert_eq!(rn, 1);
        assert_eq!(imm, 0x20);
        assert!(!is_sub);
    }

    #[test]
    fn mov_wide_movz_with_shift() {
        // movz x0, #0xabcd, lsl #16 → sf=1, opc=10, fixed=100101,
        //   hw=01, imm16=0xabcd, Rd=0
        // 1 10 100101 01 1010_1011_1100_1101 00000 = 0xd2b5_79a0
        let (rd, val, kind) = decode_mov_wide(0xd2b5_79a0).expect("movz shape");
        assert_eq!(rd, 0);
        assert_eq!(val, 0xabcd_0000);
        assert_eq!(kind, MovWideKind::Movz);
    }

    #[test]
    fn mov_reg_decodes_orr_xzr_alias() {
        // mov x0, x1 = orr x0, xzr, x1
        // Encoding (ORR shifted): sf=1, fixed=0101010, shift=00, N=0,
        //   Rm=1, imm6=0, Rn=31, Rd=0
        // 1 0101010 00 0 00001 000000 11111 00000 = 0xaa01_03e0
        let (rd, rm) = decode_mov_reg(0xaa01_03e0).expect("mov reg shape");
        assert_eq!(rd, 0);
        assert_eq!(rm, 1);
    }

    #[test]
    fn ldr_reg_decodes_lsl_3_64bit() {
        // ldr x0, [x1, x2, lsl #3] → size=11, V=0, opc=01, S=1
        // Encoding: 11 111 0 00 011 0 00010 011 1 10 00001 00000
        //         = 0xf862_7820
        let op = decode_ldr_reg(0xf862_7820).expect("ldr reg shape");
        assert_eq!(op.rt, 0);
        assert_eq!(op.rn, 1);
        assert_eq!(op.rm, 2);
        assert_eq!(op.size_bytes, 8);
        assert_eq!(op.shift, 3);
    }

    #[test]
    fn ldr_uimm_decodes_got_load() {
        // ldr x16, [x17, #0x18] → size=11, V=0, opc=01, L=1, imm12=3
        //   (0x18 / 8 = 3), Rn=17, Rt=16
        // 11 111 0 01 01 0 0000_0000_0011 10001 10000 = 0xf940_0e30
        let op = decode_ldr_str_uimm(0xf940_0e30).expect("ldr uimm shape");
        assert_eq!(op.rt, 16);
        assert_eq!(op.rn, 17);
        assert_eq!(op.offset, 0x18);
        assert_eq!(op.size_bytes, 8);
        assert!(!op.is_store);
    }

    #[test]
    fn ldr_reg_decodes_byte_load() {
        // ldrb w0, [x1, x2] → size=00, V=0, opc=01, S=0
        // Encoding: 00 111 0 00 01 1 00010 011 0 10 00001 00000
        //         = 0x3862_6820
        let op = decode_ldr_reg(0x3862_6820).expect("ldrb shape");
        assert_eq!(op.rt, 0);
        assert_eq!(op.rn, 1);
        assert_eq!(op.rm, 2);
        assert_eq!(op.size_bytes, 1);
        assert_eq!(op.shift, 0);
    }

    #[test]
    fn ldr_reg_decodes_halfword_load_lsl1() {
        // ldrh w0, [x1, x2, lsl #1] → size=01, V=0, opc=01, S=1
        // Encoding: 01 111 0 00 01 1 00010 011 1 10 00001 00000
        //         = 0x7862_7820
        let op = decode_ldr_reg(0x7862_7820).expect("ldrh shape");
        assert_eq!(op.rt, 0);
        assert_eq!(op.rn, 1);
        assert_eq!(op.rm, 2);
        assert_eq!(op.size_bytes, 2);
        assert_eq!(op.shift, 1);
    }

    #[test]
    fn add_ext_reg_decodes_sxtb_lsl2() {
        // add x3, x1, w2, sxtb #2 → sf=1, op=0, S=0, opt2=00,
        //   Rm=2, option=100 (SXTB), imm3=010, Rn=1, Rd=3
        // 1 0 0 01011 00 1 00010 100 010 00001 00011
        // = 0x8B22_8823
        let op = decode_add_ext_reg(0x8B22_8823).expect("add-ext shape");
        assert_eq!(op.rd, 3);
        assert_eq!(op.rn, 1);
        assert_eq!(op.rm, 2);
        assert_eq!(op.option, 0b100);
        assert_eq!(op.shift, 2);
        assert!(!op.is_sub);
    }

    #[test]
    fn adr_decodes_pc_relative_byte() {
        // adr x0, #+4 at pc 0x1000 → target 0x1004, Rd=0.
        // imm21 = 4: immlo=00 (bits 30:29), immhi=1 (bits 23:5).
        // Encoding: op=0, immlo=00, fixed=10000, immhi=0x1, Rd=0
        // Bits: 0 00 10000 0000000000000000001 00000
        //     = 0x1000_0020
        let (rd, target) = decode_adr(0x1000_0020, 0x1000).expect("adr shape");
        assert_eq!(rd, 0);
        assert_eq!(target, 0x1004);
    }

    #[test]
    fn ldrsw_reg_decodes_lsl_2() {
        // ldrsw x9, [x8, x9, lsl #2] → opc=10, size=10, V=0, S=1
        // Rt=9, Rn=8, Rm=9, option=011 (LSL), S=1
        // Encoding: 10 111 0 00 10 1 0 1001 011 1 10 01000 01001
        //         = 0xb8a9_7909
        let op = decode_ldrsw_reg(0xb8a9_7909).expect("ldrsw shape");
        assert_eq!(op.rt, 9);
        assert_eq!(op.rn, 8);
        assert_eq!(op.rm, 9);
        assert_eq!(op.shift, 2);
    }

    #[test]
    fn br_decodes_register() {
        // br x16 → 1101011 0 0 00 11111 0000 00 10000 00000 = 0xd61f_0200
        assert_eq!(decode_branch_reg(0xd61f_0200), Some(16));
    }

    #[test]
    fn blr_decodes_register() {
        // blr x17 → 1101011 0 0 01 11111 0000 00 10001 00000 = 0xd63f_0220
        assert_eq!(decode_branch_reg(0xd63f_0220), Some(17));
    }
}
