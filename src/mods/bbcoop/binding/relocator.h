// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace BBCoop::Binding {

/// The length in bytes of the shortest run of whole instructions at the start of `code` that
/// covers at least `min_bytes` (0 for min_bytes == 0). Fails when an instruction cannot be decoded
/// or `code` ends before `min_bytes` are covered.
///
/// This is only length arithmetic over a linear decode. It does not know where the function ends
/// (it steps over RET and unconditional jumps) and does not check that the instructions can be
/// relocated; RelocateInstructions does that.
std::expected<std::size_t, std::string> StealLength(std::span<const std::uint8_t> code,
                                                    std::size_t min_bytes);

/// The offset of the first unconditional control transfer (RET, IRET, JMP, UD0/UD1/UD2, INT3, HLT)
/// in `code` that is not its last instruction; nullopt when there is none. The bytes after such an
/// instruction are only reached by a jump to them (often they are the next function), so a hook
/// must not steal them: a function shorter than the stolen length ends inside the region. Fails
/// when `code` does not decode as whole instructions.
std::expected<std::optional<std::size_t>, std::string> FindEarlyControlTransfer(
    std::span<const std::uint8_t> code);

struct ControlTransferScan {
    /// What FindEarlyControlTransfer returns.
    std::optional<std::size_t> early;
    /// The last instruction is an unconditional control transfer (same set). Running the code ends
    /// there, so continuing at the first byte after `code` without running it (a detour's
    /// SkipStolen) would run past the end of the function.
    bool ends_with_transfer = false;
};

/// FindEarlyControlTransfer plus whether `code` ends with an unconditional control transfer.
std::expected<ControlTransferScan, std::string> ScanControlTransfers(
    std::span<const std::uint8_t> code);

/// Re-encodes `code`, which sits at `source_address`, to run from `target_address`: RIP-relative
/// operands and relative jumps and calls keep their original targets. Short jcc/jmp are widened
/// to rel32 when the new target needs it.
///
/// Fails, and returns no bytes, for code that cannot be moved into a trampoline:
///  - instructions the emulator rewrites lazily in place (FS/GS segment access and the SSE4a
///    EXTRQ, INSERTQ, MOVNTSS, MOVNTSD), because a trampoline copy would never be rewritten.
///    The segment check covers every operand, hidden ones too: a string operation or XLAT with an
///    FS/GS prefix is rejected as well;
///  - EIP-relative addressing (0x67 prefix), whose 32-bit wrap-around cannot be preserved;
///  - a relative branch into the middle of `code`, which the hook's jump will overwrite (a branch
///    to its first byte or to the first byte after it is fine);
///  - an instruction whose re-encoded form does not reach its target from `target_address`
///    (for example JRCXZ and LOOP, which exist only with an 8-bit displacement, or a RIP-relative
///    operand more than 2 GiB away).
/// Bytes that do not decode as whole instructions are rejected as well.
///
/// Not checked: a RIP-relative data reference that points INTO `code` itself. The relocated
/// instruction keeps the original address, which is overwritten by the hook's jump, so it would
/// read the jump's bytes. Callers must not steal bytes that the relocated code reads.
std::expected<std::vector<std::uint8_t>, std::string> RelocateInstructions(
    std::span<const std::uint8_t> code, std::uint64_t source_address, std::uint64_t target_address);

} // namespace BBCoop::Binding
