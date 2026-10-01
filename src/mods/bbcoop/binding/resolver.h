// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Zydis/Zydis.h>

namespace BBCoop::Binding {

enum class SymbolKind : std::uint8_t { Function, Site, Global, Data, Patch };

/// How the result is derived from the pattern match.
enum class TargetMode : std::uint8_t {
    Match,           ///< target = match + operand_offset.
    RelativeOperand, ///< Decode the instruction at match + operand_offset and take the absolute
                     ///< target of its first [rip+disp] operand or relative immediate (call/jmp/jcc).
};

/// The most bytes a hook may overwrite at a code symbol: the detour's limit (BuildDetour), and the
/// window sigmaker searches for branch targets (SymbolSpec::max_steal).
constexpr std::uint8_t kMaxHookSteal = 16;

struct SymbolSpec {
    std::string_view name;
    SymbolKind kind;
    bool required;
    std::uint64_t target_rva;    ///< Expected result on the reference image.
    std::uint64_t match_rva;     ///< Where the pattern matches on the reference image.
    std::int32_t operand_offset; ///< See TargetMode.
    TargetMode mode;
    std::string_view pattern;
    /// How many bytes from the symbol a hook may overwrite (PlanHooks refuses longer steals).
    /// Function, Site, Patch: the distance from target_rva to the nearest target of a direct
    /// branch (jmp, jcc, call, loop, jrcxz) inside (target_rva, target_rva + kMaxHookSteal], over
    /// every complete function of the reference image; kMaxHookSteal when there is none. A jump
    /// to such a target would land inside the hook's own jump. Computed by tools/re/sigmaker.
    /// Not covered: indirect jumps and calls (jump tables, function pointers), whose targets are
    /// not in the code. Global, Data: 0 (not hookable). The default 0 refuses every hook.
    std::uint8_t max_steal = 0;
};

/// The executable segment of the loaded image. With is_reference_image set (the caller has verified
/// the fingerprint of the known-good image) each pattern is checked only at match_rva and the result
/// must equal target_rva; otherwise every pattern is scanned over the whole text and must match once.
struct ImageView {
    std::span<const std::uint8_t> text;
    std::uint64_t text_rva;
    bool is_reference_image;
};

enum class ResolveError : std::uint8_t {
    BadPattern,   ///< The pattern text does not parse.
    NotFound,     ///< Scan mode: no match.
    Ambiguous,    ///< Scan mode: more than one match.
    HintMismatch, ///< Reference mode: no match at match_rva, or the result differs from target_rva.
    BadOperand,   ///< RelativeOperand: the instruction is outside the text, cut off, undecodable, or
                  ///< has no RIP-relative / relative operand.
    OutOfText,    ///< A Function, Site or Patch target lies outside the executable segment (in
                  ///< either mode); Global and Data targets may lie anywhere.
    ZeroRva,      ///< The result is RVA 0, which is never a valid symbol.
};

struct ResolveFailure {
    /// Borrows SymbolSpec::name: the specs' strings must outlive the ResolveResult.
    std::string_view name;
    bool required;
    ResolveError error;
    /// Scan mode: how many matches the scan saw, capped at 2 (it stops at the second), so 2 means
    /// "two or more"; failures after a unique match report 1. Reference mode: always 0, no scan runs.
    std::size_t match_count;
    std::string detail;
};

struct ResolveResult {
    /// Parallel to the specs. 0 means unresolved: RVA 0 is never a valid symbol (on the EU 1.09
    /// image the executable segment starts at vaddr 0 and offset 0 is the INTERP string), so
    /// consumers must read results through Rva() instead of treating this value as an address.
    /// ResolveSymbols enforces this: a result of 0 is reported as a ZeroRva failure.
    std::vector<std::uint64_t> rvas;
    std::vector<ResolveFailure> failures;

    /// The resolved RVA of spec i; nullopt when it is unresolved (rvas[i] == 0) or i is out of range.
    std::optional<std::uint64_t> Rva(std::size_t i) const {
        if (i >= rvas.size() || rvas[i] == 0) {
            return std::nullopt;
        }
        return rvas[i];
    }
    /// False when any required symbol failed.
    bool AllRequiredResolved() const;
    /// Number of specs that resolved to a non-zero RVA.
    std::size_t ResolvedCount() const;
};

/// Resolves every spec independently; failures are collected, never thrown.
ResolveResult ResolveSymbols(const ImageView& image, std::span<const SymbolSpec> specs);

/// The absolute target of the first visible [rip+disp] operand or relative immediate (call, jmp,
/// jcc) of an instruction decoded at insn_rva; nullopt when it has none. This is the one definition
/// of TargetMode::RelativeOperand: ResolveSymbols uses it, and so must any tool that indexes
/// references for the resolver (sigmaker).
std::optional<std::uint64_t> RelativeOperandTarget(const ZydisDecodedInstruction& insn,
                                                   const ZydisDecodedOperand* operands,
                                                   std::uint64_t insn_rva);

/// XXH3-64 of the executable segment; identifies the reference image.
std::uint64_t Fingerprint(std::span<const std::uint8_t> text);

std::string_view ToString(ResolveError error);

/// "name: error" or "name: error: detail", the one-line form used in logs and tool output.
std::string FormatFailure(const ResolveFailure& failure);

} // namespace BBCoop::Binding
