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

namespace BBCoop::Binding {

enum class SymbolKind : std::uint8_t { Function, Site, Global, Data, Patch };

/// How the result is derived from the pattern match.
enum class TargetMode : std::uint8_t {
    Match,           ///< target = match + operand_offset.
    RelativeOperand, ///< Decode the instruction at match + operand_offset and take the absolute
                     ///< target of its first [rip+disp] operand or relative immediate (call/jmp/jcc).
};

struct SymbolSpec {
    std::string_view name;
    SymbolKind kind;
    bool required;
    std::uint64_t target_rva;    ///< Expected result on the reference image.
    std::uint64_t match_rva;     ///< Where the pattern matches on the reference image.
    std::int32_t operand_offset; ///< See TargetMode.
    TargetMode mode;
    std::string_view pattern;
};

/// The executable segment of the loaded image. With is_reference_image set (the caller has verified
/// the fingerprint of the known-good image) each pattern is checked only at match_rva and the result
/// must equal target_rva; otherwise every pattern is scanned over the whole text and must match once.
struct ImageView {
    std::span<const std::uint8_t> text;
    std::uint64_t text_rva;
    bool is_reference_image;
};

enum class ResolveError : std::uint8_t { BadPattern, NotFound, Ambiguous, HintMismatch, BadOperand };

struct ResolveFailure {
    std::string_view name;
    bool required;
    ResolveError error;
    std::size_t match_count;
    std::string detail;
};

struct ResolveResult {
    /// Parallel to the specs. 0 means unresolved: RVA 0 is never a valid symbol (on the EU 1.09
    /// image the executable segment starts at vaddr 0 and offset 0 is the INTERP string), so
    /// consumers must read results through Rva() instead of treating this value as an address.
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
    std::size_t ResolvedCount() const;
};

/// Resolves every spec independently; failures are collected, never thrown.
ResolveResult ResolveSymbols(const ImageView& image, std::span<const SymbolSpec> specs);

/// XXH3-64 of the executable segment; identifies the reference image.
std::uint64_t Fingerprint(std::span<const std::uint8_t> text);

std::string_view ToString(ResolveError error);

} // namespace BBCoop::Binding
