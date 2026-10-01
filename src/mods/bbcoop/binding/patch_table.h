// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace BBCoop::Binding {

/// One byte patch, as data. The string fields borrow static strings and must outlive the plan.
struct PatchSpec {
    std::string_view name;
    std::string_view group;
    std::string_view anchor;                // Symbol name of kind Patch.
    std::string_view original, replacement; // Hex bytes without wildcards, equal length.
    bool position_dependent; ///< The replacement encodes a target outside the patched function.
};

/// A verified patch ready to be written. `name` borrows PatchSpec::name.
struct PatchOp {
    std::string_view name;
    std::uint64_t rva;
    std::vector<std::uint8_t> original, replacement;
};

struct PatchIssue {
    std::string_view name; ///< Borrows PatchSpec::name.
    std::string detail;
};

struct PatchPlan {
    std::vector<PatchOp> ops;         ///< Enabled groups only.
    std::vector<PatchIssue> errors;   ///< Problems in enabled groups; they block activation.
    std::vector<PatchIssue> warnings; ///< Problems in disabled groups (data is still verified).
    bool Ok() const {
        return errors.empty();
    }
};

/// Maps a symbol name to its RVA; nullopt when the symbol is unresolved.
using SymbolLookup = std::function<std::optional<std::uint64_t>(std::string_view)>;

struct PatchPlanInput {
    std::span<const PatchSpec> specs;
    std::span<const std::string_view> enabled_groups;
    SymbolLookup lookup;
    std::span<const std::uint8_t> pristine; ///< The text segment before any patching.
    std::span<const std::uint8_t> live;     ///< The text segment as it is now.
    std::uint64_t text_rva;
    bool is_reference_image;
};

/// Verifies every spec against the pristine and live text and plans the enabled ones. A patch
/// becomes an op only when its original bytes equal the pristine text and the live text is still
/// pristine there. Every problem is reported (an error in an enabled group, a warning otherwise)
/// and the remaining specs are still checked. The caller must not install anything unless
/// plan.Ok().
PatchPlan PlanPatches(const PatchPlanInput& input);

using MemoryWriter = std::function<void(std::uint64_t rva, std::span<const std::uint8_t> bytes)>;

/// Writes every replacement, in order.
void ApplyPatches(std::span<const PatchOp> ops, const MemoryWriter& write);

/// Writes every original back, in reverse order.
void RevertPatches(std::span<const PatchOp> ops, const MemoryWriter& write);

/// Hex bytes separated by whitespace ("EB 0D"). Fails on an empty string, a bad token or a
/// wildcard.
std::expected<std::vector<std::uint8_t>, std::string> ParseHexBytes(std::string_view text);

} // namespace BBCoop::Binding
