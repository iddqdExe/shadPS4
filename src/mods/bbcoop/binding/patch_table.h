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
    /// Enabled groups only. Empty whenever errors is not: a plan with problems installs nothing
    /// (the N4 rule is enforced here, not left to the caller).
    std::vector<PatchOp> ops;
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
    SymbolLookup lookup;                    ///< Resolves PatchSpec::anchor to an RVA.
    std::span<const std::uint8_t> pristine; ///< The text segment before any patching.
    std::span<const std::uint8_t> live;     ///< The text segment as it is now.
    std::uint64_t text_rva;                 ///< RVA of pristine[0] and live[0].
    /// True when the image is the verified known-good one; position-dependent patches need it.
    bool is_reference_image;
};

/// Verifies every spec against the pristine and live text and plans the enabled ones. A patch
/// becomes an op only when its original bytes equal the pristine text and the live text is still
/// pristine there. The first problem of each spec is reported (an error in an enabled group, a
/// warning otherwise) and the remaining specs are still checked. After the per-spec checks the
/// enabled patches are checked against each other: two that touch the same byte are an error
/// naming both. When there are errors, plan.ops is empty.
PatchPlan PlanPatches(const PatchPlanInput& input);

using MemoryWriter = std::function<void(std::uint64_t rva, std::span<const std::uint8_t> bytes)>;

/// Writes every replacement, in order. There is no failure path of its own: if the writer throws,
/// the exception propagates and the ops before the failing one stay written. RevertPatches(ops)
/// with the same ops is a safe rollback after such a partial apply, since each site then holds
/// either its replacement or its pristine original.
void ApplyPatches(std::span<const PatchOp> ops, const MemoryWriter& write);

/// Writes every original back, in reverse order.
void RevertPatches(std::span<const PatchOp> ops, const MemoryWriter& write);

/// Hex bytes separated by whitespace ("EB 0D"). Fails on an empty string, a bad token or a
/// wildcard (including a string made only of wildcards).
std::expected<std::vector<std::uint8_t>, std::string> ParseHexBytes(std::string_view text);

} // namespace BBCoop::Binding
