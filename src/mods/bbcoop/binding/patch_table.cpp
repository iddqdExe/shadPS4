// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/patch_table.h"

#include <algorithm>
#include <format>
#include <numeric>
#include <utility>

#include "bbcoop/binding/signature.h"

namespace BBCoop::Binding {

namespace {
constexpr std::string_view kWildcardError = "wildcards are not allowed in patch bytes";

// Reports every enabled op that starts inside an earlier one (same site or partial overlap). The
// ops are walked in address order against the op that reaches furthest so far, so a long patch
// covering several short ones is reported against each of them. Differences are taken between
// addresses of ops that already passed the bounds check, so nothing here can wrap around.
void ReportOverlaps(PatchPlan& plan) {
    std::vector<std::size_t> order(plan.ops.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        return plan.ops[a].rva < plan.ops[b].rva;
    });
    const PatchOp* reach = nullptr;
    for (const std::size_t i : order) {
        const PatchOp& op = plan.ops[i];
        if (reach == nullptr) {
            reach = &op;
            continue;
        }
        const std::uint64_t gap = op.rva - reach->rva;
        if (gap < reach->original.size()) {
            plan.errors.push_back(
                {op.name, std::format("patch at {:#x} overlaps patch {} at {:#x}", op.rva,
                                      reach->name, reach->rva)});
        }
        if (gap + op.original.size() > reach->original.size()) {
            reach = &op;
        }
    }
}
} // namespace

std::expected<std::vector<std::uint8_t>, std::string> ParseHexBytes(std::string_view text) {
    const auto sig = Signature::Parse(text);
    if (!sig) {
        // An all-wildcard string fails Parse for lack of a literal byte; report the real problem.
        if (text.find('?') != std::string_view::npos) {
            return std::unexpected(std::string{kWildcardError});
        }
        return std::unexpected(sig.error());
    }
    if (sig->HasWildcards()) {
        return std::unexpected(std::string{kWildcardError});
    }
    const auto bytes = sig->Bytes();
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

PatchPlan PlanPatches(const PatchPlanInput& in) {
    PatchPlan plan;
    for (const auto& spec : in.specs) {
        const bool enabled =
            std::find(in.enabled_groups.begin(), in.enabled_groups.end(), spec.group) !=
            in.enabled_groups.end();
        const auto issue = [&](std::string detail) {
            (enabled ? plan.errors : plan.warnings).push_back({spec.name, std::move(detail)});
        };
        const auto original = ParseHexBytes(spec.original);
        const auto replacement = ParseHexBytes(spec.replacement);
        if (!original || !replacement) {
            issue(!original ? std::format("original: {}", original.error())
                            : std::format("replacement: {}", replacement.error()));
            continue;
        }
        if (original->size() != replacement->size()) {
            issue(std::format("original and replacement lengths differ ({} vs {})",
                              original->size(), replacement->size()));
            continue;
        }
        const auto rva = in.lookup(spec.anchor);
        if (!rva) {
            issue(std::format("anchor symbol {} is not resolved", spec.anchor));
            continue;
        }
        if (spec.position_dependent && !in.is_reference_image) {
            issue("position-dependent patch requires the reference image");
            continue;
        }
        // Compare against the sizes instead of adding to the offset, which could wrap around.
        const std::size_t size = original->size();
        const std::uint64_t off = *rva - in.text_rva;
        if (*rva < in.text_rva || off > in.pristine.size() || off > in.live.size() ||
            size > in.pristine.size() - off || size > in.live.size() - off) {
            issue(std::format("patch at {:#x} is outside the text segment", *rva));
            continue;
        }
        const auto pristine = in.pristine.subspan(off, size);
        const auto live = in.live.subspan(off, size);
        if (!std::equal(pristine.begin(), pristine.end(), original->begin())) {
            issue(std::format("original bytes differ at {:#x}: expected {}, found {}", *rva,
                              FormatHexBytes(*original), FormatHexBytes(pristine)));
        } else if (!std::equal(live.begin(), live.end(), pristine.begin())) {
            issue(std::format("bytes at {:#x} were modified by another patcher: {}", *rva,
                              FormatHexBytes(live)));
        } else if (enabled) {
            plan.ops.push_back({spec.name, *rva, *original, *replacement});
        }
    }
    ReportOverlaps(plan);
    if (!plan.Ok()) {
        plan.ops.clear(); // N4: a plan with problems installs nothing.
    }
    return plan;
}

void ApplyPatches(std::span<const PatchOp> ops, const MemoryWriter& write) {
    for (const auto& op : ops) {
        write(op.rva, op.replacement);
    }
}

void RevertPatches(std::span<const PatchOp> ops, const MemoryWriter& write) {
    for (auto it = ops.rbegin(); it != ops.rend(); ++it) {
        write(it->rva, it->original);
    }
}

} // namespace BBCoop::Binding
