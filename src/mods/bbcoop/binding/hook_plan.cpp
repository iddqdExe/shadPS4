// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/hook_plan.h"

#include <algorithm>
#include <cstring>
#include <format>

#include "bbcoop/binding/relocator.h"

namespace BBCoop::Binding {

namespace {
/// The site is overwritten with a JMP rel32.
constexpr std::size_t kJumpSize = 5;
/// Bytes decoded at a site to find the stolen length; more than any 5..16 byte steal needs.
constexpr std::size_t kDecodeWindow = 32;

bool KindFits(HookSiteKind hook, SymbolKind symbol) {
    switch (hook) {
    case HookSiteKind::FunctionEntry:
        return symbol == SymbolKind::Function;
    case HookSiteKind::Mid:
        return symbol == SymbolKind::Function || symbol == SymbolKind::Site;
    }
    return false;
}
} // namespace

std::expected<std::vector<PlannedHook>, std::string> PlanHooks(const HookPlanInput& input) {
    const auto& pristine = input.pristine;
    if (input.live.size() != pristine.size()) {
        return std::unexpected(std::format("live text is {:#x} bytes, pristine text {:#x}",
                                           input.live.size(), pristine.size()));
    }
    std::vector<PlannedHook> planned;
    planned.reserve(input.requests.size());
    for (std::size_t r = 0; r < input.requests.size(); ++r) {
        const auto& request = input.requests[r];
        if (request.symbol >= input.symbols.size()) {
            return std::unexpected(std::format("hook #{} ('{}'): symbol index {} is out of range",
                                               r, request.owner, request.symbol));
        }
        const auto& spec = input.symbols[request.symbol];
        const auto name = spec.name;
        if (!KindFits(request.kind, spec.kind)) {
            return std::unexpected(std::format("hook {}: a {} hook cannot go on a {} symbol", name,
                                               ToString(request.kind), ToString(spec.kind)));
        }
        const auto site_rva = input.resolved.Rva(request.symbol);
        if (!site_rva) {
            return std::unexpected(std::format("hook {}: site symbol is not resolved", name));
        }
        const std::uint64_t rva = *site_rva;
        if (rva < input.text_rva || rva - input.text_rva >= pristine.size()) {
            return std::unexpected(
                std::format("hook {}: site {:#x} is outside the text segment", name, rva));
        }
        const auto off = static_cast<std::size_t>(rva - input.text_rva);
        const auto steal = StealLength(
            pristine.subspan(off, std::min(kDecodeWindow, pristine.size() - off)), kJumpSize);
        if (!steal) {
            return std::unexpected(std::format("hook {}: {}", name, steal.error()));
        }
        const auto stolen = pristine.subspan(off, *steal);
        const auto transfers = ScanControlTransfers(stolen);
        if (!transfers) {
            return std::unexpected(std::format("hook {}: {}", name, transfers.error()));
        }
        if (transfers->early) {
            return std::unexpected(std::format(
                "hook {}: the code at {:#x} ends at +{:#x} with an unconditional jump, ret or "
                "trap, inside the {} bytes the hook overwrites",
                name, rva, *transfers->early, *steal));
        }
        // A direct branch elsewhere in the game to an instruction inside the stolen bytes would
        // land in the middle of the hook's jump.
        if (*steal > spec.max_steal) {
            if (spec.max_steal < kMaxHookSteal) {
                return std::unexpected(std::format(
                    "hook {}: a direct branch in the game targets {:#x}, inside the {} bytes the "
                    "hook would overwrite at {:#x} (max_steal {})",
                    name, rva + spec.max_steal, *steal, rva, spec.max_steal));
            }
            return std::unexpected(std::format(
                "hook {}: the hook would overwrite {} bytes at {:#x}, more than the {} checked "
                "for branch targets (max_steal {})",
                name, *steal, rva, kMaxHookSteal, spec.max_steal));
        }
        // Several handlers on one site share its detour; they must agree on what the site is.
        if (const auto same = std::ranges::find(planned, rva, &PlannedHook::rva);
            same != planned.end()) {
            const auto& first = input.requests[same->request];
            if (first.kind != request.kind) {
                return std::unexpected(std::format(
                    "hook {} ('{}'): a {} hook cannot share the site at {:#x} with the {} hook "
                    "of '{}' ({})",
                    name, request.owner, ToString(request.kind), rva, ToString(first.kind),
                    first.owner, input.symbols[first.symbol].name));
            }
            same->requests.push_back(r);
            continue;
        }
        for (const auto& other : planned) {
            if (rva < other.rva + other.stolen.size() && other.rva < rva + *steal) {
                const auto& other_request = input.requests[other.request];
                return std::unexpected(std::format(
                    "hook {} overlaps hook {} (owners '{}' and '{}')", name,
                    input.symbols[other_request.symbol].name, request.owner, other_request.owner));
            }
        }
        // The stolen bytes must be exactly the pristine ones: an emulator patch there is a jump
        // into a cpu_patches trampoline, which the relocator would copy blindly.
        const std::size_t lo = off >= kHookNeighbourhood ? off - kHookNeighbourhood : 0;
        const std::size_t hi = std::min(off + *steal + kHookNeighbourhood, pristine.size());
        if (std::memcmp(input.live.data() + lo, pristine.data() + lo, hi - lo) != 0) {
            return std::unexpected(
                std::format("hook {}: code around {:#x} was modified by another patcher "
                            "(an XML patch, the emulator or a BB Co-op byte patch)",
                            name, rva));
        }
        planned.push_back({r, rva, stolen, transfers->ends_with_transfer, {r}});
    }
    return planned;
}

std::string_view ToString(HookSiteKind kind) {
    switch (kind) {
    case HookSiteKind::FunctionEntry:
        return "FunctionEntry";
    case HookSiteKind::Mid:
        return "Mid";
    }
    return "unknown";
}

std::string_view ToString(SymbolKind kind) {
    switch (kind) {
    case SymbolKind::Function:
        return "Function";
    case SymbolKind::Site:
        return "Site";
    case SymbolKind::Global:
        return "Global";
    case SymbolKind::Data:
        return "Data";
    case SymbolKind::Patch:
        return "Patch";
    }
    return "unknown";
}

} // namespace BBCoop::Binding
