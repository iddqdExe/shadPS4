// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bbcoop/binding/resolver.h"

namespace BBCoop::Binding {

/// FunctionEntry: the first instruction of a function, where [rsp] is the return address and
/// HookContext::ReturnFromFunction is allowed. Mid: any other instruction.
enum class HookSiteKind { FunctionEntry, Mid };

struct HookRequest {
    std::size_t symbol; ///< Index into HookPlanInput::symbols and the resolved RVAs.
    HookSiteKind kind;
    std::string_view owner;
};

struct HookPlanInput {
    std::span<const HookRequest> requests;
    std::span<const SymbolSpec> symbols; ///< Names and kinds, parallel to `resolved`.
    const ResolveResult& resolved;
    std::span<const std::uint8_t> pristine; ///< The text segment before any patching.
    std::span<const std::uint8_t> live;     ///< The text segment as it is now (same size).
    std::uint64_t text_rva;                 ///< RVA of pristine[0] and live[0].
};

/// One request that passed every check, in request order.
struct PlannedHook {
    std::size_t request;
    std::uint64_t rva;
    std::span<const std::uint8_t> stolen; ///< The pristine bytes the hook's jump replaces.
    bool ends_with_transfer;              ///< See HookSiteRules::ends_with_transfer.
};

/// The bytes on each side of the stolen ones that must also be untouched in the live text.
constexpr std::size_t kHookNeighbourhood = 16;

/// Checks every request and returns where each hook goes, or the first problem (all or nothing:
/// one bad request fails the plan). A request is refused when
///  - its symbol is unresolved or out of range,
///  - its kind does not fit the symbol: FunctionEntry needs a Function, Mid a Function or Site,
///  - the site is outside the text, or the stolen bytes (whole instructions covering a JMP rel32)
///    do not decode,
///  - an unconditional jump, ret or trap comes before the last stolen instruction (the function
///    ends inside the region and the jump would overwrite what follows),
///  - its stolen bytes overlap those of an earlier request,
///  - the live text differs from the pristine text over the stolen bytes or within
///    kHookNeighbourhood bytes around them (an XML patch, an emulator patch or one of our own byte
///    patches is there).
/// Relocating the stolen bytes and the trampoline space are checked when the detours are built.
std::expected<std::vector<PlannedHook>, std::string> PlanHooks(const HookPlanInput& input);

std::string_view ToString(HookSiteKind kind);
std::string_view ToString(SymbolKind kind);

} // namespace BBCoop::Binding
