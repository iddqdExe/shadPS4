// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string_view>

#include "bbcoop/binding/detour.h"

namespace BBCoop::Binding {

/// Why a guarded handler call failed.
enum class HookFault : std::uint8_t {
    None,
    Exception,        ///< A std::exception left the handler; HookRunResult::message holds what().
    UnknownException, ///< Something that is not a std::exception left the handler.
    ReturnAtMidSite,  ///< The handler asked for ReturnFromFunction at a site that is not the first
                      ///< instruction of a function, where [rsp] is not a return address.
};

struct HookRunResult {
    HookFault fault = HookFault::None;
    /// HookFault::Exception: what(), NUL-terminated and cut to fit. Empty otherwise.
    std::array<char, 256> message{};

    std::string_view Message() const {
        return std::string_view{message.data()};
    }
};

/// Reports a fault (logging, disabling the hook). RunHookHandler calls it inside the same stack
/// bounds as the handler and swallows anything it throws.
using HookFaultReporter = void (*)(const HookRunResult& result, void* user);

/// Calls handler(ctx) the way a detour callback has to, so that nothing the handler does can
/// reach the guest:
///  - An exception that leaves the handler is caught here (std::exception and anything else).
///  - ReturnFromFunction is refused unless `function_entry` is set.
///  - On either failure the context is put back as it was on entry, with action Continue, so the
///    guest resumes as if no handler had run, and `report` (when not null) is called with the
///    result and `report_user`.
///  - Windows: detour handlers run on guest stacks, and shadPS4 runs guest code with the TEB stack
///    bounds (NT_TIB StackBase gs:0x08, StackLimit gs:0x10) set to 0. The exception dispatcher
///    rejects frames outside [StackLimit, StackBase), so a throw there would be unhandled and end
///    the process. While the handler and the reporter run, the bounds are [0, just above this
///    function's own frame); the previous values are restored before returning, on every path.
///    Code that runs on a guest stack outside this call must not throw at all.
/// Never throws. Allocates nothing itself (the handler and the reporter may).
HookRunResult RunHookHandler(HookContext& ctx, bool function_entry,
                             const std::function<void(HookContext&)>& handler,
                             HookFaultReporter report = nullptr,
                             void* report_user = nullptr) noexcept;

} // namespace BBCoop::Binding
