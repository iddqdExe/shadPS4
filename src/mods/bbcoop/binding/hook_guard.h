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
    SkipPastFunctionEnd, ///< The handler asked for SkipStolen at a site whose stolen bytes end with
                         ///< an unconditional jump or ret: the guest would continue after the end
                         ///< of the function.
};

struct HookRunResult {
    HookFault fault = HookFault::None;
    /// HookFault::Exception: what(), NUL-terminated and cut to fit. Empty otherwise.
    std::array<char, 256> message{};

    std::string_view Message() const {
        return std::string_view{message.data()};
    }
};

/// What a handler may ask for at a hooked site.
struct HookSiteRules {
    /// The site is the first instruction of a function: ReturnFromFunction is allowed.
    bool function_entry = false;
    /// The stolen bytes end with an unconditional jump or ret: SkipStolen is refused.
    bool ends_with_transfer = false;
};

/// Reports a fault (logging, disabling the hook). RunHookHandler calls it inside the same stack
/// bounds as the handler and swallows anything it throws.
using HookFaultReporter = void (*)(const HookRunResult& result, void* user);

/// Calls handler(ctx) the way a detour callback has to, so that nothing the handler does can
/// reach the guest:
///  - An exception that leaves the handler is caught here (std::exception and anything else).
///  - ReturnFromFunction is refused unless rules.function_entry is set, and SkipStolen is refused
///    when rules.ends_with_transfer is set.
///  - On any failure the context is put back as it was on entry, with action Continue, so the
///    guest resumes as if no handler had run, and `report` (when not null) is called with the
///    result and `report_user`.
///  - Windows: detour handlers run on guest stacks, and shadPS4 runs guest code with the TEB stack
///    bounds (NT_TIB StackBase gs:0x08, StackLimit gs:0x10) set to 0. The exception dispatcher
///    rejects frames outside [StackLimit, StackBase), so a throw there would be unhandled and end
///    the process. While the handler and the reporter run, the bounds are [0, just above this
///    function's own frame); the previous values are restored before returning, on every path.
///    Code that runs on a guest stack outside this call must not throw at all.
/// Never throws. Allocates nothing itself (the handler and the reporter may).
HookRunResult RunHookHandler(HookContext& ctx, HookSiteRules rules,
                             const std::function<void(HookContext&)>& handler,
                             HookFaultReporter report = nullptr,
                             void* report_user = nullptr) noexcept;

/// The same for a site with only the function-entry rule.
inline HookRunResult RunHookHandler(HookContext& ctx, bool function_entry,
                                    const std::function<void(HookContext&)>& handler,
                                    HookFaultReporter report = nullptr,
                                    void* report_user = nullptr) noexcept {
    return RunHookHandler(ctx, HookSiteRules{.function_entry = function_entry}, handler, report,
                          report_user);
}

/// The calling thread's TEB stack bounds (NT_TIB StackBase and StackLimit); both 0 off Windows.
struct StackBounds {
    std::uint64_t base = 0;  ///< Highest address of the stack.
    std::uint64_t limit = 0; ///< Lowest address the exception dispatcher accepts.
};
StackBounds CurrentStackBounds() noexcept;

/// True when a C++ exception thrown under these bounds can never reach a catch handler: both are 0,
/// as shadPS4 sets them while guest code runs on a guest stack (outside RunHookHandler, which sets
/// valid ones), so the dispatcher rejects every frame and the process ends.
constexpr bool CppThrowIsUncatchable(StackBounds bounds) noexcept {
    return bounds.base == 0 && bounds.limit == 0;
}

} // namespace BBCoop::Binding
