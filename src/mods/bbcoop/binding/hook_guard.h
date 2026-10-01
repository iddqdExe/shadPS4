// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <span>
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
    ConflictingAction,   ///< The handler asked for a non-Continue action other than the one an
                         ///< earlier handler of the same site asked for in the same hit
                         ///< (HookRunResult::requested and ::earlier).
};

/// The action the trampoline takes for `action`: values other than the HookAction enumerators
/// behave as Continue.
constexpr HookAction EffectiveAction(HookAction action) noexcept {
    return action == HookAction::SkipStolen || action == HookAction::ReturnFromFunction
               ? action
               : HookAction::Continue;
}

std::string_view ToString(HookAction action);

struct HookRunResult {
    HookFault fault = HookFault::None;
    /// HookFault::Exception: what(), NUL-terminated and cut to fit. Empty otherwise.
    std::array<char, 256> message{};
    /// HookFault::ConflictingAction: what this handler asked for, and what an earlier handler of
    /// the site asked for (the action that stays). Continue otherwise.
    HookAction requested = HookAction::Continue;
    HookAction earlier = HookAction::Continue;

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
    /// The non-Continue action an earlier handler of the same site asked for in this hit
    /// (RunSiteHandlers sets it), Continue when none did: asking for a different non-Continue
    /// action is a ConflictingAction fault, asking for the same one or for Continue is fine.
    HookAction earlier_action = HookAction::Continue;
};

/// Reports a fault (logging, disabling the hook). RunHookHandler calls it inside the same stack
/// bounds as the handler and swallows anything it throws.
using HookFaultReporter = void (*)(const HookRunResult& result, void* user);

/// Calls handler(ctx) the way a detour callback has to, so that nothing the handler does can
/// reach the guest:
///  - An exception that leaves the handler is caught here (std::exception and anything else).
///  - ReturnFromFunction is refused unless rules.function_entry is set, SkipStolen is refused
///    when rules.ends_with_transfer is set, and a non-Continue action other than
///    rules.earlier_action (when that is not Continue) is refused as ConflictingAction.
///  - On any failure the context is put back as it was on entry, with action Continue, so the
///    guest resumes as if this handler had not run, and `report` (when not null) is called with
///    the result and `report_user`.
///  - While the handler runs, ctx.mxcsr (as it is on entry) is this thread's guest MXCSR
///    (GuestMxcsrScope, see guest_mxcsr.h): game code the handler calls through
///    CallWithGuestMxcsr runs with it, while the handler itself keeps the host's MXCSR.
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

/// One of the handlers of a hooked site (RunSiteHandlers).
struct SiteHandler {
    std::function<void(HookContext&)> handler;
    /// Passed to the reporter with this handler's faults.
    void* report_user = nullptr;
    /// Set by RunSiteHandlers after the handler's first fault; a faulted handler never runs again.
    std::atomic<bool> faulted{false};
};

/// Runs the handlers of one site, in order, each through RunHookHandler with `rules` (so each is
/// isolated: a handler that faults has its own changes undone, is reported and marked faulted,
/// and the others keep running). Handlers that faulted earlier are skipped. Each handler sees the
/// registers as the handlers before it left them, and ctx.action set to Continue.
///
/// Actions: the first non-Continue action a handler asks for (SkipStolen or ReturnFromFunction,
/// within `rules`) becomes the site's action for this hit. A later handler may ask for the same
/// action or for Continue; asking for a different non-Continue action is a ConflictingAction
/// fault of that later handler (its changes are undone, it is disabled, the earlier action
/// stays). On return ctx.action is the site's action (Continue when no handler asked for one).
/// Never throws.
void RunSiteHandlers(HookContext& ctx, HookSiteRules rules, std::span<SiteHandler* const> handlers,
                     HookFaultReporter report) noexcept;

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
