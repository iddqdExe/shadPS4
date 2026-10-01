// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/hook_guard.h"

#include <algorithm>
#include <cstring>
#include <exception>

#ifdef _WIN32
#include <cstddef>

#include <intrin.h>
#include <windows.h>
#endif

namespace BBCoop::Binding {

namespace {
#ifdef _WIN32
// The TEB starts with NT_TIB, and GS points at the TEB, so these are gs:0x08 and gs:0x10, the
// fields shadPS4's _runOnAnotherStack zeroes for guest code. They are written through
// NtCurrentTeb() because clang-cl declares __writegsqword but does not implement it.
static_assert(offsetof(NT_TIB, StackBase) == 0x08);
static_assert(offsetof(NT_TIB, StackLimit) == 0x10);

/// Sets the TEB stack bounds to [0, base) for its lifetime and restores the previous ones after.
class StackBoundsScope {
public:
    explicit StackBoundsScope(std::uint64_t base) noexcept
        : tib_{reinterpret_cast<NT_TIB*>(NtCurrentTeb())}, saved_base_{tib_->StackBase},
          saved_limit_{tib_->StackLimit} {
        tib_->StackBase = reinterpret_cast<PVOID>(base);
        tib_->StackLimit = nullptr;
    }
    ~StackBoundsScope() {
        tib_->StackBase = saved_base_;
        tib_->StackLimit = saved_limit_;
    }
    StackBoundsScope(const StackBoundsScope&) = delete;
    StackBoundsScope& operator=(const StackBoundsScope&) = delete;

private:
    NT_TIB* tib_;
    PVOID saved_base_;  ///< Highest address of the stack.
    PVOID saved_limit_; ///< Lowest committed address of the stack.
};
#endif

void CopyMessage(std::array<char, 256>& out, const char* text) noexcept {
    if (text == nullptr) {
        text = "";
    }
    const std::size_t length = std::min(std::strlen(text), out.size() - 1);
    std::memcpy(out.data(), text, length);
    out[length] = '\0';
}
} // namespace

HookRunResult RunHookHandler(HookContext& ctx, bool function_entry,
                             const std::function<void(HookContext&)>& handler,
                             HookFaultReporter report, void* report_user) noexcept {
    HookRunResult result;
    const HookContext entry = ctx;
#ifdef _WIN32
    // The handler's and the reporter's frames, and those of an exception dispatched inside them,
    // all lie below this function's return address slot.
    const StackBoundsScope bounds{reinterpret_cast<std::uint64_t>(_AddressOfReturnAddress()) +
                                  sizeof(void*)};
#endif
    try {
        handler(ctx);
    } catch (const std::exception& e) {
        result.fault = HookFault::Exception;
        CopyMessage(result.message, e.what());
    } catch (...) {
        result.fault = HookFault::UnknownException;
    }
    if (result.fault == HookFault::None && ctx.action == HookAction::ReturnFromFunction &&
        !function_entry) {
        result.fault = HookFault::ReturnAtMidSite;
    }
    if (result.fault != HookFault::None) {
        ctx = entry;
        ctx.action = HookAction::Continue;
        if (report != nullptr) {
            try {
                report(result, report_user);
            } catch (...) {
            }
        }
    }
    return result;
}

} // namespace BBCoop::Binding
