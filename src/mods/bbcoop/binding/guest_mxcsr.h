// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <utility>

namespace BBCoop::Binding {

/// The MXCSR Orbis threads run with: round to nearest, all exceptions masked, FTZ and DAZ on.
/// shadPS4 starts guest threads and fibers with it (src/core/thread.cpp, fiber.cpp).
constexpr std::uint32_t kOrbisDefaultMxcsr = 0x9FC0;

/// The MXCSR bits LDMXCSR accepts on a CPU with AVX (MXCSR_MASK 0xFFFF); bits 31:16 are reserved
/// and raise #GP when set.
constexpr std::uint32_t kMxcsrWritableBits = 0xFFFF;

// Hook handlers (detour callbacks) run with the host's default MXCSR 0x1F80, so host code in them
// is not subject to the guest's rounding and flush-to-zero modes; game code called from a handler
// must run with the guest's MXCSR instead, as it would natively. RunHookHandler records the
// guest's MXCSR (the context's) for the current thread while the handler runs, and
// CallWithGuestMxcsr loads it around the game call.

/// The guest MXCSR recorded on this thread by the innermost live GuestMxcsrScope (inside a hook
/// handler: the context's MXCSR when the handler started); nullopt outside any.
std::optional<std::uint32_t> CurrentGuestMxcsr() noexcept;

/// Records `mxcsr` (bits 31:16 cleared) as this thread's guest MXCSR for its lifetime and puts the
/// previous record back when it ends, so scopes nest (a game function called from a handler that
/// reaches another hooked site).
class GuestMxcsrScope {
public:
    explicit GuestMxcsrScope(std::uint32_t mxcsr) noexcept;
    ~GuestMxcsrScope();
    GuestMxcsrScope(const GuestMxcsrScope&) = delete;
    GuestMxcsrScope& operator=(const GuestMxcsrScope&) = delete;

private:
    std::optional<std::uint32_t> saved_;
};

/// Loads the guest MXCSR (CurrentGuestMxcsr(), or kOrbisDefaultMxcsr outside any scope) into the
/// thread's MXCSR for its lifetime and loads back the value it found when it ends, on every path
/// (an exception that leaves the scope included).
class GuestMxcsrLoad {
public:
    GuestMxcsrLoad() noexcept;
    ~GuestMxcsrLoad();
    GuestMxcsrLoad(const GuestMxcsrLoad&) = delete;
    GuestMxcsrLoad& operator=(const GuestMxcsrLoad&) = delete;

private:
    std::uint32_t saved_;
};

/// Calls f() with the guest MXCSR loaded (GuestMxcsrLoad) and returns its result; the previous
/// MXCSR is back when this returns or throws. Runtime::CallGame calls game functions through it.
template <typename F>
decltype(auto) CallWithGuestMxcsr(F&& f) {
    const GuestMxcsrLoad load;
    return std::forward<F>(f)();
}

} // namespace BBCoop::Binding
