// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/guest_mxcsr.h"

#include <xmmintrin.h>

namespace BBCoop::Binding {

namespace {
/// Constant-initialized, so it needs no dynamic TLS initialization on guest threads.
thread_local std::optional<std::uint32_t> t_guest_mxcsr;
} // namespace

std::optional<std::uint32_t> CurrentGuestMxcsr() noexcept {
    return t_guest_mxcsr;
}

GuestMxcsrScope::GuestMxcsrScope(std::uint32_t mxcsr) noexcept : saved_{t_guest_mxcsr} {
    t_guest_mxcsr = mxcsr & kMxcsrWritableBits;
}

GuestMxcsrScope::~GuestMxcsrScope() {
    t_guest_mxcsr = saved_;
}

GuestMxcsrLoad::GuestMxcsrLoad() noexcept : saved_{_mm_getcsr()} {
    _mm_setcsr(t_guest_mxcsr.value_or(kOrbisDefaultMxcsr));
}

GuestMxcsrLoad::~GuestMxcsrLoad() {
    _mm_setcsr(saved_);
}

} // namespace BBCoop::Binding
