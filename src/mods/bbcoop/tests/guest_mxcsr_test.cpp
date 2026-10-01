// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

// The guest MXCSR that CallGame loads around a game call (ruling 0B-R52, Important 1): recorded by
// RunHookHandler from the hook's context, the Orbis default outside a handler, and the caller's
// value back afterwards on every path. The "game function" is a System V function that returns
// the MXCSR it runs with.

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>

#include <gtest/gtest.h>
#include <windows.h>
#include <xbyak/xbyak.h>
#include <xmmintrin.h>

#include "bbcoop/binding/detour.h"
#include "bbcoop/binding/guest_mxcsr.h"
#include "bbcoop/binding/hook_guard.h"

using namespace BBCoop::Binding;

namespace {
constexpr std::uint32_t kHostMxcsr = 0x1F80;
/// Round toward zero, flush to zero, denormals are zero, all exceptions masked: unlike both the
/// host default and the Orbis default.
constexpr std::uint32_t kGuestMxcsr = 0xFFC0;

/// What a game function sees: its MXCSR (STMXCSR), through the guest's calling convention.
__attribute__((noinline)) std::uint32_t BBCOOP_SYSV_ABI GameMxcsr() {
    return _mm_getcsr();
}

/// A call that throws after recording its MXCSR (host ABI: only the restore is under test).
__attribute__((noinline)) void GameThrows(std::uint32_t* seen) {
    *seen = _mm_getcsr();
    throw std::runtime_error("thrown under the guest MXCSR");
}

/// Runs the test with the host's default MXCSR and puts the thread's value back afterwards.
class GuestMxcsrTest : public ::testing::Test {
protected:
    void SetUp() override {
        saved_ = _mm_getcsr();
        _mm_setcsr(kHostMxcsr);
    }
    void TearDown() override {
        _mm_setcsr(saved_);
    }

private:
    std::uint32_t saved_ = 0;
};
} // namespace

TEST_F(GuestMxcsrTest, OutsideAHandlerTheOrbisDefaultIsLoadedAndTheCallersRestored) {
    ASSERT_FALSE(CurrentGuestMxcsr().has_value());
    EXPECT_EQ(CallWithGuestMxcsr([] { return GameMxcsr(); }), kOrbisDefaultMxcsr);
    EXPECT_EQ(kOrbisDefaultMxcsr, 0x9FC0u);
    EXPECT_EQ(_mm_getcsr(), kHostMxcsr);
}

TEST_F(GuestMxcsrTest, InsideAScopeTheRecordedValueIsLoaded) {
    {
        const GuestMxcsrScope scope{kGuestMxcsr};
        EXPECT_EQ(CurrentGuestMxcsr(), kGuestMxcsr);
        EXPECT_EQ(CallWithGuestMxcsr([] { return GameMxcsr(); }), kGuestMxcsr);
        EXPECT_EQ(_mm_getcsr(), kHostMxcsr) << "the caller's MXCSR was not restored";
    }
    EXPECT_FALSE(CurrentGuestMxcsr().has_value());
}

TEST_F(GuestMxcsrTest, ScopesNestAndPutThePreviousRecordBack) {
    const GuestMxcsrScope outer{0x9F80};
    {
        const GuestMxcsrScope inner{kGuestMxcsr};
        EXPECT_EQ(CurrentGuestMxcsr(), kGuestMxcsr);
    }
    EXPECT_EQ(CurrentGuestMxcsr(), 0x9F80u);
    EXPECT_EQ(CallWithGuestMxcsr([] { return GameMxcsr(); }), 0x9F80u);
}

TEST_F(GuestMxcsrTest, ReservedBitsAreNotRecorded) {
    // A handler may have written bits 31:16 into the context; LDMXCSR would raise #GP with them.
    const GuestMxcsrScope scope{0xFFFF0000u | kGuestMxcsr};
    EXPECT_EQ(CurrentGuestMxcsr(), kGuestMxcsr);
    EXPECT_EQ(CallWithGuestMxcsr([] { return GameMxcsr(); }), kGuestMxcsr);
}

TEST_F(GuestMxcsrTest, TheCallersMxcsrIsRestoredWhenTheCallThrows) {
    const GuestMxcsrScope scope{kGuestMxcsr};
    std::uint32_t seen = 0;
    EXPECT_THROW(CallWithGuestMxcsr([&] { GameThrows(&seen); }), std::runtime_error);
    EXPECT_EQ(seen, kGuestMxcsr);
    EXPECT_EQ(_mm_getcsr(), kHostMxcsr);
}

TEST_F(GuestMxcsrTest, RunHookHandlerRecordsTheContextsMxcsrWhileTheHandlerRuns) {
    HookContext ctx{};
    ctx.mxcsr = kGuestMxcsr;
    std::optional<std::uint32_t> recorded;
    std::uint32_t game = 0;
    std::uint32_t handler_mxcsr = 0;
    const auto result = RunHookHandler(ctx, false, [&](HookContext&) {
        recorded = CurrentGuestMxcsr();
        handler_mxcsr = _mm_getcsr();
        game = CallWithGuestMxcsr([] { return GameMxcsr(); });
    });
    EXPECT_EQ(result.fault, HookFault::None);
    EXPECT_EQ(recorded, kGuestMxcsr);
    EXPECT_EQ(game, kGuestMxcsr);
    EXPECT_EQ(handler_mxcsr, kHostMxcsr) << "the handler itself keeps the caller's MXCSR";
    EXPECT_FALSE(CurrentGuestMxcsr().has_value()) << "the record outlived the handler";

    // Also when the handler throws.
    RunHookHandler(ctx, false, [](HookContext&) { throw std::runtime_error("x"); });
    EXPECT_FALSE(CurrentGuestMxcsr().has_value());
}

namespace {
struct DetourProbe {
    std::uint32_t handler_mxcsr = 0;
    std::uint32_t game_mxcsr = 0;
    std::uint32_t after_call = 0;
};

/// The runtime's hook thunk in miniature: the detour callback runs the handler through the guard.
void BBCOOP_SYSV_ABI GuardedGameCall(HookContext* ctx, void* user) {
    auto* probe = static_cast<DetourProbe*>(user);
    RunHookHandler(*ctx, false, [probe](HookContext&) {
        probe->handler_mxcsr = _mm_getcsr();
        probe->game_mxcsr = CallWithGuestMxcsr([] { return GameMxcsr(); });
        probe->after_call = _mm_getcsr();
    });
}
} // namespace

// End to end on the host: "guest" code with its own MXCSR reaches a hooked site, the callback runs
// under the host default, and a game function it calls runs under the guest's value again.
TEST_F(GuestMxcsrTest, AGameFunctionCalledFromADetourRunsWithTheGuestsMxcsr) {
    using namespace Xbyak::util;
    auto* const code = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_NE(code, nullptr) << GetLastError();
    auto* const slots = reinterpret_cast<std::uint32_t*>(code + 0x4000);
    slots[0] = kGuestMxcsr;
    slots[1] = kHostMxcsr; // put back before the "guest" returns to the test

    Xbyak::CodeGenerator g(0x1000, code);
    g.ldmxcsr(dword[rip + &slots[0]]);
    std::uint8_t* const site = const_cast<std::uint8_t*>(g.getCurr());
    g.nop(5);
    g.ldmxcsr(dword[rip + &slots[1]]);
    g.ret();

    DetourProbe probe;
    const DetourRequest request{reinterpret_cast<std::uint64_t>(site),
                                std::span<const std::uint8_t>(site, 5), GuardedGameCall, &probe};
    const auto detour = BuildDetour(request, code + 0x8000, kMaxTrampolineSize);
    ASSERT_TRUE(detour.has_value()) << detour.error();
    std::memcpy(site, detour->site_patch.data(), detour->site_patch_size);
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    reinterpret_cast<void (*)()>(code)();
    VirtualFree(code, 0, MEM_RELEASE);

    EXPECT_EQ(probe.handler_mxcsr, kHostMxcsr);
    EXPECT_EQ(probe.game_mxcsr, kGuestMxcsr) << "the game function ran under the host's MXCSR";
    EXPECT_EQ(probe.after_call, kHostMxcsr);
}
