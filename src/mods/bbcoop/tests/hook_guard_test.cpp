// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>
#include <windows.h>
#include <xbyak/xbyak.h>

#include "bbcoop/binding/detour.h"
#include "bbcoop/binding/hook_guard.h"
#include "bbcoop/binding/relocator.h"

using namespace BBCoop::Binding;

namespace {
// The TEB stack bounds through NT_TIB, which also checks the guard's raw gs:0x08 / gs:0x10 offsets.
NT_TIB* Tib() {
    return reinterpret_cast<NT_TIB*>(NtCurrentTeb());
}
std::uint64_t TebStackBase() {
    return reinterpret_cast<std::uint64_t>(Tib()->StackBase);
}
std::uint64_t TebStackLimit() {
    return reinterpret_cast<std::uint64_t>(Tib()->StackLimit);
}
void SetTebStackBounds(std::uint64_t base, std::uint64_t limit) {
    Tib()->StackBase = reinterpret_cast<PVOID>(base);
    Tib()->StackLimit = reinterpret_cast<PVOID>(limit);
}

HookContext MakeContext() {
    HookContext ctx{};
    std::uint64_t value = 0x1000;
    for (auto* reg :
         {&ctx.rax, &ctx.rbx, &ctx.rcx, &ctx.rdx, &ctx.rsi, &ctx.rdi, &ctx.rbp, &ctx.rsp, &ctx.r8,
          &ctx.r9, &ctx.r10, &ctx.r11, &ctx.r12, &ctx.r13, &ctx.r14, &ctx.r15}) {
        *reg = value++;
    }
    ctx.rflags = 0x202;
    ctx.site = 0x400000;
    ctx.mxcsr = 0x1F80;
    ctx.action = HookAction::Continue;
    for (std::size_t i = 0; i < ctx.ymm.size(); ++i) {
        ctx.ymm[i].fill(static_cast<std::uint8_t>(i));
    }
    return ctx;
}

bool SameContext(const HookContext& a, const HookContext& b) {
    return std::memcmp(&a, &b, sizeof(HookContext)) == 0;
}
} // namespace

TEST(HookGuardTest, KeepsTheChangesOfAHandlerThatSucceeds) {
    HookContext ctx = MakeContext();
    const auto result = RunHookHandler(ctx, false, [](HookContext& c) {
        c.rax = 99;
        c.ymm[3][0] = 0xAB;
        c.SkipStolenInstructions();
    });
    EXPECT_EQ(result.fault, HookFault::None);
    EXPECT_TRUE(result.Message().empty());
    EXPECT_EQ(ctx.rax, 99u);
    EXPECT_EQ(ctx.ymm[3][0], 0xAB);
    EXPECT_EQ(ctx.action, HookAction::SkipStolen);
}

TEST(HookGuardTest, CatchesStdExceptionAndRestoresTheContext) {
    HookContext ctx = MakeContext();
    const HookContext before = ctx;
    const auto result = RunHookHandler(ctx, true, [](HookContext& c) {
        c.rax = 99;
        c.rsp = 0;
        c.ymm[15][31] = 0xEE;
        c.SkipStolenInstructions();
        throw std::runtime_error("boom");
    });
    EXPECT_EQ(result.fault, HookFault::Exception);
    EXPECT_EQ(result.Message(), "boom");
    EXPECT_TRUE(SameContext(ctx, before)) << "the handler's partial changes were not undone";
}

TEST(HookGuardTest, CatchesAnythingElseThatIsThrown) {
    HookContext ctx = MakeContext();
    const HookContext before = ctx;
    const auto result = RunHookHandler(ctx, true, [](HookContext& c) {
        c.rbx = 0;
        throw 42;
    });
    EXPECT_EQ(result.fault, HookFault::UnknownException);
    EXPECT_TRUE(result.Message().empty());
    EXPECT_TRUE(SameContext(ctx, before));
}

TEST(HookGuardTest, AnEmptyHandlerIsAFault) {
    HookContext ctx = MakeContext();
    const auto result = RunHookHandler(ctx, false, std::function<void(HookContext&)>{});
    EXPECT_EQ(result.fault, HookFault::Exception); // std::bad_function_call
}

TEST(HookGuardTest, CutsLongMessagesToTheBuffer) {
    HookContext ctx = MakeContext();
    const auto result = RunHookHandler(
        ctx, false, [](HookContext&) { throw std::runtime_error(std::string(1000, 'x')); });
    ASSERT_EQ(result.fault, HookFault::Exception);
    EXPECT_EQ(result.Message(), std::string(result.message.size() - 1, 'x'));
}

TEST(HookGuardTest, RefusesReturnFromFunctionAtAMidFunctionSite) {
    HookContext ctx = MakeContext();
    const HookContext before = ctx;
    const auto result = RunHookHandler(ctx, false, [](HookContext& c) {
        c.rbx = 5;
        c.ReturnFromFunction(7);
    });
    EXPECT_EQ(result.fault, HookFault::ReturnAtMidSite);
    EXPECT_TRUE(SameContext(ctx, before));
    EXPECT_EQ(ctx.action, HookAction::Continue);
}

TEST(HookGuardTest, AllowsReturnFromFunctionAtAFunctionEntry) {
    HookContext ctx = MakeContext();
    const auto result = RunHookHandler(ctx, true, [](HookContext& c) { c.ReturnFromFunction(7); });
    EXPECT_EQ(result.fault, HookFault::None);
    EXPECT_EQ(ctx.rax, 7u);
    EXPECT_EQ(ctx.action, HookAction::ReturnFromFunction);
}

TEST(HookGuardTest, BoundsTheStackForTheHandlerAndRestoresTheTebAfterwards) {
    const std::uint64_t base = TebStackBase();
    const std::uint64_t limit = TebStackLimit();
    for (const bool throws : {false, true}) {
        std::uint64_t seen_base = 0;
        std::uint64_t seen_limit = 1;
        std::uint64_t local_address = 0;
        HookContext ctx = MakeContext();
        RunHookHandler(ctx, false, [&](HookContext&) {
            int local = 0;
            local_address = reinterpret_cast<std::uint64_t>(&local);
            seen_base = TebStackBase();
            seen_limit = TebStackLimit();
            if (throws) {
                throw std::runtime_error("x");
            }
        });
        EXPECT_EQ(seen_limit, 0u) << "throws=" << throws;
        EXPECT_GT(seen_base, local_address) << "the handler's frame lies outside the bounds";
        EXPECT_EQ(TebStackBase(), base) << "throws=" << throws;
        EXPECT_EQ(TebStackLimit(), limit) << "throws=" << throws;
    }
}

namespace {
struct ReportLog {
    int calls = 0;
    HookFault fault = HookFault::None;
    const HookContext* ctx = nullptr;
    std::uint64_t rax_seen = 0;
};

void RecordingReporter(const HookRunResult& result, void* user) {
    auto* log = static_cast<ReportLog*>(user);
    ++log->calls;
    log->fault = result.fault;
    log->rax_seen = log->ctx->rax;
}
} // namespace

TEST(HookGuardTest, ReportsEachFaultOnceWithTheContextAlreadyRestored) {
    HookContext ctx = MakeContext();
    const std::uint64_t rax = ctx.rax;
    ReportLog log{.ctx = &ctx};
    RunHookHandler(ctx, false, [](HookContext& c) { c.rax = 1; }, RecordingReporter, &log);
    EXPECT_EQ(log.calls, 0) << "a handler that succeeds is not a fault";

    ctx.rax = rax;
    RunHookHandler(
        ctx, false,
        [](HookContext& c) {
            c.rax = 2;
            throw std::runtime_error("x");
        },
        RecordingReporter, &log);
    EXPECT_EQ(log.calls, 1);
    EXPECT_EQ(log.fault, HookFault::Exception);
    EXPECT_EQ(log.rax_seen, rax);

    RunHookHandler(
        ctx, false, [](HookContext& c) { c.ReturnFromFunction(3); }, RecordingReporter, &log);
    EXPECT_EQ(log.calls, 2);
    EXPECT_EQ(log.fault, HookFault::ReturnAtMidSite);
    EXPECT_EQ(log.rax_seen, rax);
}

TEST(HookGuardTest, SwallowsWhatTheReporterThrows) {
    HookContext ctx = MakeContext();
    const auto result = RunHookHandler(
        ctx, false, [](HookContext&) { throw 1; },
        [](const HookRunResult&, void*) { throw std::runtime_error("reporter"); }, nullptr);
    EXPECT_EQ(result.fault, HookFault::UnknownException);
}

namespace {
struct GuestProbe {
    std::function<void(HookContext&)> handler;
    HookRunResult result;
    int calls = 0;
    std::uint64_t base_in_handler = 0;
    std::uint64_t limit_in_handler = 1;
    std::uint64_t base_after = 1;
    std::uint64_t limit_after = 1;
    int reports = 0;
    HookFault reported = HookFault::None;
    bool uncatchable_outside = false; ///< CppThrowIsUncatchable before the guard.
    bool uncatchable_inside = true;   ///< CppThrowIsUncatchable inside the handler.
};

/// Like the runtime's fault logger, except that it throws as well: that must not escape either.
void ThrowingReporter(const HookRunResult& result, void* user) {
    auto* probe = static_cast<GuestProbe*>(user);
    ++probe->reports;
    probe->reported = result.fault;
    throw std::runtime_error("the reporter throws too");
}

/// The detour callback: what the runtime's hook thunk does.
void BBCOOP_SYSV_ABI GuardedCallback(HookContext* ctx, void* user) {
    auto* probe = static_cast<GuestProbe*>(user);
    ++probe->calls;
    probe->uncatchable_outside = CppThrowIsUncatchable(CurrentStackBounds());
    probe->result = RunHookHandler(*ctx, false, probe->handler, ThrowingReporter, probe);
    probe->base_after = TebStackBase();
    probe->limit_after = TebStackLimit();
}

class Allocation {
public:
    Allocation(std::size_t size, DWORD protect)
        : base_{static_cast<std::uint8_t*>(
              VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protect))},
          size_{size} {}
    ~Allocation() {
        if (base_ != nullptr) {
            VirtualFree(base_, 0, MEM_RELEASE);
        }
    }
    Allocation(const Allocation&) = delete;
    Allocation& operator=(const Allocation&) = delete;
    std::uint8_t* Get() const {
        return base_;
    }
    std::uint8_t* End() const {
        return base_ + size_;
    }

private:
    std::uint8_t* base_;
    std::size_t size_;
};
} // namespace

// What a shadPS4 guest thread looks like (core/libraries/kernel/threads/stack_asm.cpp): the code
// runs on a stack the emulator allocated, with the TEB stack bounds set to 0. A C++ exception
// thrown by a hook handler there must be caught by the guard, and the guest must go on.
TEST(HookGuardTest, CatchesAnExceptionThrownOnAGuestStackWithZeroTebBounds) {
    using namespace Xbyak::util;
    Allocation code(0x10000, PAGE_EXECUTE_READWRITE);
    Allocation stack(0x40000, PAGE_READWRITE);
    ASSERT_NE(code.Get(), nullptr) << GetLastError();
    ASSERT_NE(stack.Get(), nullptr) << GetLastError();
    std::uint8_t* const trampoline = code.Get() + 0x8000;
    auto* const saved_rsp = reinterpret_cast<std::uint64_t*>(code.Get() + 0x4000);
    std::uint8_t* const stack_top = stack.End() - 0x100;

    // std::uint64_t guest(std::uint64_t x) { switch to the private stack; rax = x; [site];
    // rax += 1; switch back; return rax; }
    Xbyak::CodeGenerator g(0x1000, code.Get());
    g.mov(qword[rip + saved_rsp], rsp);
    g.mov(rax, reinterpret_cast<std::uint64_t>(stack_top));
    g.mov(rsp, rax);
    g.mov(rax, rcx);
    std::uint8_t* const site = const_cast<std::uint8_t*>(g.getCurr());
    g.nop(5);
    g.add(rax, 1);
    g.mov(rsp, qword[rip + saved_rsp]);
    g.ret();

    GuestProbe probe;
    probe.handler = [&probe](HookContext& c) {
        probe.base_in_handler = TebStackBase();
        probe.limit_in_handler = TebStackLimit();
        probe.uncatchable_inside = CppThrowIsUncatchable(CurrentStackBounds());
        c.rax = 0xDEAD;
        throw std::runtime_error("boom from the guest stack");
    };
    const DetourRequest request{reinterpret_cast<std::uint64_t>(site),
                                std::span<const std::uint8_t>(site, 5), GuardedCallback, &probe};
    const auto detour = BuildDetour(request, trampoline, kMaxTrampolineSize);
    ASSERT_TRUE(detour.has_value()) << detour.error();
    std::memcpy(site, detour->site_patch.data(), detour->site_patch_size);
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);

    const std::uint64_t host_base = TebStackBase();
    const std::uint64_t host_limit = TebStackLimit();
    SetTebStackBounds(0, 0);
    const std::uint64_t out = reinterpret_cast<std::uint64_t (*)(std::uint64_t)>(code.Get())(41);
    SetTebStackBounds(host_base, host_limit);

    EXPECT_EQ(probe.calls, 1);
    EXPECT_EQ(out, 42u) << "the guest did not resume with its own rax";
    EXPECT_EQ(probe.result.fault, HookFault::Exception);
    EXPECT_EQ(probe.result.Message(), "boom from the guest stack");
    EXPECT_EQ(probe.reports, 1);
    EXPECT_EQ(probe.reported, HookFault::Exception);
    EXPECT_EQ(probe.limit_in_handler, 0u);
    EXPECT_GT(probe.base_in_handler, reinterpret_cast<std::uint64_t>(stack.Get()));
    EXPECT_LE(probe.base_in_handler, reinterpret_cast<std::uint64_t>(stack_top))
        << "the bounds must end on the guest stack, below the guest's own frames";
    EXPECT_EQ(probe.base_after, 0u) << "the guest's TEB stack base was not restored";
    EXPECT_EQ(probe.limit_after, 0u) << "the guest's TEB stack limit was not restored";
    // What the emulator's exception handler tells apart (0B-R47): a throw on the guest stack
    // outside the guard can never be caught, one inside it can.
    EXPECT_TRUE(probe.uncatchable_outside);
    EXPECT_FALSE(probe.uncatchable_inside);
}

TEST(HookGuardTest, RefusesSkipStolenWhereTheStolenBytesEndWithATransfer) {
    HookContext ctx = MakeContext();
    const HookContext before = ctx;
    const auto result =
        RunHookHandler(ctx, HookSiteRules{.ends_with_transfer = true}, [](HookContext& c) {
            c.rax = 3;
            c.SkipStolenInstructions();
        });
    EXPECT_EQ(result.fault, HookFault::SkipPastFunctionEnd);
    EXPECT_TRUE(SameContext(ctx, before));
    EXPECT_EQ(ctx.action, HookAction::Continue);
}

TEST(HookGuardTest, AllowsTheOtherActionsWhereTheStolenBytesEndWithATransfer) {
    // Continue runs the stolen jump or ret itself; ReturnFromFunction at an entry returns first.
    const HookSiteRules rules{.function_entry = true, .ends_with_transfer = true};
    HookContext ctx = MakeContext();
    EXPECT_EQ(RunHookHandler(ctx, rules, [](HookContext& c) { c.rax = 1; }).fault, HookFault::None);
    EXPECT_EQ(ctx.rax, 1u);
    EXPECT_EQ(RunHookHandler(ctx, rules, [](HookContext& c) { c.ReturnFromFunction(2); }).fault,
              HookFault::None);
    EXPECT_EQ(ctx.action, HookAction::ReturnFromFunction);
    // Without the rule SkipStolen is fine.
    ctx = MakeContext();
    EXPECT_EQ(
        RunHookHandler(ctx, HookSiteRules{}, [](HookContext& c) { c.SkipStolenInstructions(); })
            .fault,
        HookFault::None);
    EXPECT_EQ(ctx.action, HookAction::SkipStolen);
}

TEST(HookGuardTest, ReportsTheCallingThreadsTebStackBounds) {
    const auto bounds = CurrentStackBounds();
    EXPECT_EQ(bounds.base, TebStackBase());
    EXPECT_EQ(bounds.limit, TebStackLimit());
    // An ordinary host thread: the current frame lies inside the bounds.
    int local = 0;
    const auto here = reinterpret_cast<std::uint64_t>(&local);
    EXPECT_LT(here, bounds.base);
    EXPECT_GE(here, bounds.limit);
    EXPECT_FALSE(CppThrowIsUncatchable(bounds));
}

TEST(HookGuardTest, ACppThrowIsUncatchableOnlyWithBothBoundsZero) {
    static_assert(CppThrowIsUncatchable({}));
    EXPECT_TRUE(CppThrowIsUncatchable({.base = 0, .limit = 0}));
    EXPECT_FALSE(CppThrowIsUncatchable({.base = 0x7000, .limit = 0})); // inside RunHookHandler
    EXPECT_FALSE(CppThrowIsUncatchable({.base = 0x7000, .limit = 0x1000}));
}
