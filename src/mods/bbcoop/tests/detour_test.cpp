// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

// The detours are built and executed on the host: the "guest" is machine code written into an
// executable arena (by hand or with Xbyak), hooked and then called as an ordinary function.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>

#include <gtest/gtest.h>
#include <xbyak/xbyak.h>
#include <xmmintrin.h>
#include <windows.h>

#include "bbcoop/binding/detour.h"
#include "bbcoop/binding/relocator.h"

using namespace BBCoop::Binding;

namespace {
class Arena {
public:
    Arena()
        : base_(static_cast<std::uint8_t*>(VirtualAlloc(
              nullptr, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {}
    ~Arena() {
        if (base_ != nullptr) {
            VirtualFree(base_, 0, MEM_RELEASE);
        }
    }
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;

    std::uint8_t* Code() {
        return base_;
    }
    std::uint8_t* Data() {
        return base_ + 0x4000;
    }
    std::uint8_t* Trampoline() {
        return base_ + 0x8000;
    }
    static constexpr std::size_t kSize = 0x10000;

private:
    std::uint8_t* base_;
};

class DetourTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_NE(a.Code(), nullptr) << "VirtualAlloc failed: " << GetLastError();
    }

    Arena a;
};

using Fn = std::uint64_t (*)(std::uint64_t);
using VoidFn = void (*)();

void Emit(std::uint8_t* at, std::initializer_list<std::uint8_t> bytes) {
    std::memcpy(at, bytes.begin(), bytes.size());
}

/// A request that steals the `length` bytes at `site`.
DetourRequest Steal(const std::uint8_t* site, std::size_t length, HookCallback cb,
                    void* user = nullptr) {
    return {reinterpret_cast<std::uint64_t>(site), std::span<const std::uint8_t>(site, length), cb,
            user};
}

/// Builds the detour for `request` into the arena's trampoline area.
std::expected<DetourCode, std::string> Build(Arena& arena, const DetourRequest& request) {
    return BuildDetour(request, arena.Trampoline(), kMaxTrampolineSize);
}

/// Steals the shortest whole instructions covering 5 bytes at `site`, builds the detour and
/// applies its patch to the site.
void Hook(Arena& arena, std::uint8_t* site, HookCallback cb, void* user) {
    const auto steal = StealLength(std::span<const std::uint8_t>(site, 32), 5);
    ASSERT_TRUE(steal.has_value()) << steal.error();
    const auto code = Build(arena, Steal(site, *steal, cb, user));
    ASSERT_TRUE(code.has_value()) << code.error();
    std::memcpy(site, code->site_patch.data(), code->site_patch_size);
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
}

struct Probe {
    int calls = 0;
    std::uint64_t site = 0;
    std::uint64_t seen_xmm0 = 0;
    std::uint64_t ctx_address = 0;
    std::uint64_t guest_rsp = 0;
    std::uint32_t mxcsr = 0;
    std::uint64_t host_rflags = 0;
    std::uint64_t guest_rflags = 0;
    HookAction initial_action = HookAction::ReturnFromFunction;
    std::uint64_t gpr[15] = {};
    std::uint8_t ymm1[32] = {};
};

/// Every general register of the context but rsp, in the order of the tests' register tables.
std::array<std::uint64_t*, 15> GprSlots(HookContext& ctx) {
    return {&ctx.rax, &ctx.rbx, &ctx.rcx, &ctx.rdx, &ctx.rsi, &ctx.rdi, &ctx.rbp, &ctx.r8,
            &ctx.r9,  &ctx.r10, &ctx.r11, &ctx.r12, &ctx.r13, &ctx.r14, &ctx.r15};
}

// The callbacks are plain functions: they are System V functions called by the trampoline.

void BBCOOP_SYSV_ABI AddTenToRcx(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    ++p->calls;
    p->site = ctx->site;
    ctx->rcx += 10;
}

void BBCOOP_SYSV_ABI CountCalls(HookContext*, void* user) {
    ++static_cast<Probe*>(user)->calls;
}

void BBCOOP_SYSV_ABI SetRaxAndSkipStolen(HookContext* ctx, void*) {
    ctx->rax = 7;
    ctx->SkipStolenInstructions();
}

void BBCOOP_SYSV_ABI ReturnFortyTwo(HookContext* ctx, void*) {
    ctx->ReturnFromFunction(42);
}

void BBCOOP_SYSV_ABI ClobberFlagsOnHost(HookContext* ctx, void*) {
    volatile std::uint64_t x = ctx->rcx;
    x = (x > 3) ? x * 3 : x + 1; // clobbers flags in host code
    (void)x;
}

void BBCOOP_SYSV_ABI SetZeroFlagWhenRcxIsSix(HookContext* ctx, void*) {
    if (ctx->rcx == 6) {
        ctx->rflags |= 0x40; // ZF
    }
}

void BBCOOP_SYSV_ABI SwapXmm0(HookContext* ctx, void* user) {
    std::memcpy(&static_cast<Probe*>(user)->seen_xmm0, ctx->ymm[0].data(), 8);
    const std::uint64_t replacement = 0xABCD;
    std::memcpy(ctx->ymm[0].data(), &replacement, 8);
}

void BBCOOP_SYSV_ABI SkipWhenRcxIsOne(HookContext* ctx, void*) {
    if (ctx->rcx == 1) {
        ctx->rax = 7;
        ctx->SkipStolenInstructions();
    }
}

void BBCOOP_SYSV_ABI ZeroRcxWhenSix(HookContext* ctx, void*) {
    if (ctx->rcx == 6) {
        ctx->rcx = 0;
    }
}

void BBCOOP_SYSV_ABI RecordContext(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    p->ctx_address = reinterpret_cast<std::uint64_t>(ctx);
    p->guest_rsp = ctx->rsp;
    p->initial_action = ctx->action;
}

void BBCOOP_SYSV_ABI RecordAndIncrementGprs(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    p->guest_rsp = ctx->rsp;
    const auto slots = GprSlots(*ctx);
    for (int i = 0; i < 15; ++i) {
        p->gpr[i] = *slots[i];
        *slots[i] += 1;
    }
}

void BBCOOP_SYSV_ABI ScribbleOnStack(HookContext*, void*) {
    volatile std::uint8_t scratch[1024];
    for (auto& byte : scratch) {
        byte = 0xEE;
    }
}

void BBCOOP_SYSV_ABI ChangeMxcsr(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    p->mxcsr = ctx->mxcsr;
    // The context wins over whatever the host code leaves in the register.
    _mm_setcsr(ctx->mxcsr ^ 0x4000);
    ctx->mxcsr ^= 0x2000;
}

void BBCOOP_SYSV_ABI RecordFlags(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    p->host_rflags = __builtin_ia32_readeflags_u64();
    p->guest_rflags = ctx->rflags;
}

void BBCOOP_SYSV_ABI EditYmm1(HookContext* ctx, void* user) {
    auto* p = static_cast<Probe*>(user);
    std::memcpy(p->ymm1, ctx->ymm[1].data(), 32);
    ctx->ymm[1][0] = 0x55;
    ctx->ymm[1][31] = 0x77;
}

/// Restores the thread's MXCSR when a test that changes it ends.
class MxcsrGuard {
public:
    MxcsrGuard() : saved_(_mm_getcsr()) {}
    ~MxcsrGuard() {
        _mm_setcsr(saved_);
    }
    MxcsrGuard(const MxcsrGuard&) = delete;
    MxcsrGuard& operator=(const MxcsrGuard&) = delete;
    unsigned Saved() const {
        return saved_;
    }

private:
    unsigned saved_;
};
} // namespace

TEST_F(DetourTest, ModifiesRegisterAndContinues) {
    // lea rax,[rcx+1]; add rax,2; ret
    Emit(a.Code(), {0x48, 0x8D, 0x41, 0x01, 0x48, 0x83, 0xC0, 0x02, 0xC3});
    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), AddTenToRcx, &probe));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(5), 18u);
    EXPECT_EQ(probe.calls, 1);
    EXPECT_EQ(probe.site, reinterpret_cast<std::uint64_t>(a.Code()));
}

TEST_F(DetourTest, RelocatesRipRelativeStolenInstruction) {
    const std::uint64_t value = 0x1122334455667788;
    std::memcpy(a.Data(), &value, sizeof(value));
    const auto disp = static_cast<std::int32_t>(a.Data() - (a.Code() + 7));
    std::uint8_t code[8] = {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3}; // mov rax,[rip+disp]; ret
    std::memcpy(code + 3, &disp, 4);
    std::memcpy(a.Code(), code, sizeof(code));
    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), CountCalls, &probe));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(0), value);
    EXPECT_EQ(probe.calls, 1);
}

TEST_F(DetourTest, SkipsStolenInstructions) {
    // mov rax,rcx; add rax,100; ret
    Emit(a.Code(), {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x64, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), SetRaxAndSkipStolen, nullptr));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(1), 7u);
}

TEST_F(DetourTest, ReturnsFromFunctionAtEntry) {
    Emit(a.Code(), {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x64, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), ReturnFortyTwo, nullptr));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(1), 42u);
}

TEST_F(DetourTest, PreservesFlagsAtMidFunctionSite) {
    // cmp rcx,5; [site] mov eax,0; sete al; ret
    Emit(a.Code(), {0x48, 0x83, 0xF9, 0x05, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x94, 0xC0, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code() + 4, ClobberFlagsOnHost, nullptr));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(5), 1u);
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(6), 0u);
}

TEST_F(DetourTest, RflagsAreWritable) {
    // cmp rcx,5; [site] mov eax,0; sete al; ret
    Emit(a.Code(), {0x48, 0x83, 0xF9, 0x05, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x94, 0xC0, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code() + 4, SetZeroFlagWhenRcxIsSix, nullptr));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(5), 1u);
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(6), 1u); // ZF forced by the callback
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(7), 0u);
}

TEST_F(DetourTest, ExposesAndRestoresVectorRegisters) {
    // movq xmm0,rcx; [site] 5x nop; movq rax,xmm0; ret
    Emit(a.Code(), {0x66, 0x48, 0x0F, 0x6E, 0xC1, 0x90, 0x90, 0x90, 0x90, 0x90, 0x66, 0x48, 0x0F,
                    0x7E, 0xC0, 0xC3});
    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code() + 5, SwapXmm0, &probe));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(0x1234), 0xABCDu);
    EXPECT_EQ(probe.seen_xmm0, 0x1234u);
}

TEST_F(DetourTest, RejectsTooShortStolenBytes) {
    Emit(a.Code(), {0x90, 0x90, 0x90, 0x90});
    const auto code = Build(a, Steal(a.Code(), 4, CountCalls));
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("5..16"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsTooLongStolenBytes) {
    std::memset(a.Code(), 0x90, 17);
    const auto code = Build(a, Steal(a.Code(), 17, CountCalls));
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("5..16"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsNullCallback) {
    std::memset(a.Code(), 0x90, 5);
    const auto code = Build(a, Steal(a.Code(), 5, nullptr));
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("callback"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsStolenBytesThatSplitAnInstruction) {
    // mov rax,[rip+0x10] cut after 5 of its 7 bytes.
    Emit(a.Code(), {0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00});
    const auto code = Build(a, Steal(a.Code(), 5, CountCalls));
    EXPECT_FALSE(code.has_value());
}

TEST_F(DetourTest, RejectsInstructionsTheRelocatorRefuses) {
    // mov rax, fs:[0]: the emulator patches FS accesses lazily, a trampoline copy would not be.
    Emit(a.Code(), {0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00});
    const auto code = Build(a, Steal(a.Code(), 9, CountCalls));
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("FS"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsTrampolineOutOfReachOfTheSite) {
    std::memset(a.Code(), 0x90, 5);
    const auto far_site = reinterpret_cast<std::uint64_t>(a.Trampoline()) + 0x1'0000'0000ull;
    auto request = Steal(a.Code(), 5, CountCalls);
    request.site = far_site;
    const auto code = Build(a, request);
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("rel32"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsJumpBackOutOfReachWhenOnlyTheSitePatchReaches) {
    std::memset(a.Code(), 0x90, 5);
    // The site's JMP rel32 just reaches the trampoline, but the jump back from the end of the
    // trampoline (some 800 bytes further on) to the site does not.
    auto request = Steal(a.Code(), 5, CountCalls);
    request.site = reinterpret_cast<std::uint64_t>(a.Trampoline()) - 0x7FFF'FFF0ull - 5;
    const auto code = Build(a, request);
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("xbyak"), std::string::npos) << code.error();
}

TEST_F(DetourTest, RejectsNullTrampolineBuffer) {
    std::memset(a.Code(), 0x90, 5);
    const auto code = BuildDetour(Steal(a.Code(), 5, CountCalls), nullptr, kMaxTrampolineSize);
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("null"), std::string::npos) << code.error();
}

TEST_F(DetourTest, NeverWritesPastTheCapacity) {
    std::memset(a.Code(), 0x90, 5);
    constexpr std::size_t kCapacity = 64;
    std::memset(a.Trampoline(), 0xA5, 2 * kCapacity);
    const auto code = BuildDetour(Steal(a.Code(), 5, CountCalls), a.Trampoline(), kCapacity);
    ASSERT_FALSE(code.has_value());
    EXPECT_NE(code.error().find("xbyak"), std::string::npos) << code.error();
    for (std::size_t i = kCapacity; i < 2 * kCapacity; ++i) {
        ASSERT_EQ(a.Trampoline()[i], 0xA5) << "trampoline byte " << i << " was overwritten";
    }
}

TEST_F(DetourTest, DescribesTheSitePatch) {
    const std::uint64_t value = 0;
    std::memcpy(a.Data(), &value, sizeof(value));
    const auto disp = static_cast<std::int32_t>(a.Data() - (a.Code() + 7));
    std::uint8_t code[8] = {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xC3}; // mov rax,[rip+disp]; ret
    std::memcpy(code + 3, &disp, 4);
    std::memcpy(a.Code(), code, sizeof(code));
    const auto detour = Build(a, Steal(a.Code(), 7, CountCalls));
    ASSERT_TRUE(detour.has_value()) << detour.error();
    EXPECT_GT(detour->trampoline_size, 0u);
    EXPECT_LE(detour->trampoline_size, kMaxTrampolineSize);
    ASSERT_EQ(detour->site_patch_size, 7u); // the stolen length, padded with NOPs
    EXPECT_EQ(detour->site_patch[0], 0xE9);
    std::int32_t rel32 = 0;
    std::memcpy(&rel32, detour->site_patch.data() + 1, sizeof(rel32));
    EXPECT_EQ(static_cast<std::int64_t>(rel32), a.Trampoline() - (a.Code() + 5));
    EXPECT_EQ(detour->site_patch[5], 0x90);
    EXPECT_EQ(detour->site_patch[6], 0x90);
    // The detour builder itself leaves the site alone.
    EXPECT_EQ(std::memcmp(a.Code(), code, sizeof(code)), 0);
}

TEST_F(DetourTest, LargestRequestFitsTheTrampolineBudget) {
    // Eight short conditional jumps: each is widened from 2 to 6 bytes, the largest growth a
    // 16-byte stolen region can have. Their targets are outside the region.
    for (int i = 0; i < 8; ++i) {
        a.Code()[2 * i] = 0x74;
        a.Code()[2 * i + 1] = 0x40;
    }
    const auto detour = Build(a, Steal(a.Code(), 16, CountCalls));
    ASSERT_TRUE(detour.has_value()) << detour.error();
    EXPECT_LE(detour->trampoline_size, kMaxTrampolineSize);
}

TEST_F(DetourTest, SavesAndRestoresEveryGeneralRegister) {
    using namespace Xbyak::util;
    constexpr std::uint64_t kBase = 0x1111'0000'0000'0100ull;
    const Xbyak::Reg64 regs[15] = {rax, rbx, rcx, rdx, rsi, rdi, rbp, r8,
                                   r9,  r10, r11, r12, r13, r14, r15};
    const Xbyak::Reg64 callee_saved[] = {rbx, rbp, rdi, rsi, r12, r13, r14, r15}; // Windows x64
    std::uint64_t* const stored = reinterpret_cast<std::uint64_t*>(a.Data());

    Xbyak::CodeGenerator g(0x1000, a.Code());
    for (const auto& reg : callee_saved) {
        g.push(reg);
    }
    for (int i = 0; i < 15; ++i) {
        g.mov(regs[i], kBase + 0x10 * i);
    }
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    for (int i = 0; i < 15; ++i) {
        g.mov(qword[rip + &stored[i]], regs[i]);
    }
    g.mov(qword[rip + &stored[15]], rsp);
    for (int i = 7; i >= 0; --i) {
        g.pop(callee_saved[i]);
    }
    g.ret();

    Probe probe;
    ASSERT_NO_FATAL_FAILURE(
        Hook(a, const_cast<std::uint8_t*>(site), RecordAndIncrementGprs, &probe));
    reinterpret_cast<VoidFn>(a.Code())();

    for (int i = 0; i < 15; ++i) {
        SCOPED_TRACE(i);
        EXPECT_EQ(probe.gpr[i], kBase + 0x10 * i) << "the callback saw a wrong value";
        EXPECT_EQ(stored[i], kBase + 0x10 * i + 1) << "the guest saw a wrong value";
    }
    EXPECT_EQ(probe.guest_rsp, stored[15]);
}

TEST_F(DetourTest, LeavesTheRedZoneAlone) {
    using namespace Xbyak::util;
    constexpr std::uint64_t kBase = 0x7777'0000'0000'0000ull;
    std::uint64_t* const seen = reinterpret_cast<std::uint64_t*>(a.Data());

    Xbyak::CodeGenerator g(0x1000, a.Code());
    for (int i = 1; i <= 16; ++i) {
        g.mov(rax, kBase + i);
        g.mov(qword[rsp - 8 * i], rax);
    }
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    for (int i = 1; i <= 16; ++i) {
        g.mov(rax, qword[rsp - 8 * i]);
        g.mov(qword[rip + &seen[i - 1]], rax);
    }
    g.ret();

    ASSERT_NO_FATAL_FAILURE(Hook(a, const_cast<std::uint8_t*>(site), ScribbleOnStack, nullptr));
    reinterpret_cast<VoidFn>(a.Code())();
    for (int i = 1; i <= 16; ++i) {
        EXPECT_EQ(seen[i - 1], kBase + i) << "[rsp-" << 8 * i << "]";
    }
}

TEST_F(DetourTest, AlignsTheContextForAnyGuestStackAlignment) {
    using namespace Xbyak::util;
    // sub rsp,rcx; [site] nop; add rsp,rcx; ret: rcx moves the guest rsp off any alignment.
    Xbyak::CodeGenerator g(0x1000, a.Code());
    g.sub(rsp, rcx);
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    g.add(rsp, rcx);
    g.ret();

    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, const_cast<std::uint8_t*>(site), RecordContext, &probe));
    reinterpret_cast<Fn>(a.Code())(0);
    const std::uint64_t rsp_at_zero = probe.guest_rsp;
    for (std::uint64_t shift = 0; shift < 32; ++shift) {
        SCOPED_TRACE(shift);
        reinterpret_cast<Fn>(a.Code())(shift);
        EXPECT_EQ(probe.ctx_address % 32, 0u);
        EXPECT_EQ(probe.guest_rsp, rsp_at_zero - shift);
    }
}

TEST_F(DetourTest, ActionIsResetOnEveryCall) {
    // mov rax,rcx; add rax,100; ret
    Emit(a.Code(), {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x64, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), SkipWhenRcxIsOne, nullptr));
    // Back to back, so the second context lands on the stack bytes of the first one, which
    // asked to skip. A trampoline that does not reset the action would skip again.
    const std::uint64_t first = reinterpret_cast<Fn>(a.Code())(1);
    const std::uint64_t second = reinterpret_cast<Fn>(a.Code())(2);
    EXPECT_EQ(first, 7u);
    EXPECT_EQ(second, 102u);
}

TEST_F(DetourTest, CallbackSeesContinueAsTheInitialAction) {
    Emit(a.Code(), {0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x64, 0xC3});
    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), RecordContext, &probe));
    reinterpret_cast<Fn>(a.Code())(1);
    EXPECT_EQ(probe.initial_action, HookAction::Continue);
}

TEST_F(DetourTest, ClearsTheDirectionFlagForTheCallbackAndRestoresIt) {
    using namespace Xbyak::util;
    constexpr std::uint64_t kDirectionFlag = 0x400;
    // std; [site] nop; pushfq; pop rax; cld; ret
    Xbyak::CodeGenerator g(0x1000, a.Code());
    g.std();
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    g.pushfq();
    g.pop(rax);
    g.cld();
    g.ret();

    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, const_cast<std::uint8_t*>(site), RecordFlags, &probe));
    const std::uint64_t flags_after = reinterpret_cast<Fn>(a.Code())(0);
    EXPECT_EQ(probe.host_rflags & kDirectionFlag, 0u) << "System V requires DF clear in a callee";
    EXPECT_NE(probe.guest_rflags & kDirectionFlag, 0u) << "the context holds the guest's flags";
    EXPECT_NE(flags_after & kDirectionFlag, 0u) << "the guest's flags are restored";
}

TEST_F(DetourTest, ExposesAndRestoresMxcsr) {
    using namespace Xbyak::util;
    const MxcsrGuard guard;
    std::uint32_t* const stored = reinterpret_cast<std::uint32_t*>(a.Data());
    Xbyak::CodeGenerator g(0x1000, a.Code());
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    g.stmxcsr(dword[rip + stored]);
    g.ret();

    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, const_cast<std::uint8_t*>(site), ChangeMxcsr, &probe));
    reinterpret_cast<VoidFn>(a.Code())();
    EXPECT_EQ(probe.mxcsr, guard.Saved());
    EXPECT_EQ(*stored, guard.Saved() ^ 0x2000u);
}

TEST_F(DetourTest, ExposesAndRestoresTheUpperHalfOfYmmRegisters) {
    using namespace Xbyak::util;
    std::uint8_t pattern[32];
    for (int i = 0; i < 32; ++i) {
        pattern[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    std::memcpy(a.Data(), pattern, sizeof(pattern));
    std::uint8_t* const out = a.Data() + 64;

    Xbyak::CodeGenerator g(0x1000, a.Code());
    g.vmovdqu(ymm1, ptr[rip + a.Data()]);
    const std::uint8_t* const site = g.getCurr();
    g.nop(5);
    g.vmovdqu(ptr[rip + out], ymm1);
    g.vzeroupper();
    g.ret();

    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, const_cast<std::uint8_t*>(site), EditYmm1, &probe));
    reinterpret_cast<VoidFn>(a.Code())();
    EXPECT_EQ(std::memcmp(probe.ymm1, pattern, 32), 0);
    pattern[0] = 0x55;
    pattern[31] = 0x77;
    EXPECT_EQ(std::memcmp(out, pattern, 32), 0);
}

TEST_F(DetourTest, RunsRelocatedCallAndContinuesAfterItReturns) {
    // [site] call helper; add rax,100; ret ... helper: lea rax,[rcx+7]; ret
    Emit(a.Code(), {0xE8, 0xFB, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x64, 0xC3});
    Emit(a.Code() + 0x100, {0x48, 0x8D, 0x41, 0x07, 0xC3});
    Probe probe;
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), AddTenToRcx, &probe));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(5), 5u + 10 + 7 + 100);
    EXPECT_EQ(probe.calls, 1);
}

TEST_F(DetourTest, RunsRelocatedConditionalJumpWithTheFlagsOfTheStolenCompare) {
    // [site] cmp rcx,0; jz +6 -> mov eax,11; ret ... else: mov eax,22; ret
    Emit(a.Code(), {0x48, 0x83, 0xF9, 0x00, 0x74, 0x06, 0xB8, 0x16, 0x00, 0x00, 0x00, 0xC3,
                    0xB8, 0x0B, 0x00, 0x00, 0x00, 0xC3});
    ASSERT_NO_FATAL_FAILURE(Hook(a, a.Code(), ZeroRcxWhenSix, nullptr));
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(0), 11u);
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(1), 22u);
    EXPECT_EQ(reinterpret_cast<Fn>(a.Code())(6), 11u); // the callback zeroed rcx before the compare
}
