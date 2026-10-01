// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

/// Calling convention of detour callbacks. The guest is System V code and the callbacks are called
/// from a trampoline that follows System V (rdi = context, rsi = user data), while the host
/// compiler targets Windows x64 by default.
#define BBCOOP_SYSV_ABI __attribute__((sysv_abi))

namespace BBCoop::Binding {

/// What the trampoline does after the callback returns.
enum class HookAction : std::uint32_t {
    /// Restore the context, run the stolen instructions, continue after them.
    Continue = 0,
    /// Restore the context and continue after the stolen instructions.
    SkipStolen = 1,
    /// Restore the context and RET to the caller.
    ReturnFromFunction = 2,
};

/// The register state at the hooked instruction. The trampoline builds it on the guest stack,
/// passes it to the callback and restores every register, RFLAGS, MXCSR and YMM0-15 from it
/// afterwards, so a callback changes guest state by writing here.
///
/// Contract of the fields:
///  - rsp is the guest stack pointer at the site. The trampoline works below rsp - 128 (the System
///    V red zone is left alone) and a changed rsp takes effect when the guest code resumes.
///  - rflags: change only the status flags (CF, PF, AF, ZF, SF, OF) and DF. Other bits go to POPFQ
///    as written, with whatever effect the CPU gives them (TF, for one, traps the guest).
///  - site is information only. Writing it has no effect: there is no redirection of rip.
///  - mxcsr is the guest's MXCSR. The callback itself runs with the default value 0x1F80 (round to
///    nearest, all exceptions masked, FTZ/DAZ off), so host code in it is not subject to the
///    guest's rounding mode; game code it calls must be run with the guest's value again
///    (RunHookHandler records it for CallWithGuestMxcsr, see guest_mxcsr.h). Bits 31:16 are
///    reserved: the trampoline clears them before it loads
///    the value back, so a stray write cannot fault, but it should not set them. The x87 control
///    word and stack are not part of the context; a callback runs with the guest's x87 state and
///    must leave the x87 stack as it found it.
///  - action starts as Continue. Any value other than the HookAction enumerators behaves as
///    Continue.
///  - reserved is zero on entry, and writes to it are ignored.
struct alignas(32) HookContext {
    std::uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    std::uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    std::uint64_t rflags;
    std::uint64_t site; ///< Address of the hooked instruction; read-only in effect.
    std::uint32_t mxcsr;
    HookAction action; ///< Set to Continue before the callback runs; the last request wins.
    std::uint64_t reserved;
    /// YMM0-15, low 16 bytes = XMM. alignas(32): the trampoline saves them with aligned stores.
    alignas(32) std::array<std::array<std::uint8_t, 32>, 16> ymm;

    /// Continue after the stolen instructions without running them.
    void SkipStolenInstructions() {
        action = HookAction::SkipStolen;
    }

    /// Return from the hooked function with `value` in rax: the trampoline restores the context
    /// and executes RET at the guest stack pointer. Only meaningful at the first instruction of a
    /// function (FunctionEntry sites), where [rsp] is the return address; the hook installer
    /// refuses it elsewhere.
    void ReturnFromFunction(std::uint64_t value) {
        rax = value;
        action = HookAction::ReturnFromFunction;
    }
};
static_assert(sizeof(HookContext) % 32 == 0);
static_assert(alignof(HookContext) == 32);

/// Called on the guest thread with the guest stack in use, so it must not throw: an exception
/// that leaves a callback would unwind into guest frames. The hook installer wraps callbacks.
using HookCallback = void BBCOOP_SYSV_ABI (*)(HookContext* ctx, void* user);

struct DetourRequest {
    std::uint64_t site;                   ///< Address of the first stolen instruction.
    std::span<const std::uint8_t> stolen; ///< Whole instructions at `site`, 5..16 bytes.
    HookCallback callback;
    void* user; ///< Passed to the callback as is.
};

struct DetourCode {
    std::size_t trampoline_size;               ///< Bytes written to the trampoline buffer.
    std::array<std::uint8_t, 16> site_patch;   ///< JMP rel32 to the trampoline, padded with NOPs.
    std::size_t site_patch_size;               ///< Equals the stolen length; write it at `site`.
};

/// Upper bound of trampoline_size for any request, and the buffer size to give BuildDetour.
constexpr std::size_t kMaxTrampolineSize = 1024;

/// Writes the trampoline for `request` to `trampoline` (`capacity` writable bytes at its final
/// address) and returns the bytes to write over the stolen instructions. Nothing is written at
/// the site: the caller applies `site_patch` itself, only after this succeeded.
///
/// The trampoline saves the context (all GPRs, RFLAGS, MXCSR, YMM0-15), calls the callback with
/// the System V convention and then, per HookContext::action, runs the relocated stolen
/// instructions and jumps to site + stolen.size(), jumps there directly, or executes RET. It needs
/// AVX. The trampoline must be within +-2 GiB of the site (the site's JMP rel32 and the jump back
/// both have to reach).
///
/// Fails when the stolen length is outside 5..16, the callback or the buffer is null, the stolen
/// instructions cannot be relocated (see RelocateInstructions), the trampoline is out of rel32
/// reach of the site or `capacity` is too small. A failed build may leave partial bytes in the
/// buffer; they are never reachable, since the site is only patched on success.
std::expected<DetourCode, std::string> BuildDetour(const DetourRequest& request,
                                                   std::uint8_t* trampoline, std::size_t capacity);

} // namespace BBCoop::Binding
