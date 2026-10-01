// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/detour.h"

#include <cstddef>
#include <cstring>
#include <format>
#include <limits>

#include <xbyak/xbyak.h>

#include "bbcoop/binding/relocator.h"

namespace BBCoop::Binding {

namespace {
// The context is saved with aligned stores and sits at a 32-byte aligned stack address.
static_assert(offsetof(HookContext, ymm) % 32 == 0);
// The System V red zone below the guest's rsp, which the guest may be using at the site.
constexpr std::uint32_t kRedZone = 128;
// MXCSR the callback runs with: the power-on default (round to nearest, all exceptions masked, no
// FTZ/DAZ), not whatever the guest had set.
constexpr std::uint32_t kHostMxcsr = 0x1F80;
// The bits of MXCSR a CPU with AVX accepts in LDMXCSR (MXCSR_MASK is 0xFFFF there); bits 31:16 are
// reserved and raise #GP when set.
constexpr std::uint32_t kMxcsrWritableBits = 0xFFFF;
} // namespace

std::expected<DetourCode, std::string> BuildDetour(const DetourRequest& req,
                                                   std::uint8_t* trampoline,
                                                   std::size_t capacity) {
    using namespace Xbyak::util;
    if (req.stolen.size() < 5 || req.stolen.size() > 16) {
        return std::unexpected(
            std::format("stolen length {} must be 5..16 bytes", req.stolen.size()));
    }
    if (req.callback == nullptr) {
        return std::unexpected(std::string{"detour callback is null"});
    }
    if (trampoline == nullptr) {
        // Xbyak would silently allocate a buffer of its own for a null pointer.
        return std::unexpected(std::string{"trampoline buffer is null"});
    }
    const auto rel = static_cast<std::int64_t>(reinterpret_cast<std::uint64_t>(trampoline)) -
                     static_cast<std::int64_t>(req.site + 5);
    if (rel < std::numeric_limits<std::int32_t>::min() ||
        rel > std::numeric_limits<std::int32_t>::max()) {
        return std::unexpected(std::string{"trampoline is out of rel32 range of the site"});
    }
    const std::uint64_t site_end = req.site + req.stolen.size();
    const auto at = [](std::size_t field) { return static_cast<std::uint32_t>(field); };
    try {
        Xbyak::CodeGenerator gen(capacity, trampoline);
        const auto q = [&](std::size_t field) { return qword[rsp + at(field)]; };
        Xbyak::Label skip, ret_path, host_mxcsr;

        // Entry: rsp = guest rsp (R). Skip the red zone, save rax and flags, build the context.
        gen.lea(rsp, ptr[rsp - kRedZone]);
        gen.push(rax);    // [R-136]
        gen.pushfq();     // [R-144]
        gen.mov(rax, rsp);
        gen.and_(rsp, -32);
        gen.sub(rsp, static_cast<std::uint32_t>(sizeof(HookContext)));
        gen.mov(q(offsetof(HookContext, rbx)), rbx);
        gen.mov(q(offsetof(HookContext, rcx)), rcx);
        gen.mov(q(offsetof(HookContext, rdx)), rdx);
        gen.mov(q(offsetof(HookContext, rsi)), rsi);
        gen.mov(q(offsetof(HookContext, rdi)), rdi);
        gen.mov(q(offsetof(HookContext, rbp)), rbp);
        gen.mov(q(offsetof(HookContext, r8)), r8);
        gen.mov(q(offsetof(HookContext, r9)), r9);
        gen.mov(q(offsetof(HookContext, r10)), r10);
        gen.mov(q(offsetof(HookContext, r11)), r11);
        gen.mov(q(offsetof(HookContext, r12)), r12);
        gen.mov(q(offsetof(HookContext, r13)), r13);
        gen.mov(q(offsetof(HookContext, r14)), r14);
        gen.mov(q(offsetof(HookContext, r15)), r15);
        gen.mov(rbx, qword[rax + 8]);
        gen.mov(q(offsetof(HookContext, rax)), rbx);
        gen.mov(rbx, qword[rax]);
        gen.mov(q(offsetof(HookContext, rflags)), rbx);
        gen.lea(rbx, ptr[rax + 16 + kRedZone]);
        gen.mov(q(offsetof(HookContext, rsp)), rbx);
        gen.mov(rbx, req.site);
        gen.mov(q(offsetof(HookContext, site)), rbx);
        gen.stmxcsr(dword[rsp + at(offsetof(HookContext, mxcsr))]);
        gen.mov(dword[rsp + at(offsetof(HookContext, action))], 0);
        gen.mov(q(offsetof(HookContext, reserved)), 0);
        for (int i = 0; i < 16; ++i) {
            gen.vmovdqa(yword[rsp + at(offsetof(HookContext, ymm) + i * 32)], Xbyak::Ymm(i));
        }

        // The guest's MXCSR is saved in the context; the callback runs with the default one.
        // The x87 control word and stack are not touched.
        gen.ldmxcsr(ptr[rip + host_mxcsr]);

        // Host callback, SysV ABI: rdi = ctx, rsi = user. rbx is callee-saved in SysV.
        gen.mov(rbx, rsp);
        gen.mov(rdi, rsp);
        gen.mov(rsi, reinterpret_cast<std::uint64_t>(req.user));
        gen.mov(rax, reinterpret_cast<std::uint64_t>(req.callback));
        gen.cld();
        gen.vzeroupper();
        gen.call(rax);
        gen.mov(rsp, rbx);

        for (int i = 0; i < 16; ++i) {
            gen.vmovdqa(Xbyak::Ymm(i), yword[rsp + at(offsetof(HookContext, ymm) + i * 32)]);
        }
        // The callback may have written anything to the context's MXCSR; reserved bits would fault.
        gen.and_(dword[rsp + at(offsetof(HookContext, mxcsr))], kMxcsrWritableBits);
        gen.ldmxcsr(dword[rsp + at(offsetof(HookContext, mxcsr))]);

        const auto restore = [&] {
            gen.push(q(offsetof(HookContext, rflags)));
            gen.popfq();
            gen.mov(rbx, q(offsetof(HookContext, rbx)));
            gen.mov(rcx, q(offsetof(HookContext, rcx)));
            gen.mov(rdx, q(offsetof(HookContext, rdx)));
            gen.mov(rsi, q(offsetof(HookContext, rsi)));
            gen.mov(rdi, q(offsetof(HookContext, rdi)));
            gen.mov(rbp, q(offsetof(HookContext, rbp)));
            gen.mov(r8, q(offsetof(HookContext, r8)));
            gen.mov(r9, q(offsetof(HookContext, r9)));
            gen.mov(r10, q(offsetof(HookContext, r10)));
            gen.mov(r11, q(offsetof(HookContext, r11)));
            gen.mov(r12, q(offsetof(HookContext, r12)));
            gen.mov(r13, q(offsetof(HookContext, r13)));
            gen.mov(r14, q(offsetof(HookContext, r14)));
            gen.mov(r15, q(offsetof(HookContext, r15)));
            gen.mov(rax, q(offsetof(HookContext, rax)));
            gen.mov(rsp, q(offsetof(HookContext, rsp)));
        };

        gen.mov(eax, dword[rsp + at(offsetof(HookContext, action))]);
        gen.cmp(eax, static_cast<std::uint32_t>(HookAction::SkipStolen));
        gen.je(skip, Xbyak::CodeGenerator::T_NEAR);
        gen.cmp(eax, static_cast<std::uint32_t>(HookAction::ReturnFromFunction));
        gen.je(ret_path, Xbyak::CodeGenerator::T_NEAR);

        restore();
        const auto relocated = RelocateInstructions(req.stolen, req.site,
                                                    reinterpret_cast<std::uint64_t>(gen.getCurr()));
        if (!relocated) {
            return std::unexpected(relocated.error());
        }
        gen.db(relocated->data(), relocated->size());
        gen.jmp(reinterpret_cast<const void*>(site_end), Xbyak::CodeGenerator::T_NEAR);

        gen.L(skip);
        restore();
        gen.jmp(reinterpret_cast<const void*>(site_end), Xbyak::CodeGenerator::T_NEAR);

        gen.L(ret_path);
        restore();
        gen.ret();

        // Data, after the last instruction: it is only ever read.
        gen.L(host_mxcsr);
        gen.dd(kHostMxcsr);

        DetourCode code{};
        code.trampoline_size = gen.getSize();
        const auto rel32 = static_cast<std::int32_t>(rel);
        code.site_patch.fill(0x90);
        code.site_patch[0] = 0xE9;
        std::memcpy(code.site_patch.data() + 1, &rel32, sizeof(rel32));
        code.site_patch_size = req.stolen.size();
        return code;
    } catch (const Xbyak::Error& e) {
        return std::unexpected(std::format("xbyak: {}", e.what()));
    }
}

} // namespace BBCoop::Binding
