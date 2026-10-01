// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/hooks.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <windows.h>

#include "bbcoop/binding/hook_guard.h"
#include "bbcoop/binding/relocator.h"
#include "common/logging/log.h"
#include "core/cpu_patches.h"

namespace BBCoop::Runtime {

namespace {
/// The site is overwritten with a JMP rel32.
constexpr std::size_t kJumpSize = 5;
/// Bytes decoded at a site to find the stolen length; more than any 5..16 byte steal needs.
constexpr std::size_t kDecodeWindow = 32;
/// Bytes on each side of the stolen ones that must also be untouched by other patchers.
constexpr std::size_t kNeighbourhood = 16;

struct HookRecord {
    Binding::SymbolId site;
    HookSiteKind kind;
    std::string owner;
    HookHandler handler;
    std::atomic<bool> faulted{false};
};

std::vector<std::unique_ptr<HookRecord>>& Records() {
    static std::vector<std::unique_ptr<HookRecord>> records;
    return records;
}

/// Set when InstallHooks runs; a hook registered later would never be installed.
bool g_install_ran = false;

/// Runs inside RunHookHandler's stack bounds, so a throw from the logger cannot reach the guest.
void ReportFault(const Binding::HookRunResult& result, void* user) {
    auto* rec = static_cast<HookRecord*>(user);
    rec->faulted.store(true, std::memory_order_release);
    const auto site = Binding::SymbolName(rec->site);
    switch (result.fault) {
    case Binding::HookFault::Exception:
        LOG_CRITICAL(BBCoop_Binding, "hook '{}' at {} threw: {}; handler disabled", rec->owner,
                     site, result.Message());
        break;
    case Binding::HookFault::UnknownException:
        LOG_CRITICAL(BBCoop_Binding, "hook '{}' at {} threw an unknown exception; handler disabled",
                     rec->owner, site);
        break;
    case Binding::HookFault::ReturnAtMidSite:
        LOG_CRITICAL(BBCoop_Binding,
                     "hook '{}' at {} asked for ReturnFromFunction at a mid-function site; "
                     "handler disabled",
                     rec->owner, site);
        break;
    case Binding::HookFault::None:
        break;
    }
}

/// The detour callback of every hook. It runs on a guest stack, where nothing may throw outside
/// RunHookHandler (see hook_guard.h), so it only calls functions that cannot throw.
void BBCOOP_SYSV_ABI HookThunk(Binding::HookContext* ctx, void* user) noexcept {
    auto* rec = static_cast<HookRecord*>(user);
    if (rec->faulted.load(std::memory_order_acquire)) {
        return;
    }
    Binding::RunHookHandler(*ctx, rec->kind == HookSiteKind::FunctionEntry, rec->handler,
                            &ReportFault, rec);
}
} // namespace

void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner,
                  HookHandler handler) {
    if (g_install_ran) {
        LOG_ERROR(BBCoop_Binding, "hook '{}' at {} registered after the game was loaded; ignored",
                  owner, Binding::SymbolName(site));
        return;
    }
    auto rec = std::make_unique<HookRecord>();
    rec->site = site;
    rec->kind = kind;
    rec->owner = std::move(owner);
    rec->handler = std::move(handler);
    Records().push_back(std::move(rec));
}

std::size_t HookCount() {
    return Records().size();
}

bool InstallHooks(std::uint64_t base, std::span<const std::uint8_t> pristine,
                  std::uint64_t text_rva, const Binding::ResolveResult& resolved,
                  std::string& error) {
    g_install_ran = true;
    struct Planned {
        std::string_view name;
        std::string_view owner;
        std::uint64_t rva;
        std::size_t steal;
        std::uint8_t* site;
        std::array<std::uint8_t, 16> patch;
        std::size_t patch_size;
    };
    std::vector<Planned> planned;
    planned.reserve(Records().size());
    const auto* live = reinterpret_cast<const std::uint8_t*>(base + text_rva);
    for (const auto& rec : Records()) {
        const auto name = Binding::SymbolName(rec->site);
        const auto site_rva = resolved.Rva(static_cast<std::size_t>(rec->site));
        if (!site_rva) {
            error = std::format("hook {}: site symbol is not resolved", name);
            return false;
        }
        const std::uint64_t rva = *site_rva;
        if (rva < text_rva || rva - text_rva >= pristine.size()) {
            error = std::format("hook {}: site {:#x} is outside the text segment", name, rva);
            return false;
        }
        const std::size_t off = static_cast<std::size_t>(rva - text_rva);
        const auto steal = Binding::StealLength(
            pristine.subspan(off, std::min(kDecodeWindow, pristine.size() - off)), kJumpSize);
        if (!steal) {
            error = std::format("hook {}: {}", name, steal.error());
            return false;
        }
        const auto stolen = pristine.subspan(off, *steal);
        // The jump must not overwrite code after the end of the function (0B-R46).
        const auto early_end = Binding::FindEarlyControlTransfer(stolen);
        if (!early_end) {
            error = std::format("hook {}: {}", name, early_end.error());
            return false;
        }
        if (*early_end) {
            error = std::format("hook {}: the code at {:#x} ends at +{:#x} with an unconditional "
                                "jump, ret or trap, inside the {} bytes the hook overwrites",
                                name, rva, **early_end, *steal);
            return false;
        }
        for (const auto& other : planned) {
            if (rva < other.rva + other.steal && other.rva < rva + *steal) {
                error = std::format("hook {} overlaps hook {} (owners '{}' and '{}')", name,
                                    other.name, rec->owner, other.owner);
                return false;
            }
        }
        // The stolen bytes must be exactly the pristine ones: an emulator patch there is a jump
        // into a cpu_patches trampoline, which the relocator would copy blindly.
        const std::size_t lo = off >= kNeighbourhood ? off - kNeighbourhood : 0;
        const std::size_t hi = std::min(off + *steal + kNeighbourhood, pristine.size());
        if (std::memcmp(live + lo, pristine.data() + lo, hi - lo) != 0) {
            error = std::format("hook {}: code around {:#x} was modified by another patcher "
                                "(an XML patch, the emulator or a BB Co-op byte patch)",
                                name, rva);
            return false;
        }
        auto* site = reinterpret_cast<std::uint8_t*>(base + rva);
        auto* tramp = ::Core::ReserveModuleTrampolineSpace(site, Binding::kMaxTrampolineSize);
        if (tramp == nullptr) {
            error = std::format("hook {}: no trampoline space next to the eboot", name);
            return false;
        }
        const auto code = Binding::BuildDetour(
            {reinterpret_cast<std::uint64_t>(site), stolen, &HookThunk, rec.get()}, tramp,
            Binding::kMaxTrampolineSize);
        if (!code) {
            error = std::format("hook {}: {}", name, code.error());
            return false;
        }
        planned.push_back(
            {name, rec->owner, rva, *steal, site, code->site_patch, code->site_patch_size});
    }
    // Nothing above wrote outside the reserved trampoline space; an aborted plan leaves only
    // unreachable trampoline bytes behind.
    for (const auto& p : planned) {
        std::memcpy(p.site, p.patch.data(), p.patch_size);
    }
    if (!planned.empty()) {
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    }
    for (const auto& p : planned) {
        LOG_INFO(BBCoop_Binding, "hook {} ('{}') installed at rva {:#x}, {} bytes stolen", p.name,
                 p.owner, p.rva, p.steal);
    }
    return true;
}

} // namespace BBCoop::Runtime
