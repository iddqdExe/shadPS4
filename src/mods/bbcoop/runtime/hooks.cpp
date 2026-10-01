// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/hooks.h"

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
#include "common/logging/log.h"
#include "core/cpu_patches.h"

namespace BBCoop::Runtime {

namespace {
struct HookRecord {
    Binding::SymbolId site;
    HookSiteKind kind;
    std::string owner;
    HookHandler handler;
    /// Set by InstallHooks before the site is patched.
    Binding::HookSiteRules rules;
    std::atomic<bool> faulted{false};
};

/// Intentionally leaked: guest threads can still reach a hook site while static destructors run
/// at process exit, and the trampolines point at these records.
std::vector<std::unique_ptr<HookRecord>>& Records() {
    static auto& records = *new std::vector<std::unique_ptr<HookRecord>>();
    return records;
}

/// Set when InstallHooks runs; a hook registered later would never be installed.
std::atomic<bool> g_install_ran{false};

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
    case Binding::HookFault::SkipPastFunctionEnd:
        LOG_CRITICAL(BBCoop_Binding,
                     "hook '{}' at {} asked for SkipStolenInstructions where the stolen bytes end "
                     "the function; handler disabled",
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
    Binding::RunHookHandler(*ctx, rec->rules, rec->handler, &ReportFault, rec);
}
} // namespace

void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner,
                  HookHandler handler) {
    if (g_install_ran.load()) {
        LOG_ERROR(BBCoop_Binding, "hook '{}' at {} registered after the game was loaded; ignored",
                  owner, Binding::SymbolName(site));
        return;
    }
    if (!handler) {
        LOG_ERROR(BBCoop_Binding, "hook '{}' at {} has no handler; ignored", owner,
                  Binding::SymbolName(site));
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
    g_install_ran.store(true);
    const auto& records = Records();
    std::vector<Binding::HookRequest> requests;
    requests.reserve(records.size());
    for (const auto& rec : records) {
        requests.push_back({static_cast<std::size_t>(rec->site), rec->kind, rec->owner});
    }
    const std::span<const std::uint8_t> live(reinterpret_cast<const std::uint8_t*>(base + text_rva),
                                             pristine.size());
    const auto plan =
        Binding::PlanHooks({requests, Binding::Eu109Symbols(), resolved, pristine, live, text_rva});
    if (!plan) {
        error = plan.error();
        return false;
    }

    struct Built {
        std::uint8_t* site;
        std::array<std::uint8_t, 16> patch;
        std::size_t patch_size;
    };
    std::vector<Built> built;
    built.reserve(plan->size());
    for (const auto& hook : *plan) {
        auto& rec = *records[hook.request];
        const auto name = Binding::SymbolName(rec.site);
        auto* site = reinterpret_cast<std::uint8_t*>(base + hook.rva);
        auto* tramp = ::Core::ReserveModuleTrampolineSpace(site, Binding::kMaxTrampolineSize);
        if (tramp == nullptr) {
            error = std::format("hook {}: no trampoline space next to the eboot", name);
            return false;
        }
        const auto code = Binding::BuildDetour(
            {reinterpret_cast<std::uint64_t>(site), hook.stolen, &HookThunk, &rec}, tramp,
            Binding::kMaxTrampolineSize);
        if (!code) {
            error = std::format("hook {}: {}", name, code.error());
            return false;
        }
        built.push_back({site, code->site_patch, code->site_patch_size});
    }
    // Nothing above wrote outside the reserved trampoline space; an aborted plan leaves only
    // unreachable trampoline bytes behind. No guest code runs yet, so the records and the sites
    // are written without synchronization.
    for (std::size_t i = 0; i < plan->size(); ++i) {
        const auto& hook = (*plan)[i];
        records[hook.request]->rules = {
            .function_entry = records[hook.request]->kind == HookSiteKind::FunctionEntry,
            .ends_with_transfer = hook.ends_with_transfer,
        };
        std::memcpy(built[i].site, built[i].patch.data(), built[i].patch_size);
    }
    if (!built.empty()) {
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    }
    for (const auto& hook : *plan) {
        const auto& rec = *records[hook.request];
        LOG_INFO(BBCoop_Binding, "hook {} ('{}') installed at rva {:#x}, {} bytes stolen{}",
                 Binding::SymbolName(rec.site), rec.owner, hook.rva, hook.stolen.size(),
                 hook.ends_with_transfer ? " (ends the function: SkipStolen refused)" : "");
    }
    return true;
}

} // namespace BBCoop::Runtime
