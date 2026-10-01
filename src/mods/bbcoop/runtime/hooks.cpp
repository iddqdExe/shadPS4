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
/// One RegisterHook call.
struct HookRecord {
    Binding::SymbolId site;
    HookSiteKind kind;
    std::string owner;
    /// The handler, its fault flag and this record as the reporter's user pointer.
    Binding::SiteHandler handler;
    /// Called by ReportFault after the fault is logged (RegisterHook's on_fault).
    std::function<void()> on_fault;
};

/// One installed detour: the handlers of every record on its site, in registration order.
struct InstalledSite {
    Binding::HookSiteRules rules;
    std::vector<Binding::SiteHandler*> handlers;
};

/// Intentionally leaked: guest threads can still reach a hook site while static destructors run
/// at process exit, and the trampolines point at these records.
std::vector<std::unique_ptr<HookRecord>>& Records() {
    static auto& records = *new std::vector<std::unique_ptr<HookRecord>>();
    return records;
}

/// Intentionally leaked, like Records(): the trampolines pass these to HookThunk.
std::vector<std::unique_ptr<InstalledSite>>& InstalledSites() {
    static auto& sites = *new std::vector<std::unique_ptr<InstalledSite>>();
    return sites;
}

/// Set when InstallHooks runs; a hook registered later would never be installed.
std::atomic<bool> g_install_ran{false};

/// Runs inside RunHookHandler's stack bounds, so a throw from the logger cannot reach the guest.
/// RunSiteHandlers marks the handler faulted after this returns.
void ReportFault(const Binding::HookRunResult& result, void* user) {
    auto* rec = static_cast<HookRecord*>(user);
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
    case Binding::HookFault::ConflictingAction:
        LOG_CRITICAL(BBCoop_Binding,
                     "hook '{}' at {} asked for {} where an earlier handler of the site asked for "
                     "{} in the same hit; the earlier action stays, handler disabled",
                     rec->owner, site, Binding::ToString(result.requested),
                     Binding::ToString(result.earlier));
        break;
    case Binding::HookFault::None:
        return;
    }
    // RunSiteHandlers skips the handler from now on (two threads that fault in it at the same
    // moment may both get here).
    if (rec->on_fault) {
        rec->on_fault();
    }
}

/// The detour callback of every site. It runs on a guest stack, where nothing may throw outside
/// RunHookHandler (see hook_guard.h), so it only calls functions that cannot throw.
void BBCOOP_SYSV_ABI HookThunk(Binding::HookContext* ctx, void* user) noexcept {
    const auto* site = static_cast<const InstalledSite*>(user);
    Binding::RunSiteHandlers(*ctx, site->rules, site->handlers, &ReportFault);
}

/// "'a'" or "'a', 'b'": the owners of the records on one site, for the log.
std::string OwnersOf(const Binding::PlannedHook& hook,
                     const std::vector<std::unique_ptr<HookRecord>>& records) {
    std::string owners;
    for (const std::size_t r : hook.requests) {
        owners += std::format("{}'{}'", owners.empty() ? "" : ", ", records[r]->owner);
    }
    return owners;
}
} // namespace

void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner, HookHandler handler,
                  std::function<void()> on_fault) {
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
    rec->handler.handler = std::move(handler);
    rec->handler.report_user = rec.get();
    rec->on_fault = std::move(on_fault);
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
    // One detour per site; it runs the handlers of every record on the site (all of one kind,
    // PlanHooks checked that) in registration order.
    std::vector<std::unique_ptr<InstalledSite>> sites;
    sites.reserve(plan->size());
    for (const auto& hook : *plan) {
        auto& installed = *sites.emplace_back(std::make_unique<InstalledSite>());
        installed.rules = {
            .function_entry = records[hook.request]->kind == HookSiteKind::FunctionEntry,
            .ends_with_transfer = hook.ends_with_transfer,
        };
        for (const std::size_t r : hook.requests) {
            installed.handlers.push_back(&records[r]->handler);
        }
        const auto name = Binding::SymbolName(records[hook.request]->site);
        auto* site = reinterpret_cast<std::uint8_t*>(base + hook.rva);
        auto* tramp = ::Core::ReserveModuleTrampolineSpace(site, Binding::kMaxTrampolineSize);
        if (tramp == nullptr) {
            error = std::format("hook {}: no trampoline space next to the eboot", name);
            return false;
        }
        const auto code = Binding::BuildDetour(
            {reinterpret_cast<std::uint64_t>(site), hook.stolen, &HookThunk, &installed}, tramp,
            Binding::kMaxTrampolineSize);
        if (!code) {
            error = std::format("hook {}: {}", name, code.error());
            return false;
        }
        built.push_back({site, code->site_patch, code->site_patch_size});
    }
    // Nothing above wrote outside the reserved trampoline space; an aborted plan leaves only
    // unreachable trampoline bytes behind (and frees the sites they would have used). No guest
    // code runs yet, so the sites are written without synchronization.
    for (auto& installed : sites) {
        InstalledSites().push_back(std::move(installed));
    }
    for (const auto& b : built) {
        std::memcpy(b.site, b.patch.data(), b.patch_size);
    }
    if (!built.empty()) {
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    }
    for (const auto& hook : *plan) {
        LOG_INFO(BBCoop_Binding, "hook {} ({}) installed at rva {:#x}, {} bytes stolen{}{}",
                 Binding::SymbolName(records[hook.request]->site), OwnersOf(hook, records),
                 hook.rva, hook.stolen.size(),
                 hook.requests.size() > 1 ? std::format(", {} handlers", hook.requests.size())
                                          : std::string{},
                 hook.ends_with_transfer ? " (ends the function: SkipStolen refused)" : "");
    }
    return true;
}

} // namespace BBCoop::Runtime
