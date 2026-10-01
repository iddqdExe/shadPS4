// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/binding_runtime.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <windows.h>

#include "bbcoop/binding/patch_table.h"
#include "bbcoop/binding/resolver.h"
#include "bbcoop/runtime/hooks.h"
#include "bbcoop/runtime/mod.h"
#include "common/assert.h"
#include "common/elf_info.h"
#include "common/logging/log.h"
#include "core/cpu_patches.h"
#include "core/emulator_settings.h"

namespace BBCoop::Runtime {

namespace {
constexpr std::string_view kSerial = "CUSA03173";
constexpr std::string_view kAppVersion = "01.09";

struct State {
    std::vector<std::uint8_t> pristine;
    std::uint64_t pristine_addr = 0;
    std::uint64_t base = 0;
    Binding::ResolveResult resolved;
    std::atomic<bool> active{false};
};
// Intentionally leaked: guest threads can still call IsActive/SymbolAddress while static
// destructors run at process exit.
State& g_state = *new State();

void Disable(std::string_view reason) {
    g_state.active = false;
    LOG_ERROR(BBCoop, "BB Co-op disabled: {}. The game continues without the mod.", reason);
}

bool IsEboot(std::string_view module_name) {
    constexpr std::string_view kEboot = "eboot.bin";
    return std::ranges::equal(module_name, kEboot, [](char a, char b) {
        return (a >= 'A' && a <= 'Z' ? static_cast<char>(a - 'A' + 'a') : a) == b;
    });
}

/// Everything OnGameLoaded does; any early return leaves the mod inactive with nothing written.
void Activate(std::uint64_t base, std::uint64_t size) {
    // The game version was checked before the pristine copy was taken (OnExecutableSegmentLoaded).
    const auto& info = Common::ElfInfo::Instance();
    // The setting, and the mode the loader acted on (module.cpp reads the mode).
    if (EmulatorSettings.IsRedZonePatchingEnabled() ||
        ::Core::WindowsGuestRedZoneProtection::IsStaticPatchingEnabled()) {
        Disable("guest red-zone patching is on (redzone_patches in the shadPS4 config); turn it "
                "off to use BB Co-op");
        return;
    }
    const auto& pristine = g_state.pristine;
    if (g_state.pristine_addr < base || g_state.pristine_addr - base > size ||
        pristine.size() > size - (g_state.pristine_addr - base)) {
        Disable(
            fmt::format("the captured text at {:#x} is not inside eboot.bin ({:#x}, {:#x} bytes)",
                        g_state.pristine_addr, base, size));
        return;
    }
    const std::uint64_t text_rva = g_state.pristine_addr - base;

    const auto started = std::chrono::steady_clock::now();
    const auto fingerprint = Binding::Fingerprint(pristine);
    const auto image = Binding::Eu109Image();
    const bool reference = fingerprint == image.fingerprint && pristine.size() == image.text_size &&
                           text_rva == image.text_rva;
    LOG_INFO(BBCoop_Binding,
             "image {} {}: text {:#x} bytes at rva {:#x}, fingerprint {:#018x} ({})",
             info.GameSerial(), info.AppVer(), pristine.size(), text_rva, fingerprint,
             reference ? "reference EU 1.09" : "unknown build, scanning");

    const auto specs = Binding::Eu109Symbols();
    auto resolved = Binding::ResolveSymbols({pristine, text_rva, reference}, specs);
    const auto required = static_cast<std::size_t>(
        std::ranges::count_if(specs, [](const Binding::SymbolSpec& s) { return s.required; }));
    std::size_t required_failed = 0;
    for (const auto& failure : resolved.failures) {
        if (failure.required) {
            ++required_failed;
            LOG_ERROR(BBCoop_Binding, "required symbol {}", Binding::FormatFailure(failure));
        } else {
            LOG_WARNING(BBCoop_Binding, "optional symbol {}", Binding::FormatFailure(failure));
        }
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - started)
                        .count();
    LOG_INFO(BBCoop_Binding, "resolved {}/{} signatures ({}/{} required) in {} ms",
             resolved.ResolvedCount(), specs.size(), required - required_failed, required, ms);
    if (!resolved.AllRequiredResolved()) {
        Disable("required signatures are missing");
        return;
    }

    const std::span<const std::uint8_t> live(reinterpret_cast<const std::uint8_t*>(base + text_rva),
                                             pristine.size());
    const std::vector<std::string_view> enabled_groups; // stage 0: no patch group is enabled
    const auto plan = Binding::PlanPatches(
        {Binding::Eu109Patches(), enabled_groups,
         [&resolved](std::string_view name) -> std::optional<std::uint64_t> {
             const auto id = Binding::FindSymbol(name);
             return id ? resolved.Rva(static_cast<std::size_t>(*id)) : std::nullopt;
         },
         pristine, live, text_rva, reference});
    for (const auto& warning : plan.warnings) {
        LOG_WARNING(BBCoop_Binding, "patch {} (disabled): {}", warning.name, warning.detail);
    }
    for (const auto& plan_error : plan.errors) {
        LOG_ERROR(BBCoop_Binding, "patch {}: {}", plan_error.name, plan_error.detail);
    }
    if (!plan.Ok()) {
        Disable("enabled byte patches do not match this image");
        return;
    }

    // Patches first, hooks second: InstallHooks compares the live text with the pristine one
    // around every site, so a hook next to one of our own patches is refused like any conflict.
    const auto write = [base](std::uint64_t rva, std::span<const std::uint8_t> bytes) {
        std::memcpy(reinterpret_cast<void*>(base + rva), bytes.data(), bytes.size());
    };
    Binding::ApplyPatches(plan.ops, write);
    std::string error;
    if (!InstallHooks(base, pristine, text_rva, resolved, error)) {
        Binding::RevertPatches(plan.ops, write);
        Disable(error);
        return;
    }
    if (!plan.ops.empty()) {
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    }
    g_state.base = base;
    g_state.resolved = std::move(resolved);
    g_state.active = true;
    LOG_INFO(BBCoop, "BB Co-op active: {} hooks, {} patches", HookCount(), plan.ops.size());
}
} // namespace

void OnExecutableSegmentLoaded(std::string_view module_name, std::uint64_t segment_addr,
                               std::uint64_t size) {
    if (!IsEboot(module_name) || !BBCoop::GetConfig().enabled) {
        return;
    }
    const auto& info = Common::ElfInfo::Instance();
    const auto serial = info.GameSerial();
    if (serial != kSerial) {
        LOG_INFO(BBCoop, "BB Co-op inactive: game {} is not Bloodborne EU ({})", serial, kSerial);
        return;
    }
    // Before the 85 MB copy below: another version of the game would only copy and discard it.
    // Without the copy OnGameLoaded does nothing, so the mod stays inactive.
    if (info.AppVer() != kAppVersion) {
        Disable(fmt::format("unsupported game version {} (only {} is supported)", info.AppVer(),
                            kAppVersion));
        return;
    }
    if (!g_state.pristine.empty()) {
        LOG_WARNING(BBCoop_Binding,
                    "eboot.bin has another executable segment at {:#x}; only the first is used",
                    segment_addr);
        return;
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(segment_addr);
    g_state.pristine.assign(bytes, bytes + size);
    g_state.pristine_addr = segment_addr;
    LOG_INFO(BBCoop_Binding, "captured pristine eboot text: {:#x} bytes", size);
}

void OnGameLoaded(std::uint64_t base, std::uint64_t size) {
    if (g_state.pristine.empty()) {
        return;
    }
    Activate(base, size);
    std::vector<std::uint8_t>().swap(g_state.pristine);
}

bool IsActive() {
    return g_state.active;
}

std::uint64_t SymbolAddress(Binding::SymbolId id) {
    ASSERT_MSG(g_state.active, "SymbolAddress used while BB Co-op is inactive");
    const auto rva = g_state.resolved.Rva(static_cast<std::size_t>(id));
    ASSERT_MSG(rva.has_value(), "SymbolAddress: symbol {} is not resolved",
               Binding::SymbolName(id));
    return g_state.base + *rva;
}

std::optional<std::uint64_t> TrySymbolAddress(Binding::SymbolId id) {
    if (!g_state.active) {
        return std::nullopt;
    }
    const auto rva = g_state.resolved.Rva(static_cast<std::size_t>(id));
    if (!rva) {
        return std::nullopt;
    }
    return g_state.base + *rva;
}

} // namespace BBCoop::Runtime
