// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>

#include "bbcoop/binding/detour.h"
#include "bbcoop/binding/hook_plan.h"
#include "bbcoop/binding/resolver.h"
#include "bbcoop/binding/symbols.h"

namespace BBCoop::Runtime {

/// FunctionEntry: the first instruction of a function (a Function symbol), where [rsp] is the
/// return address and HookContext::ReturnFromFunction is allowed. Mid: any other instruction of a
/// Function or Site symbol.
using HookSiteKind = Binding::HookSiteKind;

/// A detour handler. It runs on the game thread that reached the site, on that thread's GUEST
/// stack (below the guest's red zone and the saved context), with MXCSR 0x1F80.
///
/// Stack budget: 16 KB at most for the handler and everything it calls, a C++ exception thrown
/// and caught inside it included (Windows exception dispatch alone takes a few KB). Emulator-made
/// guest stacks are 1 MB + 128 KB, but stacks the game supplies itself and fiber stacks can be
/// much smaller, and none has a guard page: an overflow silently corrupts guest memory. Keep
/// handlers short and move heavy work elsewhere.
///
/// A fault — an exception that leaves the handler, ReturnFromFunction at a Mid site, or
/// SkipStolenInstructions at a site whose stolen bytes end with an unconditional jump or ret (the
/// guest would continue past the end of the function) — makes the guest resume with the context
/// it had at the site (the handler's changes are dropped); the fault is logged and the handler
/// never runs again.
using HookHandler = std::function<void(Binding::HookContext&)>;

/// Registers a detour; call before the game is loaded (from BBCoop::Initialize()). A hook
/// registered after InstallHooks ran, or with an empty handler, is refused with an error in the
/// log.
void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner,
                  HookHandler handler);

std::size_t HookCount();

/// Plans every hook (Binding::PlanHooks: kind fits the symbol, resolved, inside text, function
/// does not end inside the stolen bytes, no overlap, live text pristine around the site), then
/// generates every trampoline, then writes every site patch. On any failure nothing is written
/// and `error` explains why. `pristine` is the executable segment before any patching, at
/// `text_rva` from `base`.
bool InstallHooks(std::uint64_t base, std::span<const std::uint8_t> pristine,
                  std::uint64_t text_rva, const Binding::ResolveResult& resolved,
                  std::string& error);

} // namespace BBCoop::Runtime
