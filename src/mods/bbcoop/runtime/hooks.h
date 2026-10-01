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
/// stack (below the guest's red zone and the saved context), with the host's MXCSR 0x1F80. Game
/// functions it calls through CallGame run with the guest's MXCSR (the context's mxcsr when the
/// handler started), see game_thread.h.
///
/// Stack budget: 16 KB at most for the handler and everything it calls, a C++ exception thrown
/// and caught inside it included (Windows exception dispatch alone takes a few KB). Emulator-made
/// guest stacks are 1 MB + 128 KB, but stacks the game supplies itself and fiber stacks can be
/// much smaller, and none has a guard page: an overflow silently corrupts guest memory. Keep
/// handlers short and move heavy work elsewhere.
///
/// A fault — an exception that leaves the handler, ReturnFromFunction at a Mid site,
/// SkipStolenInstructions at a site whose stolen bytes end with an unconditional jump or ret (the
/// guest would continue past the end of the function), or an action that conflicts with an
/// earlier handler's at the same site (see RegisterHook) — drops the handler's changes to the
/// context (the guest resumes as if it had not run); the fault is logged and the handler never
/// runs again.
using HookHandler = std::function<void(Binding::HookContext&)>;

/// Registers a detour; call before the game is loaded (from BBCoop::Initialize()). A hook
/// registered after InstallHooks ran, or with an empty handler, is refused with an error in the
/// log.
///
/// Several hooks on one site (any owners): with the same HookSiteKind they share one detour, and
/// its handlers run in registration order, each isolated (a handler that faults is disabled
/// alone, the others keep running; each sees the registers as the earlier handlers left them).
/// Actions: the first handler that asks for SkipStolenInstructions or ReturnFromFunction decides
/// the site's action for that hit; a later handler may ask for the same action or none, and
/// asking for the other one is a fault of the later handler (its changes are undone, it is
/// disabled, the earlier action stays). Hooks of different HookSiteKinds on one site make
/// InstallHooks fail, which disables the whole mod (N4).
void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner,
                  HookHandler handler);

/// The number of RegisterHook calls that were accepted (handlers, not sites).
std::size_t HookCount();

/// Plans every hook (Binding::PlanHooks: kind fits the symbol, resolved, inside text, function
/// does not end inside the stolen bytes, one kind per site, no overlap between sites, live text
/// pristine around the site), then generates one trampoline per site, then writes every site
/// patch. On any failure nothing is written and `error` explains why. `pristine` is the
/// executable segment before any patching, at `text_rva` from `base`.
bool InstallHooks(std::uint64_t base, std::span<const std::uint8_t> pristine,
                  std::uint64_t text_rva, const Binding::ResolveResult& resolved,
                  std::string& error);

} // namespace BBCoop::Runtime
