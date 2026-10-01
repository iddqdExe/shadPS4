// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>

#include "bbcoop/binding/detour.h"
#include "bbcoop/binding/resolver.h"
#include "bbcoop/binding/symbols.h"

namespace BBCoop::Runtime {

/// FunctionEntry: the first instruction of a function, where [rsp] is the return address and
/// HookContext::ReturnFromFunction is allowed. Mid: any other instruction.
enum class HookSiteKind { FunctionEntry, Mid };

/// A detour handler. It runs on the game thread that reached the site, on that thread's GUEST
/// stack (below the guest's red zone and the saved context), with MXCSR 0x1F80.
///
/// Stack budget: 16 KB at most for the handler and everything it calls, a C++ exception thrown
/// and caught inside it included (Windows exception dispatch alone takes a few KB). Emulator-made
/// guest stacks are 1 MB + 128 KB, but stacks the game supplies itself and fiber stacks can be
/// much smaller, and none has a guard page: an overflow silently corrupts guest memory. Keep
/// handlers short and move heavy work elsewhere.
///
/// An exception that leaves the handler, or a ReturnFromFunction request at a Mid site, is a
/// fault: the guest resumes with the context it had at the site (the handler's changes are
/// dropped), the fault is logged and the handler never runs again.
using HookHandler = std::function<void(Binding::HookContext&)>;

/// Registers a detour; call before the game is loaded (from BBCoop::Initialize()). A hook
/// registered after InstallHooks ran is refused with an error in the log.
void RegisterHook(Binding::SymbolId site, HookSiteKind kind, std::string owner,
                  HookHandler handler);

std::size_t HookCount();

/// Generates every trampoline first, then writes every site patch. On any failure nothing is
/// written and `error` explains why. A hook is refused when its site symbol is unresolved, its
/// stolen bytes run past the end of the function (an unconditional jump, ret, ud2 or int3 before
/// the last stolen instruction), overlap another hook's, differ from `pristine` in the live text
/// (or within 16 bytes around them), cannot be relocated, or no trampoline space is left.
/// `pristine` is the executable segment before any patching, at `text_rva` from `base`.
bool InstallHooks(std::uint64_t base, std::span<const std::uint8_t> pristine,
                  std::uint64_t text_rva, const Binding::ResolveResult& resolved,
                  std::string& error);

} // namespace BBCoop::Runtime
