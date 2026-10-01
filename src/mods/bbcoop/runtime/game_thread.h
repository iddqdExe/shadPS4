// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "bbcoop/binding/symbols.h"
#include "bbcoop/runtime/binding_runtime.h"
#include "common/assert.h"
#include "common/types.h"

namespace BBCoop::Runtime {

/// Work for the game thread (see PostToGameThread).
using GameTask = std::function<void()>;

/// A per-frame callback; `frame` counts ticks from 1.
using FrameCallback = std::function<void(std::uint64_t frame)>;

// The game thread is the thread that runs the game's main loop. A hook on the epilogue of the
// game's idle/heartbeat function (idle_heartbeat_epilogue, once per frame) ticks it: the tick
// runs the tasks posted with PostToGameThread, then every frame callback, in registration order.
// Everything the mod does with the game's data or functions (CallGame, the game API) happens
// there.
//
// Stack budget: frame callbacks and game-thread tasks run on the game's own stack, nested in the
// hook handler (see hooks.h). Keep their stack use small: 16 KB at most for a callback or task
// and everything it calls, a C++ exception thrown and caught inside it included. No deep
// recursion and no large stack buffers (use heap or static storage). The game's stack has no
// guard page, so an overflow silently corrupts guest memory. They also run with the host's
// default MXCSR (0x1F80), not the game's.
//
// An exception that leaves a task or a frame callback is caught and logged. A task that throws
// is dropped; a frame callback that throws is disabled and never called again. The tick keeps
// running either way.

/// Registers the per-frame tick hook; call once, before the game is loaded (from
/// BBCoop::Initialize()). The tick only runs when the mod activates ("BB Co-op active" in the
/// log).
void InitializeGameThread();

/// Queues `task` to run on the game thread at the next tick. Callable from any thread. Returns
/// false when the mod is inactive or the queue (256 tasks) is full; the task is then dropped.
bool PostToGameThread(GameTask task);

/// True on the game thread once the first tick has run, false everywhere else (the game thread
/// is the first thread that reaches the tick).
bool IsGameThread();

/// The number of ticks so far.
std::uint64_t FrameCount();

/// Registers a per-frame callback named `owner` (for the log); call before the game is loaded.
/// A call after the game was loaded is refused with an error in the log.
void OnEveryFrame(std::string owner, FrameCallback callback);

/// Calls a game function by symbol. Game thread only (asserts otherwise). The function takes
/// the game's calling convention (System V), so `Args` must be what the function takes (integers,
/// pointers) and `R` what it returns.
template <typename R, typename... Args>
R CallGame(Binding::SymbolId fn, Args... args) {
    ASSERT_MSG(IsGameThread(), "CallGame used outside the game thread");
    using Fn = R PS4_SYSV_ABI (*)(Args...);
    return reinterpret_cast<Fn>(SymbolAddress(fn))(args...);
}

} // namespace BBCoop::Runtime
