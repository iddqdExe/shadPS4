// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "bbcoop/binding/symbols.h"
#include "bbcoop/core/call_args.h"
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
// The tick does not run on the title screen: it starts when the game starts loading a save, and
// ticks slow down or stop for a few seconds on the loading screens between areas (see README.md).
//
// Tasks and callbacks run inside the game's own frame, on its own stack, nested in the hook
// handler (see hooks.h):
//  - Stack budget: 16 KB at most for a callback or task and everything it calls, a C++ exception
//    thrown and caught inside it included. For CallGame the game function's own stack use counts
//    toward the same 16 KB, because it runs on the caller's stack. No deep recursion and no large
//    stack buffers (use heap or static storage). The game's stack has no guard page, so an
//    overflow silently corrupts guest memory.
//  - Anything that blocks (file or network I/O, waiting for another thread, a contended lock)
//    stalls the game for as long as it takes. Hand such work to another thread and post the
//    result back with PostToGameThread.
//  - They run with the host's default MXCSR (0x1F80), not the game's.
//
// An exception that leaves a task or a frame callback is caught and logged. A task that throws
// is dropped; a frame callback that throws is disabled and never called again. The tick keeps
// running either way.
//
// A tick that is reached again while a task or callback is running (for example by a game
// function called through CallGame that runs the hooked per-frame code) is skipped, with an
// error line in the log.
//
// The game API (CallGame and everything that asserts IsGameThread) works only on the game
// thread and only after the first tick: until FrameCount() > 0, IsGameThread() is false
// everywhere, so code on another hook (a detour at some other site) must check FrameCount()
// before it calls the game.

/// Registers the per-frame tick hook; call once, before the game is loaded (from
/// BBCoop::Initialize()). The tick only runs when the mod activates ("BB Co-op active" in the
/// log).
void InitializeGameThread();

/// Queues `task` to run on the game thread at the next tick. Callable from any thread. Returns
/// false when the mod is inactive or the queue (256 tasks) is full; the task is then dropped and
/// counted (the periodic tick line in the log shows the total). Check the result.
[[nodiscard]] bool PostToGameThread(GameTask task);

/// True on the game thread once the first tick has run, false everywhere else (the game thread
/// is the first thread that reaches the tick).
bool IsGameThread();

/// The number of ticks so far.
std::uint64_t FrameCount();

/// Registers a per-frame callback named `owner` (for the log); call before the game is loaded.
/// A call after the game was loaded is refused with an error in the log.
void OnEveryFrame(std::string owner, FrameCallback callback);

/// Calls a game function by symbol. Game thread only, after the first tick (asserts otherwise).
/// The game's calling convention is System V, and every argument is passed in one register as
/// the type it has here, so integer arguments must have the width the game function reads: pass
/// std::uint64_t or std::int64_t explicitly for a 64-bit parameter, never a bare literal (0 and
/// -1 are 32-bit ints, and the upper half of the register is then undefined):
///
///     CallGame<void>(SymbolId::some_function, object_pointer, std::uint64_t{0});
///
/// `R` is what the function returns. See the stack budget above.
template <typename R, typename... Args>
R CallGame(Binding::SymbolId fn, Args... args) {
    static_assert((Core::IsGameCallArg<Args> && ...),
                  "CallGame arguments must be integers, enums, pointers or floating-point values");
    ASSERT_MSG(IsGameThread(), "CallGame used outside the game thread");
    using Fn = R PS4_SYSV_ABI (*)(Args...);
    return reinterpret_cast<Fn>(SymbolAddress(fn))(args...);
}

} // namespace BBCoop::Runtime
