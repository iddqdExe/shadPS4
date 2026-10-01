// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/game_thread.h"

#include <atomic>
#include <chrono>
#include <exception>
#include <thread>
#include <utility>
#include <vector>

#include "bbcoop/core/scoped_entry.h"
#include "bbcoop/core/task_queue.h"
#include "bbcoop/runtime/hooks.h"
#include "common/logging/log.h"

namespace BBCoop::Runtime {

namespace {
struct FrameCallbackEntry {
    std::string owner;
    FrameCallback callback;
    bool disabled = false; ///< Set after the callback threw; only the game thread touches it.
};

// The task queue, the callback list and the drain buffer are intentionally leaked: guest threads
// can still tick while static destructors run at process exit.
Core::BoundedTaskQueue<GameTask>& Tasks() {
    static auto& tasks = *new Core::BoundedTaskQueue<GameTask>(256);
    return tasks;
}

/// Filled before the game is loaded, then only touched by the game thread.
std::vector<FrameCallbackEntry>& FrameCallbacks() {
    static auto& callbacks = *new std::vector<FrameCallbackEntry>();
    return callbacks;
}

/// Reused every tick (the queue keeps its buffers too), so the tick does not allocate once it has
/// warmed up. Game thread only.
std::vector<GameTask>& DrainBuffer() {
    static auto& buffer = *new std::vector<GameTask>();
    return buffer;
}

std::atomic<std::uint64_t> g_frames{0};
std::atomic<std::thread::id> g_game_thread{};
std::atomic<bool> g_foreign_thread_reported{false};
std::atomic<bool> g_initialized{false};
std::atomic<std::uint64_t> g_dropped_tasks{0}; ///< PostToGameThread calls that returned false.
/// Cleared for good when the tick's hook handler faults (it is then disabled and never ticks).
std::atomic<bool> g_tick_alive{true};
// The next three are only touched by the game thread.
std::chrono::steady_clock::time_point g_rate_start;
bool g_in_tick = false;
std::uint64_t g_nested_ticks_skipped = 0;

void RunTasks() {
    auto& drain = DrainBuffer();
    drain.clear();
    Tasks().Drain(drain);
    for (auto& task : drain) {
        try {
            task();
        } catch (const std::exception& e) {
            LOG_ERROR(BBCoop, "game-thread task threw: {}", e.what());
        } catch (...) {
            LOG_ERROR(BBCoop, "game-thread task threw an unknown exception");
        }
    }
    drain.clear(); // destroy what the tasks captured now, not at the next tick
}

void RunFrameCallbacks(std::uint64_t frame) {
    for (auto& entry : FrameCallbacks()) {
        if (entry.disabled) {
            continue;
        }
        try {
            entry.callback(frame);
        } catch (const std::exception& e) {
            entry.disabled = true;
            LOG_ERROR(BBCoop, "frame callback '{}' threw: {}; callback disabled", entry.owner,
                      e.what());
        } catch (...) {
            entry.disabled = true;
            LOG_ERROR(BBCoop, "frame callback '{}' threw an unknown exception; callback disabled",
                      entry.owner);
        }
    }
}

void OnHeartbeat(Binding::HookContext&) {
    const auto me = std::this_thread::get_id();
    auto expected = std::thread::id{};
    if (!g_game_thread.compare_exchange_strong(expected, me) && expected != me) {
        if (!g_foreign_thread_reported.exchange(true)) {
            LOG_ERROR(BBCoop, "per-frame site ran on a second thread; those ticks are ignored");
        }
        return;
    }
    // A task or callback that calls into the game (CallGame) can reach the hooked per-frame code
    // again on this thread. A nested tick would clear the batch the outer tick is running and
    // run the callbacks recursively, so it is skipped.
    Core::ScopedEntry tick(g_in_tick);
    if (!tick) {
        ++g_nested_ticks_skipped;
        if (g_nested_ticks_skipped == 1 || g_nested_ticks_skipped % 1800 == 0) {
            LOG_ERROR(BBCoop,
                      "nested per-frame tick skipped: a task or frame callback reached the "
                      "per-frame site again ({} skipped so far)",
                      g_nested_ticks_skipped);
        }
        return;
    }
    const auto frame = g_frames.fetch_add(1) + 1;
    if (frame == 1) {
        g_rate_start = std::chrono::steady_clock::now();
        LOG_INFO(BBCoop, "game thread tick started");
    }
    RunTasks();
    RunFrameCallbacks(frame);
    if (frame % 1800 == 0) {
        const auto now = std::chrono::steady_clock::now();
        const double seconds = std::chrono::duration<double>(now - g_rate_start).count();
        const auto dropped = g_dropped_tasks.load();
        if (dropped == 0) {
            LOG_INFO(BBCoop, "tick: frame {} ({:.1f} ticks/s)", frame, 1800.0 / seconds);
        } else {
            LOG_INFO(BBCoop, "tick: frame {} ({:.1f} ticks/s), {} posted tasks dropped so far",
                     frame, 1800.0 / seconds, dropped);
        }
        g_rate_start = now;
    }
}
} // namespace

void InitializeGameThread() {
    if (g_initialized.exchange(true)) {
        LOG_WARNING(BBCoop, "InitializeGameThread called twice; ignored");
        return;
    }
    RegisterHook(Binding::SymbolId::idle_heartbeat_epilogue, HookSiteKind::Mid, "game_thread",
                 OnHeartbeat, [] {
                     g_tick_alive.store(false);
                     LOG_CRITICAL(BBCoop, "game thread tick stopped for good: frame callbacks and "
                                          "posted tasks no longer run, PostToGameThread refuses");
                 });
}

bool PostToGameThread(GameTask task) {
    if (IsActive() && g_tick_alive.load() && Tasks().Push(std::move(task))) {
        return true;
    }
    g_dropped_tasks.fetch_add(1, std::memory_order_relaxed);
    return false;
}

bool IsGameThread() {
    return g_game_thread.load() == std::this_thread::get_id();
}

std::uint64_t FrameCount() {
    return g_frames.load();
}

void OnEveryFrame(std::string owner, FrameCallback callback) {
    // Once the mod is active the game thread may already be walking the list.
    if (IsActive()) {
        LOG_ERROR(BBCoop, "frame callback '{}' registered after the game was loaded; ignored",
                  owner);
        return;
    }
    if (!callback) {
        LOG_ERROR(BBCoop, "frame callback '{}' is empty; ignored", owner);
        return;
    }
    FrameCallbacks().push_back({std::move(owner), std::move(callback)});
}

} // namespace BBCoop::Runtime
