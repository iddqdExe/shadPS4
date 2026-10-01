// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/game_api.h"

#include <array>
#include <chrono>
#include <cmath>

#include "bbcoop/core/map_id.h"
#include "bbcoop/runtime/game_thread.h"
#include "bbcoop/runtime/guest_memory.h"
#include "bbcoop/runtime/mod.h"
#include "common/assert.h"
#include "common/logging/log.h"

namespace BBCoop::Runtime {

using Binding::SymbolId;

namespace {
// Structure offsets of EU 1.09 (research/notes/01-shadp2p-game-re.md, sections 1.2 and 1.3).
// WorldChrMan: the local PlayerIns.
constexpr std::uint64_t kPlayerInsOffset = 0x60;
// PlayerIns -> ... -> transform.
constexpr std::array<std::uint32_t, 4> kTransformChain{0x58, 0x08, 0x3B0, 0x68};
// Transform: heading (float), and x, y, z (floats, 4 bytes apart).
constexpr std::uint64_t kHeadingOffset = 0x1D4;
constexpr std::uint64_t kPositionOffset = 0x1E0;
// Map list: active index (s32) and the pointer to the owner of the entry array.
constexpr std::uint64_t kMapListIndexOffset = 0x20;
constexpr std::uint64_t kMapListArrayOffset = 0x10;
// Owner: entry count (s32) and the pointer to the entries.
constexpr std::uint64_t kMapArrayCountOffset = 0x18;
constexpr std::uint64_t kMapArrayEntriesOffset = 0x20;
// Entry: fixed stride, packed map id (u32).
constexpr std::uint64_t kMapEntryStride = 0xA0;
constexpr std::uint64_t kMapEntryPackedIdOffset = 0x08;

constexpr std::chrono::milliseconds kPlayerLogInterval{1000};

/// Frame callback of [debug] log_player_state. Time-based (not every N-th tick) because the tick
/// rate is not constant: about 60 per second in the world, slower or stopped on loading screens.
/// Runs on the game thread only, which is the only thread that touches `last_log`.
void LogPlayerState(std::uint64_t /*frame*/) {
    static std::optional<std::chrono::steady_clock::time_point> last_log;
    const auto now = std::chrono::steady_clock::now();
    if (last_log && now - *last_log < kPlayerLogInterval) {
        return;
    }
    last_log = now;

    const auto player = GetLocalPlayer();
    const auto map = GetCurrentMapId();
    const std::string map_name = map ? Core::FormatMapId(*map) : "unknown";
    if (!player) {
        LOG_INFO(BBCoop, "player: not available (map {})", map_name);
        return;
    }
    LOG_INFO(BBCoop, "player {:#x} map {} pos ({:.2f}, {:.2f}, {:.2f}) heading {:.2f}",
             player->player_ins, map_name, player->position.x, player->position.y,
             player->position.z, player->heading);
}
} // namespace

std::optional<std::uint64_t> GetLocalPlayerIns() {
    ASSERT_MSG(IsGameThread(), "GetLocalPlayerIns used outside the game thread");
    const auto chr_man = ReadPointer(SymbolAddress(SymbolId::world_chr_man_slot));
    if (!chr_man) {
        return std::nullopt;
    }
    return ReadPointer(*chr_man + kPlayerInsOffset);
}

std::optional<PlayerSnapshot> GetLocalPlayer() {
    // GetLocalPlayerIns checks the thread.
    const auto player = GetLocalPlayerIns();
    if (!player) {
        return std::nullopt;
    }
    const auto transform = FollowPointerChain(*player, kTransformChain);
    if (!transform) {
        return std::nullopt;
    }
    const auto heading = ReadGuest<float>(*transform + kHeadingOffset);
    const auto x = ReadGuest<float>(*transform + kPositionOffset);
    const auto y = ReadGuest<float>(*transform + kPositionOffset + 4);
    const auto z = ReadGuest<float>(*transform + kPositionOffset + 8);
    if (!heading || !x || !y || !z || !std::isfinite(*heading) || !std::isfinite(*x) ||
        !std::isfinite(*y) || !std::isfinite(*z)) {
        return std::nullopt;
    }
    return PlayerSnapshot{*player, {*x, *y, *z}, *heading};
}

std::optional<std::uint32_t> GetCurrentMapId() {
    ASSERT_MSG(IsGameThread(), "GetCurrentMapId used outside the game thread");
    const auto list = ReadPointer(SymbolAddress(SymbolId::current_map_list_slot));
    if (!list) {
        return std::nullopt;
    }
    const auto index = ReadGuest<std::int32_t>(*list + kMapListIndexOffset);
    const auto array = ReadPointer(*list + kMapListArrayOffset);
    if (!index || !array || *index < 0) {
        return std::nullopt;
    }
    const auto count = ReadGuest<std::int32_t>(*array + kMapArrayCountOffset);
    const auto entries = ReadPointer(*array + kMapArrayEntriesOffset);
    if (!count || !entries || *index >= *count) {
        return std::nullopt;
    }
    return ReadGuest<std::uint32_t>(
        *entries + static_cast<std::uint64_t>(*index) * kMapEntryStride + kMapEntryPackedIdOffset);
}

void InitializeGameApi() {
    if (!GetConfig().debug.log_player_state) {
        return;
    }
    OnEveryFrame("debug.player_state", LogPlayerState);
}

} // namespace BBCoop::Runtime
