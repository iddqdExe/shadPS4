// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>

namespace BBCoop::Runtime {

struct Vec3 {
    float x;
    float y;
    float z;
};

/// The local player's character at one instant.
struct PlayerSnapshot {
    std::uint64_t player_ins; ///< Guest address of the PlayerIns object.
    Vec3 position;            ///< World position, game units.
    float heading;            ///< Facing angle as the game stores it.
};

// Reads of the game's own data structures. Every function here runs on the game thread only
// (from a frame callback, a posted task or a detour after the first tick) and asserts otherwise.
// Every read goes through ReadGuest, so a pointer that is stale or not yet valid (title screen,
// loading screens, a save that is still being set up) yields nullopt, never a crash. All of them
// also return nullopt while the game has no such data yet.

/// The local PlayerIns: [[world_chr_man_slot] + 0x60]. nullopt until a character is in the world.
std::optional<std::uint64_t> GetLocalPlayerIns();

/// The local player's address, position and heading. nullopt when there is no player, when a
/// link of the transform chain is unreadable, or when a value is not a finite number.
std::optional<PlayerSnapshot> GetLocalPlayer();

/// The packed id of the map the local player is in (0xAABBCCDD, see Core::FormatMapId).
std::optional<std::uint32_t> GetCurrentMapId();

/// Registers the debug player-state log when [debug] log_player_state is set: about once per
/// second (wall clock) the game-thread tick logs the player, map and position. Call once from
/// BBCoop::Initialize(), after InitializeGameThread() and before the game is loaded.
void InitializeGameApi();

} // namespace BBCoop::Runtime
