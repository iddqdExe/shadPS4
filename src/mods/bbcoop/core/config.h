// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace BBCoop::Core {

/// What happens to a player's blood echoes on death outside a boss fight (spec F9).
enum class EchoLossRule { Vanilla, Keep };

/// Which pickups are copied to every participant (spec F14).
enum class AutoGrantMode { All, UniqueOnly };

struct NetConfig {
    std::uint16_t port = 41800;
    bool upnp = false;
    std::string rendezvous; ///< Empty means direct connect only (stage 1).
};

struct HostRules {
    EchoLossRule echo_loss = EchoLossRule::Vanilla;
    AutoGrantMode auto_grant = AutoGrantMode::All;
    bool guest_hp_penalty = false; ///< Vanilla 70% guest HP penalty (spec §6.8: off).
    std::uint8_t max_players = 3;
};

/// Link state thresholds (spec §8.1): ok -> suspect -> reconnecting -> dead.
struct Timeouts {
    std::uint32_t suspect_ms = 3000;
    std::uint32_t reconnect_ms = 5000;
    std::uint32_t dead_ms = 45000;
};

struct DebugConfig {
    bool log_player_state = false; ///< Log player, map and position once per second.
};

struct Config {
    bool enabled = true;
    NetConfig net;
    HostRules host;
    Timeouts timeouts;
    DebugConfig debug;
};

struct ConfigResult {
    Config config;
    std::vector<std::string> warnings; ///< Non-fatal problems such as unknown keys.
};

/// Parses bbcoop.toml text. Missing keys keep their defaults; invalid values are errors.
std::expected<ConfigResult, std::string> ParseConfig(std::string_view text,
                                                     std::string_view source_name);

/// Loads bbcoop.toml from disk. A missing file yields defaults plus a warning.
std::expected<ConfigResult, std::string> LoadConfigFile(const std::filesystem::path& path);

std::string_view ToString(EchoLossRule rule);
std::string_view ToString(AutoGrantMode mode);

} // namespace BBCoop::Core
