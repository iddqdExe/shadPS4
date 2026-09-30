// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>

#include "bbcoop/core/config.h"

namespace BBCoop {

struct CliOverrides {
    std::optional<std::uint16_t> port;
};

/// Stores command-line overrides; call before Initialize().
void SetCliOverrides(const CliOverrides& overrides);

/// Loads <user>/bbcoop.toml and applies CLI overrides. Call once after emulator settings load.
void Initialize();

const Core::Config& GetConfig();

} // namespace BBCoop
