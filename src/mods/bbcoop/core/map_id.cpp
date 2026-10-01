// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/core/map_id.h"

#include <format>

namespace BBCoop::Core {

std::string FormatMapId(std::uint32_t packed) {
    return std::format("m{:02}_{:02}_{:02}_{:02}", packed >> 24, (packed >> 16) & 0xFF,
                       (packed >> 8) & 0xFF, packed & 0xFF);
}

} // namespace BBCoop::Core
