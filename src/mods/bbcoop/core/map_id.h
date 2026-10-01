// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <string>

namespace BBCoop::Core {

/// Packed map id 0xAABBCCDD -> "mAA_BB_CC_DD" with each byte in decimal.
std::string FormatMapId(std::uint32_t packed);

} // namespace BBCoop::Core
