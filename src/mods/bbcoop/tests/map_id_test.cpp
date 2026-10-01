// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <gtest/gtest.h>

#include "bbcoop/core/map_id.h"

using BBCoop::Core::FormatMapId;

TEST(MapIdTest, FormatsKnownMaps) {
    EXPECT_EQ(FormatMapId(0x15000000), "m21_00_00_00"); // Hunter's Dream
    EXPECT_EQ(FormatMapId(0x18010000), "m24_01_00_00"); // Central Yharnam / Great Bridge
    EXPECT_EQ(FormatMapId(0x17000000), "m23_00_00_00");
}

TEST(MapIdTest, FormatsEveryByteInDecimal) {
    EXPECT_EQ(FormatMapId(0x1C00010A), "m28_00_01_10");
}
