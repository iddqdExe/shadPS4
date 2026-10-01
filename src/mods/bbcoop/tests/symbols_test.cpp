// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

// Consistency checks of the generated EU 1.09 tables. The full check against the game image is
// bbcoop_sigcheck, which needs the decrypted eboot and cannot run in CI; these run everywhere.

#include <cstddef>
#include <string_view>

#include <gtest/gtest.h>

#include "bbcoop/binding/signature.h"
#include "bbcoop/binding/symbols.h"

using namespace BBCoop::Binding;

// (One spec per SymbolId is a static_assert in symbols.cpp.)
TEST(SymbolsTest, TableIsNotEmpty) {
    EXPECT_FALSE(Eu109Symbols().empty());
}

TEST(SymbolsTest, EveryPatchAnchorIsAPatchSymbol) {
    ASSERT_FALSE(Eu109Patches().empty());
    for (const auto& patch : Eu109Patches()) {
        const auto id = FindSymbol(patch.anchor);
        ASSERT_TRUE(id.has_value())
            << patch.name << ": anchor " << patch.anchor << " is not in the table";
        EXPECT_EQ(Eu109Symbols()[static_cast<std::size_t>(*id)].kind, SymbolKind::Patch)
            << patch.name;
    }
}

TEST(SymbolsTest, NamesRoundTripThroughFindSymbol) {
    for (const auto& spec : Eu109Symbols()) {
        const auto id = FindSymbol(spec.name);
        ASSERT_TRUE(id.has_value()) << spec.name;
        EXPECT_EQ(SymbolName(*id), spec.name);
    }
    EXPECT_FALSE(FindSymbol("no_such_symbol").has_value());
}

TEST(SymbolsTest, RequiredSymbolsArePresentAndRequired) {
    for (const std::string_view name :
         {"idle_heartbeat_epilogue", "world_chr_man_slot", "current_map_list_slot"}) {
        const auto id = FindSymbol(name);
        ASSERT_TRUE(id.has_value()) << name;
        EXPECT_TRUE(Eu109Symbols()[static_cast<std::size_t>(*id)].required) << name;
    }
}

TEST(SymbolsTest, CodeSymbolsHaveAMaxStealAndDataSymbolsNone) {
    for (const auto& spec : Eu109Symbols()) {
        switch (spec.kind) {
        case SymbolKind::Function:
        case SymbolKind::Site:
        case SymbolKind::Patch:
            EXPECT_GE(spec.max_steal, 1) << spec.name;
            EXPECT_LE(spec.max_steal, kMaxHookSteal) << spec.name;
            break;
        case SymbolKind::Global:
        case SymbolKind::Data:
            EXPECT_EQ(spec.max_steal, 0) << spec.name << ": not hookable";
            break;
        }
    }
}

TEST(SymbolsTest, TheTickSiteMayBeHooked) {
    // The game-thread tick steals the 7-byte add rsp,0x7E8 at idle_heartbeat_epilogue.
    const auto id = FindSymbol("idle_heartbeat_epilogue");
    ASSERT_TRUE(id.has_value());
    EXPECT_GE(Eu109Symbols()[static_cast<std::size_t>(*id)].max_steal, 7);
}

TEST(SymbolsTest, EveryPatternParses) {
    for (const auto& spec : Eu109Symbols()) {
        const auto sig = Signature::Parse(spec.pattern);
        EXPECT_TRUE(sig.has_value()) << spec.name << ": " << (sig ? "" : sig.error());
    }
}
