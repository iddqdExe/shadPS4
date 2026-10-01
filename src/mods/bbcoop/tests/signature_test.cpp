// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "bbcoop/binding/signature.h"

using BBCoop::Binding::FormatHexBytes;
using BBCoop::Binding::Signature;

TEST(SignatureTest, ParsesBytesAndWildcards) {
    const auto sig = Signature::Parse("48 8b ?? 05");
    ASSERT_TRUE(sig.has_value()) << sig.error();
    EXPECT_EQ(sig->Size(), 4u);
    EXPECT_EQ(sig->ToString(), "48 8B ?? 05");
}

TEST(SignatureTest, AcceptsSingleQuestionMarkAndExtraSpaces) {
    const auto sig = Signature::Parse("  48   ?  05 ");
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->ToString(), "48 ?? 05");
}

TEST(SignatureTest, RejectsInvalidToken) {
    const auto sig = Signature::Parse("48 ZZ");
    ASSERT_FALSE(sig.has_value());
    EXPECT_NE(sig.error().find("ZZ"), std::string::npos);
}

TEST(SignatureTest, RejectsEmptyAndAllWildcards) {
    EXPECT_FALSE(Signature::Parse("").has_value());
    EXPECT_FALSE(Signature::Parse("?? ??").has_value());
}

TEST(SignatureTest, MatchesAtRespectsWildcardsAndBounds) {
    const std::vector<std::uint8_t> hay{0x48, 0x8B, 0x77, 0x05};
    const auto sig = *Signature::Parse("48 8B ?? 05");
    EXPECT_TRUE(sig.MatchesAt(hay, 0));
    EXPECT_FALSE(sig.MatchesAt(hay, 1));
    EXPECT_FALSE(sig.MatchesAt(hay, 4));
}

TEST(SignatureTest, FindAllReturnsEveryMatchInOrder) {
    const std::vector<std::uint8_t> hay{0x48, 0x8B, 0x01, 0x05, 0x00, 0x48, 0x8B, 0x02, 0x05};
    const auto sig = *Signature::Parse("48 8B ?? 05");
    EXPECT_EQ(sig.FindAll(hay, 10), (std::vector<std::size_t>{0, 5}));
    EXPECT_EQ(sig.FindAll(hay, 1), (std::vector<std::size_t>{0}));
}

TEST(SignatureTest, FindAllHandlesLeadingWildcard) {
    const auto sig = *Signature::Parse("?? 8B 05");
    EXPECT_EQ(sig.FindAll(std::vector<std::uint8_t>{0x10, 0x8B, 0x05}, 10),
              (std::vector<std::size_t>{0}));
    EXPECT_TRUE(sig.FindAll(std::vector<std::uint8_t>{0x8B, 0x05}, 10).empty());
}

TEST(SignatureTest, FindAllIgnoresMatchCutByEnd) {
    const auto sig = *Signature::Parse("48 8B 05 ??");
    EXPECT_TRUE(sig.FindAll(std::vector<std::uint8_t>{0x00, 0x48, 0x8B, 0x05}, 10).empty());
}

TEST(SignatureTest, BytesExposesParsedBytesWithZeroAtWildcards) {
    const auto sig = *Signature::Parse("48 8b ?? 05");
    const auto bytes = sig.Bytes();
    EXPECT_EQ((std::vector<std::uint8_t>(bytes.begin(), bytes.end())),
              (std::vector<std::uint8_t>{0x48, 0x8B, 0x00, 0x05}));
}

TEST(SignatureTest, HasWildcardsReflectsThePattern) {
    EXPECT_FALSE(Signature::Parse("48 8B 05")->HasWildcards());
    EXPECT_TRUE(Signature::Parse("48 ?? 05")->HasWildcards());
    EXPECT_TRUE(Signature::Parse("?? 48")->HasWildcards());
    EXPECT_TRUE(Signature::Parse("48 ?")->HasWildcards());
}

TEST(SignatureTest, FormatHexBytesIsUppercaseTwoDigitAndSpaceSeparated) {
    EXPECT_EQ(FormatHexBytes(std::vector<std::uint8_t>{0x48, 0x8B, 0x05}), "48 8B 05");
    EXPECT_EQ(FormatHexBytes(std::vector<std::uint8_t>{0x00, 0x0A, 0xFF}), "00 0A FF");
    EXPECT_EQ(FormatHexBytes(std::vector<std::uint8_t>{0xAB}), "AB");
}

TEST(SignatureTest, FormatHexBytesOfEmptySpanIsEmpty) {
    EXPECT_EQ(FormatHexBytes(std::span<const std::uint8_t>{}), "");
}

TEST(SignatureTest, ToStringOfWildcardFreePatternMatchesFormatHexBytes) {
    const auto sig = *Signature::Parse("48 8b 05 0a");
    EXPECT_EQ(sig.ToString(), FormatHexBytes(sig.Bytes()));
}

TEST(SignatureTest, CannotBeDefaultConstructedIntoAnEmptyPattern) {
    // An empty Signature would violate Parse's invariants (FindAll on it would match every offset).
    static_assert(!std::is_default_constructible_v<Signature>);
    SUCCEED();
}
