// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "bbcoop/binding/patch_table.h"

using namespace BBCoop::Binding;

namespace {
constexpr std::uint64_t kTextRva = 0x1000;

struct Fixture {
    std::vector<std::uint8_t> pristine = std::vector<std::uint8_t>(0x40, 0x90);
    std::vector<std::uint8_t> live;
    std::map<std::string, std::uint64_t, std::less<>> symbols{{"patch_a", 0x1010},
                                                              {"patch_b", 0x1020}};
    Fixture() {
        pristine[0x10] = 0x74;
        pristine[0x11] = 0x0D; // je +0xD
        pristine[0x20] = 0x34;
        pristine[0x21] = 0x01; // xor al,1
        live = pristine;
    }
    PatchPlan Plan(std::span<const PatchSpec> specs, std::span<const std::string_view> groups,
                   bool reference = true) {
        return PlanPatches({specs, groups,
                            [this](std::string_view n) -> std::optional<std::uint64_t> {
                                const auto it = symbols.find(n);
                                return it == symbols.end() ? std::nullopt
                                                           : std::optional{it->second};
                            },
                            pristine, live, kTextRva, reference});
    }
};
const std::string_view kGroupA[] = {"a"};
const std::string_view kGroupsAB[] = {"a", "b"};
} // namespace

TEST(PatchTableTest, PlansEnabledPatch) {
    Fixture f;
    const PatchSpec specs[] = {{"jump", "a", "patch_a", "74 0D", "EB 0D", false}};
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_TRUE(plan.Ok());
    ASSERT_EQ(plan.ops.size(), 1u);
    EXPECT_EQ(plan.ops[0].rva, 0x1010u);
    EXPECT_EQ(plan.ops[0].replacement, (std::vector<std::uint8_t>{0xEB, 0x0D}));
}

TEST(PatchTableTest, DisabledGroupIsVerifiedButNotPlanned) {
    Fixture f;
    const PatchSpec specs[] = {{"wrong", "b", "patch_b", "35 01", "31 C0", false}};
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_TRUE(plan.Ok());
    EXPECT_TRUE(plan.ops.empty());
    ASSERT_EQ(plan.warnings.size(), 1u);
    EXPECT_NE(plan.warnings[0].detail.find("original bytes differ"), std::string::npos);
}

TEST(PatchTableTest, EnabledGroupErrors) {
    Fixture f;
    f.live[0x11] = 0x0E; // another patcher touched the site
    const PatchSpec specs[] = {
        {"modified", "a", "patch_a", "74 0D", "EB 0D", false},
        {"mismatch", "a", "patch_b", "35 01", "31 C0", false},
        {"unresolved", "a", "patch_missing", "74 0D", "EB 0D", false},
        {"length", "a", "patch_a", "74 0D", "EB", false},
        {"wildcard", "a", "patch_a", "74 ??", "EB 0D", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_FALSE(plan.Ok());
    EXPECT_EQ(plan.errors.size(), 5u);
    EXPECT_TRUE(plan.ops.empty());
    EXPECT_NE(plan.errors[0].detail.find("modified by another patcher"), std::string::npos);
}

TEST(PatchTableTest, PositionDependentNeedsReferenceImage) {
    Fixture f;
    const PatchSpec specs[] = {{"call", "a", "patch_a", "74 0D", "EB 0D", true}};
    EXPECT_TRUE(f.Plan(specs, kGroupA, true).Ok());
    EXPECT_FALSE(f.Plan(specs, kGroupA, false).Ok());
}

TEST(PatchTableTest, ApplyAndRevert) {
    Fixture f;
    const PatchSpec specs[] = {{"jump", "a", "patch_a", "74 0D", "EB 0D", false}};
    const auto plan = f.Plan(specs, kGroupA);
    const MemoryWriter write = [&](std::uint64_t rva, std::span<const std::uint8_t> bytes) {
        std::copy(bytes.begin(), bytes.end(),
                  f.live.begin() + static_cast<std::ptrdiff_t>(rva - kTextRva));
    };
    ApplyPatches(plan.ops, write);
    EXPECT_EQ(f.live[0x10], 0xEB);
    RevertPatches(plan.ops, write);
    EXPECT_EQ(f.live[0x10], 0x74);
}

TEST(PatchTableTest, EachErrorNamesItsProblem) {
    Fixture f;
    f.live[0x11] = 0x0E;
    const PatchSpec specs[] = {
        {"mismatch", "a", "patch_b", "35 01", "31 C0", false},
        {"unresolved", "a", "patch_missing", "74 0D", "EB 0D", false},
        {"length", "a", "patch_a", "74 0D", "EB", false},
        {"wildcard", "a", "patch_a", "74 ??", "EB 0D", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.errors.size(), 4u);
    EXPECT_EQ(plan.errors[0].name, "mismatch");
    EXPECT_EQ(plan.errors[0].detail,
              "original bytes differ at 0x1020: expected 35 01, found 34 01");
    EXPECT_EQ(plan.errors[1].name, "unresolved");
    EXPECT_NE(plan.errors[1].detail.find("patch_missing"), std::string::npos);
    EXPECT_NE(plan.errors[2].detail.find("lengths differ (2 vs 1)"), std::string::npos);
    EXPECT_NE(plan.errors[3].detail.find("wildcards are not allowed"), std::string::npos);
}

TEST(PatchTableTest, ModifiedSiteReportsLiveBytes) {
    Fixture f;
    f.live[0x11] = 0x0E;
    const PatchSpec specs[] = {{"modified", "a", "patch_a", "74 0D", "EB 0D", false}};
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.errors.size(), 1u);
    EXPECT_EQ(plan.errors[0].detail, "bytes at 0x1010 were modified by another patcher: 74 0E");
}

TEST(PatchTableTest, ModifiedSiteInDisabledGroupIsOnlyAWarning) {
    Fixture f;
    f.live[0x11] = 0x0E;
    const PatchSpec specs[] = {{"modified", "b", "patch_a", "74 0D", "EB 0D", false}};
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_TRUE(plan.Ok());
    EXPECT_TRUE(plan.ops.empty());
    ASSERT_EQ(plan.warnings.size(), 1u);
    EXPECT_NE(plan.warnings[0].detail.find("modified by another patcher"), std::string::npos);
}

TEST(PatchTableTest, OneBadPatchDoesNotHideTheOthersButNothingIsPlanned) {
    Fixture f;
    const PatchSpec specs[] = {
        {"good", "a", "patch_a", "74 0D", "EB 0D", false},
        {"bad1", "a", "patch_missing", "74 0D", "EB 0D", false},
        {"bad2", "a", "patch_b", "35 01", "31 C0", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_FALSE(plan.Ok());
    // Every bad spec is still reported, and the good one is not planned on its own.
    ASSERT_EQ(plan.errors.size(), 2u);
    EXPECT_EQ(plan.errors[0].name, "bad1");
    EXPECT_EQ(plan.errors[1].name, "bad2");
    EXPECT_TRUE(plan.ops.empty());
}

TEST(PatchTableTest, RejectsPatchOutsideText) {
    Fixture f;
    f.symbols["before"] = kTextRva - 1;
    f.symbols["straddling_end"] = kTextRva + 0x3F; // the second byte lies past the end
    f.symbols["past_end"] = kTextRva + 0x40;
    const PatchSpec specs[] = {
        {"before", "a", "before", "90 90", "CC CC", false},
        {"straddling_end", "a", "straddling_end", "90 90", "CC CC", false},
        {"past_end", "a", "past_end", "90 90", "CC CC", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.errors.size(), 3u);
    for (const auto& error : plan.errors) {
        EXPECT_NE(error.detail.find("outside the text segment"), std::string::npos) << error.name;
    }
}

TEST(PatchTableTest, RejectsAnchorWhoseOffsetWrapsAround) {
    // text_rva 0 and rva UINT64_MAX: an "off + size > text.size()" check wraps to a tiny value.
    const std::vector<std::uint8_t> text(0x40, 0x90);
    const PatchSpec specs[] = {{"far", "a", "far", "90 90", "CC CC", false}};
    const auto plan = PlanPatches(
        {specs, kGroupA,
         [](std::string_view) -> std::optional<std::uint64_t> { return UINT64_MAX; }, text, text,
         0, true});
    ASSERT_EQ(plan.errors.size(), 1u);
    EXPECT_NE(plan.errors[0].detail.find("outside the text segment"), std::string::npos);
    EXPECT_TRUE(plan.ops.empty());
}

TEST(PatchTableTest, RevertWritesOriginalsInReverseOrder) {
    // Two ops over the same byte: reverting in reverse order must end at the first op's original.
    std::uint8_t memory = 0x74;
    std::vector<std::uint8_t> written;
    const MemoryWriter write = [&](std::uint64_t, std::span<const std::uint8_t> bytes) {
        memory = bytes[0];
        written.push_back(bytes[0]);
    };
    const PatchOp ops[] = {{"first", 0x10, {0x74}, {0xEB}}, {"second", 0x10, {0xEB}, {0x90}}};
    ApplyPatches(ops, write);
    EXPECT_EQ(memory, 0x90);
    RevertPatches(ops, write);
    EXPECT_EQ(memory, 0x74);
    EXPECT_EQ(written, (std::vector<std::uint8_t>{0xEB, 0x90, 0xEB, 0x74}));
}

TEST(PatchTableTest, ParseHexBytesAcceptsBothCasesAndExtraSpaces) {
    const auto bytes = ParseHexBytes("  eb 0D   ff ");
    ASSERT_TRUE(bytes.has_value()) << bytes.error();
    EXPECT_EQ(*bytes, (std::vector<std::uint8_t>{0xEB, 0x0D, 0xFF}));
}

TEST(PatchTableTest, ParseHexBytesRejectsWildcards) {
    const auto bytes = ParseHexBytes("EB ??");
    ASSERT_FALSE(bytes.has_value());
    EXPECT_EQ(bytes.error(), "wildcards are not allowed in patch bytes");
    EXPECT_FALSE(ParseHexBytes("EB ?").has_value());
}

TEST(PatchTableTest, ParseHexBytesRejectsEmptyAndBadTokens) {
    EXPECT_FALSE(ParseHexBytes("").has_value());
    EXPECT_FALSE(ParseHexBytes("   ").has_value());
    EXPECT_FALSE(ParseHexBytes("EB ZZ").has_value());
    EXPECT_FALSE(ParseHexBytes("EB 0").has_value());
    EXPECT_FALSE(ParseHexBytes("EB 0D1").has_value());
}

TEST(PatchTableTest, PlannedOpCarriesNameAndBytes) {
    Fixture f;
    const PatchSpec specs[] = {{"jump", "a", "patch_a", "74 0D", "EB 0D", false}};
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.ops.size(), 1u);
    EXPECT_EQ(plan.ops[0].name, "jump");
    EXPECT_EQ(plan.ops[0].original, (std::vector<std::uint8_t>{0x74, 0x0D}));
    EXPECT_EQ(plan.ops[0].replacement, (std::vector<std::uint8_t>{0xEB, 0x0D}));
}

TEST(PatchTableTest, PositionDependentRejectionExplainsWhy) {
    Fixture f;
    const PatchSpec specs[] = {{"call", "a", "patch_a", "74 0D", "EB 0D", true}};
    const auto plan = f.Plan(specs, kGroupA, false);
    ASSERT_EQ(plan.errors.size(), 1u);
    EXPECT_EQ(plan.errors[0].name, "call");
    EXPECT_EQ(plan.errors[0].detail, "position-dependent patch requires the reference image");
    EXPECT_TRUE(plan.ops.empty());
}

TEST(PatchTableTest, AcceptsPatchEndingExactlyAtEndOfText) {
    Fixture f;
    f.symbols["last_two"] = kTextRva + 0x3E; // bytes 0x3E and 0x3F, the last two of the text
    f.symbols["last_one"] = kTextRva + 0x3F;
    const PatchSpec specs[] = {{"two", "a", "last_two", "90 90", "CC CC", false}};
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_TRUE(plan.Ok());
    ASSERT_EQ(plan.ops.size(), 1u);
    EXPECT_EQ(plan.ops[0].rva, kTextRva + 0x3E);
    const PatchSpec one[] = {{"one", "a", "last_one", "90", "CC", false}};
    EXPECT_TRUE(f.Plan(one, kGroupA).Ok());
}

TEST(PatchTableTest, ParseFailureNamesTheBadField) {
    Fixture f;
    const PatchSpec specs[] = {
        {"bad_original", "a", "patch_a", "74 ZZ", "EB 0D", false},
        {"bad_replacement", "a", "patch_a", "74 0D", "EB ZZ", false},
        {"wild_replacement", "a", "patch_a", "74 0D", "EB ??", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.errors.size(), 3u);
    EXPECT_EQ(plan.errors[0].detail.rfind("original: ", 0), 0u) << plan.errors[0].detail;
    EXPECT_EQ(plan.errors[1].detail.rfind("replacement: ", 0), 0u) << plan.errors[1].detail;
    EXPECT_EQ(plan.errors[2].detail,
              "replacement: wildcards are not allowed in patch bytes");
}

TEST(PatchTableTest, ParseHexBytesRejectsInputMadeOnlyOfWildcards) {
    constexpr std::string_view kMessage = "wildcards are not allowed in patch bytes";
    for (const std::string_view text : {"??", "?", "?? ??", " ? ?? "}) {
        const auto bytes = ParseHexBytes(text);
        ASSERT_FALSE(bytes.has_value()) << text;
        EXPECT_EQ(bytes.error(), kMessage) << text;
    }
}

TEST(PatchTableTest, TwoEnabledPatchesOnTheSameSiteAreAConflict) {
    Fixture f;
    const PatchSpec specs[] = {
        {"first", "a", "patch_a", "74 0D", "EB 0D", false},
        {"second", "b", "patch_a", "74 0D", "90 90", false},
    };
    const auto plan = f.Plan(specs, kGroupsAB);
    EXPECT_FALSE(plan.Ok());
    ASSERT_EQ(plan.errors.size(), 1u);
    EXPECT_EQ(plan.errors[0].name, "second");
    EXPECT_NE(plan.errors[0].detail.find("first"), std::string::npos) << plan.errors[0].detail;
    EXPECT_TRUE(plan.ops.empty());
}

TEST(PatchTableTest, PartiallyOverlappingEnabledPatchesAreAConflict) {
    Fixture f;
    f.symbols["s30"] = kTextRva + 0x30;
    f.symbols["s32"] = kTextRva + 0x32;
    // Listed in reverse address order: the check must not depend on the table order.
    const PatchSpec specs[] = {
        {"late", "a", "s32", "90 90", "CC CC", false},         // 0x32..0x33
        {"early", "a", "s30", "90 90 90", "CC CC CC", false}, // 0x30..0x32
    };
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_FALSE(plan.Ok());
    ASSERT_EQ(plan.errors.size(), 1u);
    EXPECT_EQ(plan.errors[0].name, "late");
    EXPECT_NE(plan.errors[0].detail.find("early"), std::string::npos) << plan.errors[0].detail;
    EXPECT_TRUE(plan.ops.empty());
}

TEST(PatchTableTest, AdjacentEnabledPatchesAreNotAConflict) {
    Fixture f;
    f.symbols["s30"] = kTextRva + 0x30;
    f.symbols["s32"] = kTextRva + 0x32;
    const PatchSpec specs[] = {
        {"left", "a", "s30", "90 90", "CC CC", false},  // 0x30..0x31
        {"right", "a", "s32", "90 90", "CC CC", false}, // 0x32..0x33
    };
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_TRUE(plan.Ok());
    EXPECT_EQ(plan.ops.size(), 2u);
}

TEST(PatchTableTest, OverlapWithADisabledGroupIsIgnored) {
    Fixture f;
    const PatchSpec specs[] = {
        {"enabled", "a", "patch_a", "74 0D", "EB 0D", false},
        {"disabled", "b", "patch_a", "74 0D", "90 90", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    EXPECT_TRUE(plan.Ok());
    EXPECT_TRUE(plan.warnings.empty());
    ASSERT_EQ(plan.ops.size(), 1u);
    EXPECT_EQ(plan.ops[0].name, "enabled");
}

TEST(PatchTableTest, EveryPatchInsideALongerOneIsReported) {
    Fixture f;
    f.symbols["s30"] = kTextRva + 0x30;
    f.symbols["s31"] = kTextRva + 0x31;
    f.symbols["s32"] = kTextRva + 0x32;
    // "inner1" and "inner2" do not touch each other, but both lie inside "outer".
    const PatchSpec specs[] = {
        {"outer", "a", "s30", "90 90 90 90", "CC CC CC CC", false},
        {"inner1", "a", "s31", "90", "CC", false},
        {"inner2", "a", "s32", "90", "CC", false},
    };
    const auto plan = f.Plan(specs, kGroupA);
    ASSERT_EQ(plan.errors.size(), 2u);
    EXPECT_EQ(plan.errors[0].name, "inner1");
    EXPECT_EQ(plan.errors[1].name, "inner2");
    for (const auto& error : plan.errors) {
        EXPECT_NE(error.detail.find("outer"), std::string::npos) << error.detail;
    }
}
