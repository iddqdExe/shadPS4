// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <vector>

#include <gtest/gtest.h>

#include "bbcoop/binding/resolver.h"

using namespace BBCoop::Binding;

namespace {
constexpr std::uint64_t kTextRva = 0x1000;

std::vector<std::uint8_t> MakeText() {
    std::vector<std::uint8_t> t(0x100, 0xCC);
    const auto put = [&](std::size_t at, std::initializer_list<std::uint8_t> bytes) {
        std::copy(bytes.begin(), bytes.end(), t.begin() + static_cast<std::ptrdiff_t>(at));
    };
    put(0x10, {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57});       // unique prologue
    put(0x40, {0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}); // mov rax,[rip+0x10] -> 0x1057
    put(0x60, {0xE8, 0x9B, 0xFF, 0xFF, 0xFF});             // call rel32 -> 0x1000
    put(0x80, {0x90, 0x90, 0x31, 0xC0});                   // duplicated
    put(0xA0, {0x90, 0x90, 0x31, 0xC0});
    return t;
}

SymbolSpec Spec(std::string_view name, std::string_view pattern, TargetMode mode = TargetMode::Match,
                bool required = true, std::uint64_t match = 0, std::uint64_t target = 0) {
    return SymbolSpec{name, SymbolKind::Site, required, target, match, 0, mode, pattern};
}
} // namespace

TEST(ResolverTest, ResolvesUniqueMatchByScanning) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("prologue", "55 48 89 E5")};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1010u);
}

TEST(ResolverTest, ResolvesRipRelativeAndCallTargets) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("global", "48 8B 05 ?? ?? ?? ??", TargetMode::RelativeOperand),
                                Spec("callee", "E8 ?? ?? ?? ??", TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1057u);
    EXPECT_EQ(r.rvas[1], 0x1000u);
}

TEST(ResolverTest, ReportsNotFoundAndAmbiguous) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("missing", "0F 0B"), Spec("twice", "90 90 31 C0")};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 2u);
    EXPECT_EQ(r.failures[0].error, ResolveError::NotFound);
    EXPECT_EQ(r.failures[1].error, ResolveError::Ambiguous);
    EXPECT_EQ(r.failures[1].match_count, 2u);
    EXPECT_EQ(r.rvas[0], 0u);
}

TEST(ResolverTest, ReferenceImageTrustsHintInsteadOfScanning) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("twice", "90 90 31 C0", TargetMode::Match, true, 0x1080, 0x1080)};
    const auto r = ResolveSymbols({text, kTextRva, true}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1080u);
}

TEST(ResolverTest, ReferenceImageRejectsWrongHintOrTarget) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {
        Spec("bad_match", "90 90 31 C0", TargetMode::Match, true, 0x1081, 0x1081),
        Spec("bad_target", "48 8B 05 ?? ?? ?? ??", TargetMode::RelativeOperand, true, 0x1040, 0x2000)};
    const auto r = ResolveSymbols({text, kTextRva, true}, specs);
    ASSERT_EQ(r.failures.size(), 2u);
    EXPECT_EQ(r.failures[0].error, ResolveError::HintMismatch);
    EXPECT_EQ(r.failures[1].error, ResolveError::HintMismatch);
}

TEST(ResolverTest, OnlyRequiredFailuresBlock) {
    const auto text = MakeText();
    const SymbolSpec optional_missing[] = {Spec("ok", "55 48 89 E5"),
                                           Spec("missing", "0F 0B", TargetMode::Match, false)};
    EXPECT_TRUE(ResolveSymbols({text, kTextRva, false}, optional_missing).AllRequiredResolved());
    const SymbolSpec required_missing[] = {Spec("missing", "0F 0B")};
    EXPECT_FALSE(ResolveSymbols({text, kTextRva, false}, required_missing).AllRequiredResolved());
}

TEST(ResolverTest, BadPatternAndMissingOperandAreReported) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("bad", "XX"),
                                Spec("no_operand", "55 48 89 E5", TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 2u);
    EXPECT_EQ(r.failures[0].error, ResolveError::BadPattern);
    EXPECT_EQ(r.failures[1].error, ResolveError::BadOperand);
}

TEST(ResolverTest, FingerprintIsDeterministicAndSensitive) {
    auto text = MakeText();
    const auto a = Fingerprint(text);
    EXPECT_EQ(a, Fingerprint(text));
    text[0] ^= 1;
    EXPECT_NE(a, Fingerprint(text));
}

// Ruling 0B-R3: rvas[i] == 0 is the "unresolved" sentinel and RVA 0 is never a valid symbol
// (on the real image it is the INTERP string), so Rva() must hide it from callers.
TEST(ResolverTest, UnresolvedRvaIsNullopt) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("ok", "55 48 89 E5"),
                                Spec("missing", "0F 0B", TargetMode::Match, false)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 1u);
    ASSERT_TRUE(r.AllRequiredResolved());
    EXPECT_EQ(r.ResolvedCount(), 1u);
    ASSERT_TRUE(r.Rva(0).has_value());
    EXPECT_EQ(*r.Rva(0), 0x1010u);
    EXPECT_FALSE(r.Rva(1).has_value());
    EXPECT_FALSE(r.Rva(2).has_value()); // out of range
}
