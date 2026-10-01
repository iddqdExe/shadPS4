// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
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

// ---- Fix round 1: operand_offset, RVA 0, text bounds, failure details ----

namespace {
SymbolSpec SpecAt(std::string_view name, std::string_view pattern, std::int32_t operand_offset,
                  TargetMode mode = TargetMode::Match, bool required = true, std::uint64_t match = 0,
                  std::uint64_t target = 0) {
    return SymbolSpec{name, SymbolKind::Site, required, target, match, operand_offset, mode, pattern};
}

void PutBytes(std::vector<std::uint8_t>& text, std::size_t at,
              std::initializer_list<std::uint8_t> bytes) {
    std::copy(bytes.begin(), bytes.end(), text.begin() + static_cast<std::ptrdiff_t>(at));
}

// MakeText() plus two unique marker runs next to the RIP-relative instructions:
// A1 A2 A3 A4 at 0x3C (just before the mov at 0x40) and A5 A6 at 0x65 (just after the call at 0x60).
std::vector<std::uint8_t> MakeMarkedText() {
    auto t = MakeText();
    PutBytes(t, 0x3C, {0xA1, 0xA2, 0xA3, 0xA4});
    PutBytes(t, 0x65, {0xA5, 0xA6});
    return t;
}

bool ContainsText(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}
} // namespace

TEST(ResolverTest, ScanMatchAppliesPositiveOffset) {
    const auto text = MakeText();
    const SymbolSpec specs[] = {SpecAt("after_prologue", "55 48 89 E5", 2)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1012u);
}

TEST(ResolverTest, ScanMatchAppliesNegativeOffset) {
    const auto text = MakeText();
    // "41 57" matches at 0x1014; -4 points back to the 0x1010 prologue start.
    const SymbolSpec specs[] = {SpecAt("function_start", "41 57", -4)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1010u);
}

TEST(ResolverTest, RelativeOperandAppliesPositiveOffset) {
    const auto text = MakeMarkedText();
    // The pattern matches at 0x103C; the mov rax,[rip+0x10] is 4 bytes further, at 0x1040.
    const SymbolSpec specs[] = {SpecAt("global", "A1 A2 A3 A4", 4, TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1057u);
}

TEST(ResolverTest, RelativeOperandAppliesNegativeOffset) {
    const auto text = MakeMarkedText();
    // The pattern matches at 0x1065; the call is 5 bytes earlier, at 0x1060.
    const SymbolSpec specs[] = {SpecAt("callee", "A5 A6", -5, TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1000u);
}

TEST(ResolverTest, ReferenceImageAppliesOffsetBeforeComparingTarget) {
    const auto text = MakeMarkedText();
    const SymbolSpec good[] = {
        SpecAt("plus", "55 48 89 E5", 2, TargetMode::Match, true, 0x1010, 0x1012),
        SpecAt("operand_plus", "A1 A2 A3 A4", 4, TargetMode::RelativeOperand, true, 0x103C, 0x1057),
        SpecAt("operand_minus", "A5 A6", -5, TargetMode::RelativeOperand, true, 0x1065, 0x1000)};
    const auto r = ResolveSymbols({text, kTextRva, true}, good);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x1012u);
    EXPECT_EQ(r.rvas[1], 0x1057u);
    EXPECT_EQ(r.rvas[2], 0x1000u);

    // A table row that forgot the offset (target == match) must be rejected, not silently accepted.
    const SymbolSpec stale[] = {
        SpecAt("plus", "55 48 89 E5", 2, TargetMode::Match, true, 0x1010, 0x1010)};
    const auto bad = ResolveSymbols({text, kTextRva, true}, stale);
    ASSERT_EQ(bad.failures.size(), 1u);
    EXPECT_EQ(bad.failures[0].error, ResolveError::HintMismatch);
    EXPECT_TRUE(ContainsText(bad.failures[0].detail, "0x1012")) << bad.failures[0].detail;
    EXPECT_EQ(bad.rvas[0], 0u);
}

TEST(ResolverTest, MatchTargetMustLieInsideText) {
    const auto text = MakeText(); // [0x1000, 0x1100)
    const SymbolSpec specs[] = {SpecAt("before_text", "55 48 89 E5", -0x20),
                                SpecAt("at_text_end", "55 48 89 E5", 0xF0),
                                SpecAt("last_byte", "55 48 89 E5", 0xEF),
                                SpecAt("far_past", "55 48 89 E5", 0x1000),
                                SpecAt("wraps_below_zero", "55 48 89 E5", -0x2000)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 4u);
    for (const auto& f : r.failures) {
        EXPECT_EQ(f.error, ResolveError::OutOfText) << f.name;
        EXPECT_TRUE(f.required) << f.name;
    }
    EXPECT_EQ(r.failures[0].name, "before_text");
    EXPECT_EQ(r.failures[1].name, "at_text_end");
    EXPECT_EQ(r.failures[2].name, "far_past");
    EXPECT_EQ(r.failures[3].name, "wraps_below_zero");
    EXPECT_EQ(r.rvas[0], 0u);
    EXPECT_EQ(r.rvas[1], 0u);
    EXPECT_EQ(r.rvas[2], 0x10FFu); // the last byte of the text is still inside
    EXPECT_EQ(r.rvas[3], 0u);
    EXPECT_EQ(r.rvas[4], 0u);
    EXPECT_FALSE(r.AllRequiredResolved());
}

TEST(ResolverTest, RelativeOperandTargetMayLieOutsideText) {
    auto text = MakeText();
    // call rel32 at 0x70 whose target (0x1070 + 5 + 0x2000) is far outside the 0x100-byte text:
    // globals and data legitimately live there.
    PutBytes(text, 0x70, {0xE8, 0x00, 0x20, 0x00, 0x00});
    const SymbolSpec specs[] = {SpecAt("far", "E8 00 20 00 00", 0, TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x3075u);
}

TEST(ResolverTest, ZeroTextRvaLayoutResolvesNonZeroSymbols) {
    // The real EU 1.09 image has its executable segment at vaddr 0.
    const auto text = MakeText();
    const SymbolSpec specs[] = {Spec("prologue", "55 48 89 E5"),
                                Spec("global", "48 8B 05 ?? ?? ?? ??", TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, 0, false}, specs);
    ASSERT_TRUE(r.failures.empty());
    EXPECT_EQ(r.rvas[0], 0x10u);
    EXPECT_EQ(r.rvas[1], 0x57u);
    EXPECT_EQ(r.ResolvedCount(), 2u);
}

TEST(ResolverTest, ResultOfRvaZeroIsAFailureNotASuccess) {
    auto text = MakeText();
    PutBytes(text, 0, {0xB1, 0xB2, 0xB3, 0xB4});
    // With text_rva 0, a match at text offset 0 and the call at 0x60 (rel32 -0x65) both give RVA 0.
    const SymbolSpec specs[] = {Spec("at_offset_zero", "B1 B2 B3 B4"),
                                Spec("call_to_zero", "E8 ?? ?? ?? ??", TargetMode::RelativeOperand),
                                Spec("ok", "55 48 89 E5")};
    const auto scan = ResolveSymbols({text, 0, false}, specs);
    ASSERT_EQ(scan.failures.size(), 2u);
    EXPECT_EQ(scan.failures[0].name, "at_offset_zero");
    EXPECT_EQ(scan.failures[0].error, ResolveError::ZeroRva);
    EXPECT_EQ(scan.failures[1].name, "call_to_zero");
    EXPECT_EQ(scan.failures[1].error, ResolveError::ZeroRva);
    EXPECT_TRUE(ContainsText(scan.failures[0].detail, "never a valid symbol"));
    EXPECT_FALSE(scan.AllRequiredResolved());
    EXPECT_EQ(scan.ResolvedCount(), 1u);
    EXPECT_FALSE(scan.Rva(0).has_value());
    EXPECT_FALSE(scan.Rva(1).has_value());
    ASSERT_TRUE(scan.Rva(2).has_value());
    EXPECT_EQ(*scan.Rva(2), 0x10u);

    // Reference mode: a table row that says target_rva == 0 is rejected too, even though it agrees.
    const SymbolSpec table[] = {Spec("row_says_zero", "B1 B2 B3 B4", TargetMode::Match, true, 0, 0)};
    const auto ref = ResolveSymbols({text, 0, true}, table);
    ASSERT_EQ(ref.failures.size(), 1u);
    EXPECT_EQ(ref.failures[0].error, ResolveError::ZeroRva);
    EXPECT_FALSE(ref.AllRequiredResolved());
    EXPECT_EQ(ref.ResolvedCount(), 0u);
    EXPECT_FALSE(ref.Rva(0).has_value());

    EXPECT_EQ(ToString(ResolveError::ZeroRva), "resolved to RVA 0");
}

TEST(ResolverTest, OptionalSymbolAtRvaZeroDoesNotBlock) {
    auto text = MakeText();
    PutBytes(text, 0, {0xB1, 0xB2});
    const SymbolSpec specs[] = {Spec("zero", "B1 B2", TargetMode::Match, false),
                                Spec("ok", "55 48 89 E5")};
    const auto r = ResolveSymbols({text, 0, false}, specs);
    ASSERT_EQ(r.failures.size(), 1u);
    EXPECT_EQ(r.failures[0].error, ResolveError::ZeroRva);
    EXPECT_FALSE(r.failures[0].required);
    EXPECT_TRUE(r.AllRequiredResolved());
    EXPECT_EQ(r.ResolvedCount(), 1u);
}

TEST(ResolverTest, BadOperandDetailNamesTheRealCause) {
    auto text = MakeText();
    PutBytes(text, 0xFD, {0xE8, 0x01, 0x02}); // call rel32 cut off by the end of the text
    PutBytes(text, 0xB0, {0x06});             // invalid in 64-bit mode, followed by 0xCC
    const SymbolSpec specs[] = {
        SpecAt("outside_above", "55 48 89 E5", 0x1000, TargetMode::RelativeOperand),
        SpecAt("outside_below", "55 48 89 E5", -0x1000, TargetMode::RelativeOperand),
        SpecAt("truncated", "E8 01 02", 0, TargetMode::RelativeOperand),
        SpecAt("undecodable", "06 CC", 0, TargetMode::RelativeOperand),
        SpecAt("no_operand", "55 48 89 E5", 0, TargetMode::RelativeOperand)};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 5u);
    for (const auto& f : r.failures) {
        EXPECT_EQ(f.error, ResolveError::BadOperand) << f.name;
        EXPECT_EQ(f.match_count, 1u) << f.name; // a unique match was found, the operand was bad
    }
    EXPECT_TRUE(ContainsText(r.failures[0].detail, "outside the text")) << r.failures[0].detail;
    EXPECT_TRUE(ContainsText(r.failures[1].detail, "outside the text")) << r.failures[1].detail;
    EXPECT_TRUE(ContainsText(r.failures[2].detail, "cut off")) << r.failures[2].detail;
    EXPECT_TRUE(ContainsText(r.failures[3].detail, "cannot decode")) << r.failures[3].detail;
    EXPECT_TRUE(ContainsText(r.failures[4].detail, "no RIP-relative operand"))
        << r.failures[4].detail;
    for (std::size_t i = 0; i < std::size(specs); ++i) {
        EXPECT_EQ(r.rvas[i], 0u);
        EXPECT_FALSE(r.Rva(i).has_value());
    }
}

TEST(ResolverTest, FailuresKeepIdentityAndNeverStoreAnRva) {
    const auto text = MakeText();
    const SymbolSpec scan_specs[] = {
        Spec("bad", "XX"),
        Spec("optional_operand", "55 48 89 E5", TargetMode::RelativeOperand, false)};
    const auto scan = ResolveSymbols({text, kTextRva, false}, scan_specs);
    ASSERT_EQ(scan.failures.size(), 2u);
    EXPECT_EQ(scan.failures[0].name, "bad");
    EXPECT_TRUE(scan.failures[0].required);
    EXPECT_EQ(scan.failures[0].error, ResolveError::BadPattern);
    EXPECT_FALSE(scan.failures[0].detail.empty());
    EXPECT_EQ(scan.failures[1].name, "optional_operand");
    EXPECT_FALSE(scan.failures[1].required);
    EXPECT_EQ(scan.failures[1].error, ResolveError::BadOperand);
    for (std::size_t i = 0; i < 2; ++i) {
        EXPECT_EQ(scan.rvas[i], 0u);
        EXPECT_FALSE(scan.Rva(i).has_value());
    }

    // Reference mode never runs a scan, so no failure reports a match count; a hint below the
    // text start or past its end is a mismatch, not an out-of-range read.
    const SymbolSpec ref_specs[] = {
        Spec("below_text", "55 48 89 E5", TargetMode::Match, true, 0x0FFF, 0x1010),
        Spec("past_text", "55 48 89 E5", TargetMode::Match, true, 0x1100, 0x1010),
        Spec("bad_target", "48 8B 05 ?? ?? ?? ??", TargetMode::RelativeOperand, true, 0x1040, 0x2000),
        Spec("no_operand", "55 48 89 E5", TargetMode::RelativeOperand, true, 0x1010, 0x1010)};
    const auto ref = ResolveSymbols({text, kTextRva, true}, ref_specs);
    ASSERT_EQ(ref.failures.size(), 4u);
    EXPECT_EQ(ref.failures[0].error, ResolveError::HintMismatch);
    EXPECT_EQ(ref.failures[1].error, ResolveError::HintMismatch);
    EXPECT_EQ(ref.failures[2].error, ResolveError::HintMismatch);
    EXPECT_EQ(ref.failures[3].error, ResolveError::BadOperand);
    for (std::size_t i = 0; i < ref.failures.size(); ++i) {
        EXPECT_EQ(ref.failures[i].match_count, 0u) << ref.failures[i].name;
        EXPECT_EQ(ref.rvas[i], 0u);
        EXPECT_FALSE(ref.Rva(i).has_value());
    }
}

TEST(ResolverTest, AmbiguousMatchCountIsCappedAtTwo) {
    const auto text = MakeText(); // far more than two "CC CC" matches
    const SymbolSpec specs[] = {Spec("many", "CC CC")};
    const auto r = ResolveSymbols({text, kTextRva, false}, specs);
    ASSERT_EQ(r.failures.size(), 1u);
    EXPECT_EQ(r.failures[0].error, ResolveError::Ambiguous);
    EXPECT_EQ(r.failures[0].match_count, 2u);
}
