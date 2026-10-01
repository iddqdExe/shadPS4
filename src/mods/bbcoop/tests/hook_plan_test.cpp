// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "bbcoop/binding/hook_plan.h"
#include "bbcoop/binding/patch_table.h"
#include "bbcoop/binding/resolver.h"

using namespace BBCoop::Binding;

namespace {
constexpr std::uint64_t kTextRva = 0x1000;

// Symbol indices of the synthetic image below.
enum Sym : std::size_t {
    FEntry,     // 0x20 push rbp; mov rbp,rsp; sub rsp,0x20 (8 bytes stolen)
    MidSite,    // 0x40 add rsp,0x7E8 (7 bytes stolen); pop rbx; ret
    RetOnly,    // 0x60 ret, then the next function
    TailCall,   // 0x80 jmp rel32 (5 bytes stolen, ends with a transfer)
    NopA,       // 0xA0 nops
    NopB,       // 0xA3 nops, inside NopA's stolen bytes
    NopC,       // 0xA5 nops, right after NopA's stolen bytes
    Glob,       // 0xC0, a Global
    Unresolved, // rva 0
    Outside,    // past the end of the text
    AtEnd,      // 2 bytes before the end of the text
    kCount
};

SymbolSpec Spec(std::string_view name, SymbolKind kind) {
    return {name, kind, false, 0, 0, 0, TargetMode::Match, ""};
}

void Put(std::vector<std::uint8_t>& text, std::size_t at, std::initializer_list<std::uint8_t> b) {
    std::memcpy(text.data() + at, b.begin(), b.size());
}

class HookPlanTest : public ::testing::Test {
protected:
    HookPlanTest() : pristine(0x100, 0x90) {
        Put(pristine, 0x20, {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20});
        Put(pristine, 0x40, {0x48, 0x81, 0xC4, 0xE8, 0x07, 0x00, 0x00, 0x5B, 0xC3});
        Put(pristine, 0x60, {0xC3});
        Put(pristine, 0x80, {0xE9, 0x00, 0x00, 0x00, 0x00});
        live = pristine;
        symbols = {
            Spec("f_entry", SymbolKind::Function),    Spec("mid_site", SymbolKind::Site),
            Spec("ret_only", SymbolKind::Function),   Spec("tail_call", SymbolKind::Function),
            Spec("nop_a", SymbolKind::Site),          Spec("nop_b", SymbolKind::Site),
            Spec("nop_c", SymbolKind::Site),          Spec("glob", SymbolKind::Global),
            Spec("unresolved", SymbolKind::Function), Spec("outside", SymbolKind::Function),
            Spec("at_end", SymbolKind::Site)};
        resolved.rvas = {kTextRva + 0x20,  kTextRva + 0x40, kTextRva + 0x60,
                         kTextRva + 0x80,  kTextRva + 0xA0, kTextRva + 0xA3,
                         kTextRva + 0xA5,  kTextRva + 0xC0, 0,
                         kTextRva + 0x110, kTextRva + 0xFE};
    }

    std::expected<std::vector<PlannedHook>, std::string> Plan(
        std::initializer_list<HookRequest> requests) {
        const std::vector<HookRequest> list(requests);
        return PlanHooks({list, symbols, resolved, pristine, live, kTextRva});
    }

    std::vector<std::uint8_t> pristine;
    std::vector<std::uint8_t> live;
    std::vector<SymbolSpec> symbols;
    ResolveResult resolved;
};

/// The error of a plan that must fail, or a test failure.
std::string ErrorOf(const std::expected<std::vector<PlannedHook>, std::string>& plan) {
    EXPECT_FALSE(plan.has_value());
    return plan.has_value() ? std::string{} : plan.error();
}
} // namespace

TEST_F(HookPlanTest, PlansEveryHookInRequestOrder) {
    const auto plan = Plan({{FEntry, HookSiteKind::FunctionEntry, "a"},
                            {MidSite, HookSiteKind::Mid, "b"},
                            {TailCall, HookSiteKind::FunctionEntry, "c"},
                            {NopA, HookSiteKind::Mid, "d"}});
    ASSERT_TRUE(plan.has_value()) << plan.error();
    ASSERT_EQ(plan->size(), 4u);
    const std::size_t expected_steal[] = {8, 7, 5, 5};
    const std::uint64_t expected_rva[] = {0x20, 0x40, 0x80, 0xA0};
    for (std::size_t i = 0; i < 4; ++i) {
        const auto& hook = (*plan)[i];
        EXPECT_EQ(hook.request, i);
        EXPECT_EQ(hook.rva, kTextRva + expected_rva[i]);
        ASSERT_EQ(hook.stolen.size(), expected_steal[i]);
        EXPECT_EQ(hook.stolen.data(), pristine.data() + expected_rva[i])
            << "not the pristine bytes";
    }
    EXPECT_FALSE((*plan)[0].ends_with_transfer);
    EXPECT_FALSE((*plan)[1].ends_with_transfer);
    EXPECT_TRUE((*plan)[2].ends_with_transfer) << "the tail call's jmp ends the stolen bytes";
}

TEST_F(HookPlanTest, NoRequestsPlanNothing) {
    const auto plan = Plan({});
    ASSERT_TRUE(plan.has_value()) << plan.error();
    EXPECT_TRUE(plan->empty());
}

TEST_F(HookPlanTest, RefusesAnUnresolvedSite) {
    EXPECT_EQ(ErrorOf(Plan({{Unresolved, HookSiteKind::FunctionEntry, "a"}})),
              "hook unresolved: site symbol is not resolved");
}

TEST_F(HookPlanTest, RefusesASymbolIndexOutOfRange) {
    EXPECT_NE(ErrorOf(Plan({{kCount, HookSiteKind::Mid, "a"}})).find("out of range"),
              std::string::npos);
}

TEST_F(HookPlanTest, RefusesASiteOutsideTheText) {
    EXPECT_EQ(ErrorOf(Plan({{Outside, HookSiteKind::FunctionEntry, "a"}})),
              "hook outside: site 0x1110 is outside the text segment");
}

TEST_F(HookPlanTest, RefusesAHookKindThatDoesNotFitTheSymbol) {
    EXPECT_EQ(ErrorOf(Plan({{MidSite, HookSiteKind::FunctionEntry, "a"}})),
              "hook mid_site: a FunctionEntry hook cannot go on a Site symbol");
    EXPECT_EQ(ErrorOf(Plan({{Glob, HookSiteKind::Mid, "a"}})),
              "hook glob: a Mid hook cannot go on a Global symbol");
    EXPECT_EQ(ErrorOf(Plan({{Glob, HookSiteKind::FunctionEntry, "a"}})),
              "hook glob: a FunctionEntry hook cannot go on a Global symbol");
    // A Mid hook may sit on a function's first instruction.
    const auto plan = Plan({{FEntry, HookSiteKind::Mid, "a"}});
    EXPECT_TRUE(plan.has_value()) << plan.error();
}

TEST_F(HookPlanTest, RefusesAFunctionThatEndsInsideTheStolenBytes) {
    const auto error = ErrorOf(Plan({{RetOnly, HookSiteKind::FunctionEntry, "a"}}));
    EXPECT_NE(error.find("hook ret_only: the code at 0x1060 ends at +0x0"), std::string::npos)
        << error;
}

TEST_F(HookPlanTest, RefusesASiteWhoseInstructionsRunPastTheText) {
    const auto error = ErrorOf(Plan({{AtEnd, HookSiteKind::Mid, "a"}}));
    EXPECT_NE(error.find("hook at_end: cannot decode"), std::string::npos) << error;
}

TEST_F(HookPlanTest, RefusesOverlappingHooks) {
    EXPECT_EQ(ErrorOf(Plan({{NopA, HookSiteKind::Mid, "a"}, {NopB, HookSiteKind::Mid, "b"}})),
              "hook nop_b overlaps hook nop_a (owners 'b' and 'a')");
    EXPECT_EQ(ErrorOf(Plan({{NopB, HookSiteKind::Mid, "b"}, {NopA, HookSiteKind::Mid, "a"}})),
              "hook nop_a overlaps hook nop_b (owners 'a' and 'b')");
    // Two hooks on the same site are not an overlap any more (0B-R52): see
    // TwoHandlersOnOneSiteShareOneDetour.
}

TEST_F(HookPlanTest, TwoHandlersOnOneSiteShareOneDetour) {
    const auto plan = Plan({{MidSite, HookSiteKind::Mid, "a"},
                            {FEntry, HookSiteKind::FunctionEntry, "x"},
                            {MidSite, HookSiteKind::Mid, "b"}});
    ASSERT_TRUE(plan.has_value()) << plan.error();
    ASSERT_EQ(plan->size(), 2u) << "one planned detour per site";
    EXPECT_EQ((*plan)[0].request, 0u);
    EXPECT_EQ((*plan)[0].rva, kTextRva + 0x40);
    EXPECT_EQ((*plan)[0].stolen.size(), 7u);
    EXPECT_EQ((*plan)[0].requests, (std::vector<std::size_t>{0, 2})) << "registration order";
    EXPECT_EQ((*plan)[1].request, 1u);
    EXPECT_EQ((*plan)[1].requests, (std::vector<std::size_t>{1}));
}

TEST_F(HookPlanTest, TwoSymbolsAtOneAddressShareOneDetour) {
    // A Function row and a Site row can name the same instruction.
    symbols.push_back(Spec("mid_alias", SymbolKind::Function));
    resolved.rvas.push_back(kTextRva + 0x40);
    const auto plan = Plan({{MidSite, HookSiteKind::Mid, "a"}, {kCount, HookSiteKind::Mid, "b"}});
    ASSERT_TRUE(plan.has_value()) << plan.error();
    ASSERT_EQ(plan->size(), 1u);
    EXPECT_EQ((*plan)[0].requests, (std::vector<std::size_t>{0, 1}));
}

TEST_F(HookPlanTest, RefusesHooksOfDifferentKindsOnOneSite) {
    EXPECT_EQ(ErrorOf(Plan(
                  {{FEntry, HookSiteKind::FunctionEntry, "a"}, {FEntry, HookSiteKind::Mid, "b"}})),
              "hook f_entry ('b'): a Mid hook cannot share the site at 0x1020 with the "
              "FunctionEntry hook of 'a' (f_entry)");
    EXPECT_EQ(ErrorOf(Plan({{FEntry, HookSiteKind::Mid, "a"},
                            {MidSite, HookSiteKind::Mid, "c"},
                            {FEntry, HookSiteKind::FunctionEntry, "b"}})),
              "hook f_entry ('b'): a FunctionEntry hook cannot share the site at 0x1020 with the "
              "Mid hook of 'a' (f_entry)");
}

TEST_F(HookPlanTest, AcceptsHooksThatOnlyTouch) {
    const auto plan = Plan({{NopA, HookSiteKind::Mid, "a"}, {NopC, HookSiteKind::Mid, "c"}});
    ASSERT_TRUE(plan.has_value()) << plan.error();
    EXPECT_EQ(plan->size(), 2u);
}

TEST_F(HookPlanTest, RefusesLiveChangesInTheStolenBytes) {
    live[0x43] ^= 0xFF;
    EXPECT_EQ(ErrorOf(Plan({{MidSite, HookSiteKind::Mid, "a"}})),
              "hook mid_site: code around 0x1040 was modified by another patcher (an XML patch, "
              "the emulator or a BB Co-op byte patch)");
}

TEST_F(HookPlanTest, ChecksExactlySixteenBytesAroundTheStolenOnes) {
    // mid_site steals [0x40, 0x47): the checked range is [0x30, 0x57).
    for (const std::size_t at : {0x30, 0x56}) {
        live = pristine;
        live[at] ^= 0xFF;
        EXPECT_FALSE(Plan({{MidSite, HookSiteKind::Mid, "a"}}).has_value()) << "byte " << at;
    }
    for (const std::size_t at : {0x2F, 0x57}) {
        live = pristine;
        live[at] ^= 0xFF;
        const auto plan = Plan({{MidSite, HookSiteKind::Mid, "a"}});
        EXPECT_TRUE(plan.has_value()) << "byte " << at << ": " << plan.error();
    }
}

TEST_F(HookPlanTest, RefusesAHookNextToOurOwnBytePatchUntilItIsReverted) {
    // The runtime applies the byte patches first, then plans the hooks against the live text.
    const std::vector<PatchOp> ops{{"next_to_hook", kTextRva + 0x48, {0xC3}, {0x90}}};
    const MemoryWriter write = [this](std::uint64_t rva, std::span<const std::uint8_t> bytes) {
        std::memcpy(live.data() + (rva - kTextRva), bytes.data(), bytes.size());
    };
    ApplyPatches(ops, write);
    EXPECT_NE(
        ErrorOf(Plan({{MidSite, HookSiteKind::Mid, "a"}})).find("modified by another patcher"),
        std::string::npos);
    RevertPatches(ops, write);
    const auto plan = Plan({{MidSite, HookSiteKind::Mid, "a"}});
    EXPECT_TRUE(plan.has_value()) << plan.error();
}

TEST_F(HookPlanTest, OneBadRequestFailsTheWholePlan) {
    EXPECT_FALSE(Plan({{FEntry, HookSiteKind::FunctionEntry, "a"},
                       {MidSite, HookSiteKind::Mid, "b"},
                       {Unresolved, HookSiteKind::FunctionEntry, "c"}})
                     .has_value());
}

TEST_F(HookPlanTest, RefusesTextsOfDifferentSizes) {
    live.pop_back();
    EXPECT_FALSE(Plan({}).has_value());
}

TEST(HookPlanNamesTest, KindsHaveNames) {
    EXPECT_EQ(ToString(HookSiteKind::FunctionEntry), "FunctionEntry");
    EXPECT_EQ(ToString(HookSiteKind::Mid), "Mid");
    EXPECT_EQ(ToString(SymbolKind::Function), "Function");
    EXPECT_EQ(ToString(SymbolKind::Site), "Site");
    EXPECT_EQ(ToString(SymbolKind::Global), "Global");
    EXPECT_EQ(ToString(SymbolKind::Data), "Data");
    EXPECT_EQ(ToString(SymbolKind::Patch), "Patch");
}
