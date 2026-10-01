// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <Zydis/Zydis.h>

#include "bbcoop/binding/relocator.h"

using namespace BBCoop::Binding;

namespace {
struct Decoded {
    ZydisMnemonic mnemonic;
    std::uint8_t length;
    std::uint64_t target;
};

/// Decodes the instruction at bytes[offset], which sits at `address`.
Decoded DecodeAt(const std::vector<std::uint8_t>& bytes, std::size_t offset,
                 std::uint64_t address) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    EXPECT_TRUE(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data() + offset,
                                                    bytes.size() - offset, &insn, ops)));
    ZyanU64 target = 0;
    for (std::uint8_t i = 0; i < insn.operand_count_visible; ++i) {
        const bool rip =
            ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP;
        const bool rel =
            ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative;
        if (rip || rel) ZydisCalcAbsoluteAddress(&insn, &ops[i], address, &target);
    }
    return {insn.mnemonic, insn.length, target};
}

Decoded DecodeFirst(const std::vector<std::uint8_t>& bytes, std::uint64_t address) {
    return DecodeAt(bytes, 0, address);
}

/// Decodes every instruction of bytes, the first one at `address`.
std::vector<Decoded> DecodeAll(const std::vector<std::uint8_t>& bytes, std::uint64_t address) {
    std::vector<Decoded> result;
    for (std::size_t offset = 0; offset < bytes.size();) {
        result.push_back(DecodeAt(bytes, offset, address + offset));
        offset += result.back().length;
    }
    return result;
}
} // namespace

TEST(RelocatorTest, CopiesPlainInstructionsVerbatim) {
    const std::vector<std::uint8_t> code{0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x01};
    const auto out = RelocateInstructions(code, 0x1000, 0x7FFF0000);
    ASSERT_TRUE(out.has_value()) << out.error();
    EXPECT_EQ(*out, code);
}

TEST(RelocatorTest, EmptyInputGivesEmptyOutput) {
    const auto out = RelocateInstructions({}, 0x1000, 0x2000);
    ASSERT_TRUE(out.has_value()) << out.error();
    EXPECT_TRUE(out->empty());
}

TEST(RelocatorTest, KeepsRipRelativeTarget) {
    const std::vector<std::uint8_t> code{0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}; // -> 0x1017
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto d = DecodeFirst(*out, 0x2000);
    EXPECT_EQ(d.mnemonic, ZYDIS_MNEMONIC_MOV);
    EXPECT_EQ(d.target, 0x1017u);
}

TEST(RelocatorTest, KeepsRipRelativeTargetOfVectorLoads) {
    struct Case {
        std::vector<std::uint8_t> code;
        ZydisMnemonic mnemonic;
    };
    const Case cases[] = {
        // movss xmm0, [rip+0x10]
        {{0xF3, 0x0F, 0x10, 0x05, 0x10, 0x00, 0x00, 0x00}, ZYDIS_MNEMONIC_MOVSS},
        // vmovaps xmm0, [rip+0x10]
        {{0xC5, 0xF8, 0x28, 0x05, 0x10, 0x00, 0x00, 0x00}, ZYDIS_MNEMONIC_VMOVAPS},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(ZydisMnemonicGetString(c.mnemonic));
        const auto out = RelocateInstructions(c.code, 0x1000, 0x2000);
        ASSERT_TRUE(out.has_value()) << out.error();
        const auto d = DecodeFirst(*out, 0x2000);
        EXPECT_EQ(d.mnemonic, c.mnemonic);
        EXPECT_EQ(d.length, out->size());
        EXPECT_EQ(d.target, 0x1018u);
    }
}

TEST(RelocatorTest, KeepsRipRelativeTargetBeforeTrailingImmediate) {
    // mov dword [rip+0x10], 0x12345678: the displacement is followed by a 4-byte immediate.
    const std::vector<std::uint8_t> code{0xC7, 0x05, 0x10, 0x00, 0x00, 0x00,
                                         0x78, 0x56, 0x34, 0x12};
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_TRUE(out.has_value()) << out.error();
    ASSERT_EQ(out->size(), code.size());
    EXPECT_EQ(DecodeFirst(*out, 0x2000).target, 0x101Au);
    EXPECT_EQ(std::vector<std::uint8_t>(out->end() - 4, out->end()),
              (std::vector<std::uint8_t>{0x78, 0x56, 0x34, 0x12}));
}

TEST(RelocatorTest, KeepsInstructionPrefixes) {
    // lock add dword [rip+0x10], 1: the lock prefix must survive the re-encode.
    const std::vector<std::uint8_t> locked{0xF0, 0x83, 0x05, 0x10, 0x00, 0x00, 0x00, 0x01};
    const auto out = RelocateInstructions(locked, 0x1000, 0x2000);
    ASSERT_TRUE(out.has_value()) << out.error();
    EXPECT_EQ(out->front(), 0xF0);
    EXPECT_EQ(DecodeFirst(*out, 0x2000).target, 0x1018u);

    // A branch-hint prefix on a widened jcc: cs: jz +0x10 -> 0x1013.
    const std::vector<std::uint8_t> hinted{0x2E, 0x74, 0x10};
    const auto widened = RelocateInstructions(hinted, 0x1000, 0x100000);
    ASSERT_TRUE(widened.has_value()) << widened.error();
    EXPECT_EQ(widened->front(), 0x2E);
    EXPECT_EQ(DecodeFirst(*widened, 0x100000).target, 0x1013u);
}

TEST(RelocatorTest, KeepsCallTarget) {
    const std::vector<std::uint8_t> code{0xE8, 0x00, 0x01, 0x00, 0x00}; // -> 0x1105
    const auto out = RelocateInstructions(code, 0x1000, 0x5000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto d = DecodeFirst(*out, 0x5000);
    EXPECT_EQ(d.mnemonic, ZYDIS_MNEMONIC_CALL);
    EXPECT_EQ(d.length, 5);
    EXPECT_EQ(d.target, 0x1105u);
}

TEST(RelocatorTest, KeepsIndirectBranchSlot) {
    struct Case {
        std::vector<std::uint8_t> code;
        ZydisMnemonic mnemonic;
    };
    const Case cases[] = {
        {{0xFF, 0x15, 0x10, 0x00, 0x00, 0x00}, ZYDIS_MNEMONIC_CALL}, // call [rip+0x10] -> 0x1016
        {{0xFF, 0x25, 0x10, 0x00, 0x00, 0x00}, ZYDIS_MNEMONIC_JMP},  // jmp [rip+0x10]  -> 0x1016
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(ZydisMnemonicGetString(c.mnemonic));
        const auto out = RelocateInstructions(c.code, 0x1000, 0x2000);
        ASSERT_TRUE(out.has_value()) << out.error();
        const auto d = DecodeFirst(*out, 0x2000);
        EXPECT_EQ(d.mnemonic, c.mnemonic);
        EXPECT_EQ(d.length, out->size());
        EXPECT_EQ(d.target, 0x1016u);
    }
}

TEST(RelocatorTest, RelocatesEachInstructionAtItsOwnOffset) {
    const std::vector<std::uint8_t> code{
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, // +0x0 mov rax, [rip+0x10] -> 0x1017
        0xE8, 0x00, 0x01, 0x00, 0x00,             // +0x7 call +0x100         -> 0x110C
        0x74, 0x10,                               // +0xC jz +0x10            -> 0x101E
    };
    const auto out = RelocateInstructions(code, 0x1000, 0x7000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto decoded = DecodeAll(*out, 0x7000);
    ASSERT_EQ(decoded.size(), 3u);
    EXPECT_EQ(decoded[0].mnemonic, ZYDIS_MNEMONIC_MOV);
    EXPECT_EQ(decoded[0].target, 0x1017u);
    EXPECT_EQ(decoded[1].mnemonic, ZYDIS_MNEMONIC_CALL);
    EXPECT_EQ(decoded[1].target, 0x110Cu);
    EXPECT_EQ(decoded[2].mnemonic, ZYDIS_MNEMONIC_JZ);
    EXPECT_EQ(decoded[2].target, 0x101Eu);
}

TEST(RelocatorTest, WidensShortConditionalJump) {
    const std::vector<std::uint8_t> code{0x74, 0x10}; // jz -> 0x1012
    const auto out = RelocateInstructions(code, 0x1000, 0x100000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto d = DecodeFirst(*out, 0x100000);
    EXPECT_EQ(d.mnemonic, ZYDIS_MNEMONIC_JZ);
    EXPECT_EQ(d.length, 6);
    EXPECT_EQ(d.target, 0x1012u);
}

TEST(RelocatorTest, WidensShortUnconditionalJump) {
    const std::vector<std::uint8_t> code{0xEB, 0x10}; // jmp -> 0x1012
    const auto out = RelocateInstructions(code, 0x1000, 0x100000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto d = DecodeFirst(*out, 0x100000);
    EXPECT_EQ(d.mnemonic, ZYDIS_MNEMONIC_JMP);
    EXPECT_EQ(d.length, 5);
    EXPECT_EQ(d.target, 0x1012u);
}

TEST(RelocatorTest, KeepsShortOnlyBranchWhenTargetIsInReach) {
    struct Case {
        std::vector<std::uint8_t> code;
        ZydisMnemonic mnemonic;
    };
    const Case cases[] = {
        {{0xE3, 0x10}, ZYDIS_MNEMONIC_JRCXZ}, // -> 0x1012
        {{0xE2, 0x10}, ZYDIS_MNEMONIC_LOOP},  // -> 0x1012
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(ZydisMnemonicGetString(c.mnemonic));
        const auto out = RelocateInstructions(c.code, 0x1000, 0x1020);
        ASSERT_TRUE(out.has_value()) << out.error();
        const auto d = DecodeFirst(*out, 0x1020);
        EXPECT_EQ(d.mnemonic, c.mnemonic);
        EXPECT_EQ(d.length, 2);
        EXPECT_EQ(d.target, 0x1012u);
    }
}

TEST(RelocatorTest, RejectsUnrelocatableShortOnlyBranch) {
    const std::vector<std::uint8_t> code{0xE3, 0x10}; // jrcxz
    EXPECT_FALSE(RelocateInstructions(code, 0x1000, 0x100000).has_value());
}

TEST(RelocatorTest, RejectsLoopOutOfReach) {
    const std::vector<std::uint8_t> code{0xE2, 0x10}; // loop
    EXPECT_FALSE(RelocateInstructions(code, 0x1000, 0x100000).has_value());
}

TEST(RelocatorTest, RejectsRipRelativeOperandOutOfReach) {
    const std::vector<std::uint8_t> code{0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00};
    const auto out = RelocateInstructions(code, 0x1000, 0x7FFF'0000'0000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("cannot re-encode"), std::string::npos);
}

TEST(RelocatorTest, RejectsFsSegmentAccess) {
    const std::vector<std::uint8_t> code{0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("FS"), std::string::npos);
}

TEST(RelocatorTest, RejectsGsSegmentAccess) {
    const std::vector<std::uint8_t> code{0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("GS"), std::string::npos);
}

TEST(RelocatorTest, RejectsSegmentAccessAfterPlainInstructions) {
    const std::vector<std::uint8_t> code{0x90, 0x64, 0x48, 0x8B, 0x04,
                                         0x25, 0x00, 0x00, 0x00, 0x00};
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("0x1001"), std::string::npos) << out.error();
}

TEST(RelocatorTest, RejectsSse4aInstructions) {
    struct Case {
        const char* name;
        std::vector<std::uint8_t> code;
    };
    const Case cases[] = {
        {"extrq xmm1, 4, 8", {0x66, 0x0F, 0x78, 0xC1, 0x04, 0x08}},
        {"insertq xmm0, xmm1", {0xF2, 0x0F, 0x79, 0xC1}},
        {"movntss [rbx], xmm0", {0xF3, 0x0F, 0x2B, 0x03}},
        {"movntsd [rbx], xmm0", {0xF2, 0x0F, 0x2B, 0x03}},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        const auto out = RelocateInstructions(c.code, 0x1000, 0x2000);
        ASSERT_FALSE(out.has_value());
        EXPECT_NE(out.error().find("SSE4a"), std::string::npos) << out.error();
    }
}

TEST(RelocatorTest, RejectsEipRelativeAddressing) {
    // mov eax, [eip+0x10]
    const std::vector<std::uint8_t> code{0x67, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00};
    const auto out = RelocateInstructions(code, 0x1000, 0x2000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("EIP"), std::string::npos) << out.error();
}

TEST(RelocatorTest, RejectsBranchIntoStolenBytes) {
    const std::vector<std::uint8_t> code{0xEB, 0x01, 0x90, 0x90, 0x90, 0x90};
    EXPECT_FALSE(RelocateInstructions(code, 0x1000, 0x2000).has_value());
}

TEST(RelocatorTest, AllowsBranchesToTheEdgesOfTheStolenRegion) {
    // The region is [0x1000, 0x1004). 0x1000: jmp +0x2 -> 0x1004 (the first byte after the region);
    // 0x1002: jmp -0x4 -> 0x1000 (the first byte of the region, where the hook's jump will sit).
    const std::vector<std::uint8_t> code{0xEB, 0x02, 0xEB, 0xFC};
    const auto out = RelocateInstructions(code, 0x1000, 0x100000);
    ASSERT_TRUE(out.has_value()) << out.error();
    const auto decoded = DecodeAll(*out, 0x100000);
    ASSERT_EQ(decoded.size(), 2u);
    EXPECT_EQ(decoded[0].target, 0x1004u);
    EXPECT_EQ(decoded[1].target, 0x1000u);
}

TEST(RelocatorTest, RejectsUndecodableBytes) {
    const std::vector<std::uint8_t> cut_off{0x90, 0x48, 0x8B};
    const auto out = RelocateInstructions(cut_off, 0x1000, 0x2000);
    ASSERT_FALSE(out.has_value());
    EXPECT_NE(out.error().find("+0x1"), std::string::npos) << out.error();
}

TEST(RelocatorTest, StealLengthCoversWholeInstructions) {
    const std::vector<std::uint8_t> code{0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x01, 0xC3};
    EXPECT_EQ(StealLength(code, 5).value(), 7u);
    EXPECT_FALSE(StealLength(std::vector<std::uint8_t>{0x48, 0x8B, 0x05, 0x10}, 5).has_value());
}

TEST(RelocatorTest, StealLengthStopsAtTheFirstSufficientInstructionBoundary) {
    const std::vector<std::uint8_t> code{0x48, 0x89, 0xC8, 0x48, 0x83, 0xC0, 0x01, 0xC3};
    EXPECT_EQ(StealLength(code, 0).value(), 0u);
    EXPECT_EQ(StealLength(code, 1).value(), 3u);
    EXPECT_EQ(StealLength(code, 3).value(), 3u); // exactly one instruction
    EXPECT_EQ(StealLength(code, 4).value(), 7u);
    EXPECT_EQ(StealLength(code, 8).value(), 8u);
    EXPECT_FALSE(StealLength(code, 9).has_value()); // the code ends before 9 bytes are covered
}

TEST(RelocatorTest, StealLengthDoesNotKnowFunctionBounds) {
    // A one-byte function (ret) followed by the next function: StealLength steps over the ret.
    const std::vector<std::uint8_t> code{0xC3, 0x90, 0x90, 0x90, 0x90};
    EXPECT_EQ(StealLength(code, 5).value(), 5u);
}

TEST(RelocatorTest, StealLengthReportsUndecodableBytes) {
    const std::vector<std::uint8_t> code{0x90, 0x0F};
    const auto length = StealLength(code, 5);
    ASSERT_FALSE(length.has_value());
    EXPECT_NE(length.error().find("+0x1"), std::string::npos) << length.error();
}
