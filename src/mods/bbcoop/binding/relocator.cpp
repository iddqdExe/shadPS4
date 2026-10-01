// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/relocator.h"

#include <format>
#include <optional>
#include <string_view>

#include <Zydis/Zydis.h>

namespace BBCoop::Binding {

namespace {
ZydisDecoder MakeDecoder() {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    return decoder;
}

bool IsRipRelativeMemory(const ZydisDecodedOperand& op) {
    return op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP;
}

bool IsRelativeImmediate(const ZydisDecodedOperand& op) {
    return op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative;
}

/// Why the instruction cannot be moved into a trampoline; nullopt when it can.
std::optional<std::string_view> UnrelocatableReason(const ZydisDecodedInstruction& insn,
                                                    const ZydisDecodedOperand* ops) {
    // The emulator rewrites these in place, lazily; a trampoline copy would never be rewritten.
    switch (insn.mnemonic) {
    case ZYDIS_MNEMONIC_EXTRQ:
    case ZYDIS_MNEMONIC_INSERTQ:
    case ZYDIS_MNEMONIC_MOVNTSS:
    case ZYDIS_MNEMONIC_MOVNTSD:
        return "SSE4a instruction is patched lazily by the emulator";
    default:
        break;
    }
    for (std::uint8_t i = 0; i < insn.operand_count_visible; ++i) {
        if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY) {
            continue;
        }
        if (ops[i].mem.segment == ZYDIS_REGISTER_FS || ops[i].mem.segment == ZYDIS_REGISTER_GS) {
            return "FS/GS segment access is patched lazily by the emulator";
        }
        // Zydis reports the 0x67 form of RIP-relative addressing with an EIP base. Its result is
        // truncated to 32 bits, which a copy at another address cannot reproduce.
        if (ops[i].mem.base == ZYDIS_REGISTER_EIP) {
            return "EIP-relative addressing cannot be relocated";
        }
    }
    return std::nullopt;
}
} // namespace

std::expected<std::size_t, std::string> StealLength(std::span<const std::uint8_t> code,
                                                    std::size_t min_bytes) {
    const auto decoder = MakeDecoder();
    std::size_t length = 0;
    while (length < min_bytes) {
        ZydisDecodedInstruction insn;
        if (length >= code.size() ||
            !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, code.data() + length,
                                                        code.size() - length, &insn))) {
            return std::unexpected(
                std::format("cannot decode a whole instruction at +{:#x}", length));
        }
        length += insn.length;
    }
    return length;
}

std::expected<std::vector<std::uint8_t>, std::string> RelocateInstructions(
    std::span<const std::uint8_t> code, std::uint64_t source, std::uint64_t target) {
    const auto decoder = MakeDecoder();
    std::vector<std::uint8_t> out;
    std::size_t offset = 0;
    while (offset < code.size()) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        const auto rest = code.subspan(offset);
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, rest.data(), rest.size(), &insn, ops))) {
            return std::unexpected(std::format("cannot decode instruction at +{:#x}", offset));
        }
        const std::uint64_t src = source + offset;
        if (const auto why = UnrelocatableReason(insn, ops)) {
            return std::unexpected(std::format("instruction at {:#x}: {}", src, *why));
        }
        bool relative = false;
        for (std::uint8_t i = 0; i < insn.operand_count_visible; ++i) {
            relative |= IsRipRelativeMemory(ops[i]) || IsRelativeImmediate(ops[i]);
        }
        if (!relative) {
            out.insert(out.end(), code.begin() + offset, code.begin() + offset + insn.length);
            offset += insn.length;
            continue;
        }
        ZydisEncoderRequest request;
        if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
                &insn, ops, insn.operand_count_visible, &request))) {
            return std::unexpected(std::format("cannot build an encoder request for {:#x}", src));
        }
        for (std::uint8_t i = 0; i < insn.operand_count_visible; ++i) {
            const bool rip = IsRipRelativeMemory(ops[i]);
            const bool rel = IsRelativeImmediate(ops[i]);
            if (!rip && !rel) {
                continue;
            }
            ZyanU64 absolute = 0;
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[i], src, &absolute))) {
                return std::unexpected(
                    std::format("cannot compute target of instruction at {:#x}", src));
            }
            // A target inside the region is overwritten by the hook's jump. The region's first byte
            // is the jump itself and its end is the first byte after it; both stay valid.
            if (rel && absolute > source && absolute < source + code.size()) {
                return std::unexpected(
                    std::format("branch at {:#x} targets the stolen bytes", src));
            }
            if (rip) {
                request.operands[i].mem.displacement = static_cast<ZyanI64>(absolute);
            } else {
                request.operands[i].imm.u = absolute;
            }
        }
        if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
            // Let the encoder pick the width for the new distance (short only when it reaches).
            request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
            request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
        }
        ZyanU8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize length = sizeof(buffer);
        const std::uint64_t destination = target + out.size();
        if (!ZYAN_SUCCESS(
                ZydisEncoderEncodeInstructionAbsolute(&request, buffer, &length, destination))) {
            return std::unexpected(
                std::format("cannot re-encode instruction at {:#x} for {:#x}", src, destination));
        }
        out.insert(out.end(), buffer, buffer + length);
        offset += insn.length;
    }
    return out;
}

} // namespace BBCoop::Binding
