// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/resolver.h"

#include <algorithm>
#include <format>
#include <optional>

#include <Zydis/Zydis.h>
#define XXH_INLINE_ALL
#include <xxhash.h>

#include "bbcoop/binding/signature.h"

namespace BBCoop::Binding {

namespace {
std::optional<std::uint64_t> RelativeOperandTarget(std::span<const std::uint8_t> text,
                                                   std::uint64_t text_rva, std::uint64_t insn_rva) {
    if (insn_rva < text_rva || insn_rva - text_rva >= text.size()) {
        return std::nullopt;
    }
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    const auto offset = insn_rva - text_rva;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, text.data() + offset, text.size() - offset,
                                             &insn, ops))) {
        return std::nullopt;
    }
    for (std::uint8_t i = 0; i < insn.operand_count_visible; ++i) {
        const auto& op = ops[i];
        const bool rip_memory = op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP;
        const bool relative = op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative;
        ZyanU64 target = 0;
        if ((rip_memory || relative) &&
            ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, insn_rva, &target))) {
            return target;
        }
    }
    return std::nullopt;
}
} // namespace

std::uint64_t Fingerprint(std::span<const std::uint8_t> text) {
    return XXH3_64bits(text.data(), text.size());
}

std::string_view ToString(ResolveError error) {
    switch (error) {
    case ResolveError::BadPattern:
        return "bad pattern";
    case ResolveError::NotFound:
        return "not found";
    case ResolveError::Ambiguous:
        return "ambiguous";
    case ResolveError::HintMismatch:
        return "hint mismatch";
    case ResolveError::BadOperand:
        return "no relative operand";
    }
    return "unknown";
}

bool ResolveResult::AllRequiredResolved() const {
    return std::none_of(failures.begin(), failures.end(),
                        [](const ResolveFailure& f) { return f.required; });
}

std::size_t ResolveResult::ResolvedCount() const {
    return rvas.size() - failures.size();
}

ResolveResult ResolveSymbols(const ImageView& image, std::span<const SymbolSpec> specs) {
    ResolveResult result;
    result.rvas.assign(specs.size(), 0);
    for (std::size_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];
        const auto fail = [&](ResolveError error, std::size_t count, std::string detail) {
            result.failures.push_back({spec.name, spec.required, error, count, std::move(detail)});
        };
        const auto sig = Signature::Parse(spec.pattern);
        if (!sig) {
            fail(ResolveError::BadPattern, 0, sig.error());
            continue;
        }
        std::uint64_t match_rva = 0;
        if (image.is_reference_image) {
            if (spec.match_rva < image.text_rva ||
                !sig->MatchesAt(image.text, spec.match_rva - image.text_rva)) {
                fail(ResolveError::HintMismatch, 0,
                     std::format("pattern does not match at {:#x}", spec.match_rva));
                continue;
            }
            match_rva = spec.match_rva;
        } else {
            const auto matches = sig->FindAll(image.text, 2);
            if (matches.empty()) {
                fail(ResolveError::NotFound, 0, {});
                continue;
            }
            if (matches.size() > 1) {
                fail(ResolveError::Ambiguous, matches.size(),
                     std::format("matches at {:#x} and {:#x}", image.text_rva + matches[0],
                                 image.text_rva + matches[1]));
                continue;
            }
            match_rva = image.text_rva + matches[0];
        }
        const std::uint64_t at = match_rva + static_cast<std::int64_t>(spec.operand_offset);
        std::uint64_t target = at;
        if (spec.mode == TargetMode::RelativeOperand) {
            const auto t = RelativeOperandTarget(image.text, image.text_rva, at);
            if (!t) {
                fail(ResolveError::BadOperand, 1, std::format("no RIP-relative operand at {:#x}", at));
                continue;
            }
            target = *t;
        }
        if (image.is_reference_image && target != spec.target_rva) {
            fail(ResolveError::HintMismatch, 1,
                 std::format("resolved {:#x}, table says {:#x}", target, spec.target_rva));
            continue;
        }
        result.rvas[i] = target;
    }
    return result;
}

} // namespace BBCoop::Binding
