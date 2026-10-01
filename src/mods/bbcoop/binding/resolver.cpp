// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/resolver.h"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <format>
#include <string>
#include <utility>

#include <Zydis/Zydis.h>
#define XXH_INLINE_ALL
#include <xxhash.h>

#include "bbcoop/binding/signature.h"

namespace BBCoop::Binding {

namespace {
bool InText(const ImageView& image, std::uint64_t rva) {
    return rva >= image.text_rva && rva - image.text_rva < image.text.size();
}

std::string TextRangeString(const ImageView& image) {
    return std::format("[{:#x}, {:#x})", image.text_rva, image.text_rva + image.text.size());
}

/// Absolute target of the first [rip+disp] or relative-immediate operand of the instruction at
/// insn_rva; on failure the error string names the real cause (it becomes ResolveFailure::detail).
std::expected<std::uint64_t, std::string> RelativeOperandTarget(const ImageView& image,
                                                                std::uint64_t insn_rva) {
    if (!InText(image, insn_rva)) {
        return std::unexpected(std::format("instruction address {:#x} is outside the text {}",
                                           insn_rva, TextRangeString(image)));
    }
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    const auto offset = insn_rva - image.text_rva;
    const ZyanStatus status = ZydisDecoderDecodeFull(
        &decoder, image.text.data() + offset, image.text.size() - offset, &insn, ops);
    if (!ZYAN_SUCCESS(status)) {
        return std::unexpected(
            status == ZYDIS_STATUS_NO_MORE_DATA
                ? std::format("instruction at {:#x} is cut off by the end of the text", insn_rva)
                : std::format("cannot decode an instruction at {:#x}", insn_rva));
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
    return std::unexpected(std::format("instruction at {:#x} has no RIP-relative operand", insn_rva));
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
    case ResolveError::OutOfText:
        return "target outside the text";
    case ResolveError::ZeroRva:
        return "resolved to RVA 0";
    }
    return "unknown";
}

bool ResolveResult::AllRequiredResolved() const {
    return std::none_of(failures.begin(), failures.end(),
                        [](const ResolveFailure& f) { return f.required; });
}

std::size_t ResolveResult::ResolvedCount() const {
    // Same predicate as Rva(): a stored 0 is "unresolved".
    return static_cast<std::size_t>(
        std::count_if(rvas.begin(), rvas.end(), [](std::uint64_t rva) { return rva != 0; }));
}

ResolveResult ResolveSymbols(const ImageView& image, std::span<const SymbolSpec> specs) {
    ResolveResult result;
    result.rvas.assign(specs.size(), 0);
    for (std::size_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];
        std::size_t match_count = 0; // Matches the scan saw; stays 0 in reference mode (no scan).
        const auto fail = [&](ResolveError error, std::string detail) {
            result.failures.push_back(
                {spec.name, spec.required, error, match_count, std::move(detail)});
        };
        const auto sig = Signature::Parse(spec.pattern);
        if (!sig) {
            fail(ResolveError::BadPattern, sig.error());
            continue;
        }
        std::uint64_t match_rva = 0;
        if (image.is_reference_image) {
            if (spec.match_rva < image.text_rva ||
                !sig->MatchesAt(image.text, spec.match_rva - image.text_rva)) {
                fail(ResolveError::HintMismatch,
                     std::format("pattern does not match at {:#x}", spec.match_rva));
                continue;
            }
            match_rva = spec.match_rva;
        } else {
            const auto matches = sig->FindAll(image.text, 2);
            match_count = matches.size();
            if (matches.empty()) {
                fail(ResolveError::NotFound, {});
                continue;
            }
            if (matches.size() > 1) {
                fail(ResolveError::Ambiguous,
                     std::format("matches at {:#x} and {:#x}", image.text_rva + matches[0],
                                 image.text_rva + matches[1]));
                continue;
            }
            match_rva = image.text_rva + matches[0];
        }
        // Unsigned wrap-around is intended: a negative operand_offset below the text start gives
        // a huge value that the range checks below reject.
        const std::uint64_t at =
            match_rva + static_cast<std::uint64_t>(static_cast<std::int64_t>(spec.operand_offset));
        std::uint64_t target = at;
        if (spec.mode == TargetMode::RelativeOperand) {
            const auto t = RelativeOperandTarget(image, at);
            if (!t) {
                fail(ResolveError::BadOperand, t.error());
                continue;
            }
            target = *t;
        }
        if (image.is_reference_image && target != spec.target_rva) {
            fail(ResolveError::HintMismatch,
                 std::format("resolved {:#x}, table says {:#x}", target, spec.target_rva));
            continue;
        }
        // A Match target is a position in the text; a RelativeOperand target may legitimately lie
        // outside it (globals and data).
        if (spec.mode == TargetMode::Match && !InText(image, target)) {
            fail(ResolveError::OutOfText,
                 std::format("target {:#x} is outside the text {}", target, TextRangeString(image)));
            continue;
        }
        // RVA 0 is the "unresolved" sentinel (see ResolveResult::rvas), so it cannot be a result.
        if (target == 0) {
            fail(ResolveError::ZeroRva, "resolved to RVA 0, which is never a valid symbol");
            continue;
        }
        result.rvas[i] = target;
    }
    return result;
}

} // namespace BBCoop::Binding
