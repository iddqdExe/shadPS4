// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/symbols.h"

#include <cstddef>
#include <iterator>

namespace BBCoop::Binding {

namespace {
constexpr SymbolSpec kSymbols[] = {
#define BBCOOP_SYMBOL(name, kind, required, target, match, offset, mode, pattern)                  \
    SymbolSpec{#name, SymbolKind::kind, required, target, match, offset, TargetMode::mode, pattern},
#include "bbcoop/binding/data/eu109_symbols.inc"
#undef BBCOOP_SYMBOL
};
static_assert(std::size(kSymbols) == static_cast<std::size_t>(SymbolId::Count));

constexpr PatchSpec kPatches[] = {
#define BBCOOP_PATCH(name, group, anchor, original, replacement, position_dependent)               \
    PatchSpec{#name, group, anchor, original, replacement, position_dependent},
#include "bbcoop/binding/data/eu109_patches.inc"
#undef BBCOOP_PATCH
};

constexpr ImageInfo kImage =
#define BBCOOP_IMAGE(fingerprint, text_rva, text_size) ImageInfo{fingerprint, text_rva, text_size};
#include "bbcoop/binding/data/eu109_image.inc"
#undef BBCOOP_IMAGE
} // namespace

std::span<const SymbolSpec> Eu109Symbols() {
    return kSymbols;
}

ImageInfo Eu109Image() {
    return kImage;
}

std::span<const PatchSpec> Eu109Patches() {
    return kPatches;
}

std::string_view SymbolName(SymbolId id) {
    const auto index = static_cast<std::size_t>(id);
    return index < std::size(kSymbols) ? kSymbols[index].name : std::string_view{};
}

std::optional<SymbolId> FindSymbol(std::string_view name) {
    for (std::size_t i = 0; i < std::size(kSymbols); ++i) {
        if (kSymbols[i].name == name) {
            return static_cast<SymbolId>(i);
        }
    }
    return std::nullopt;
}

} // namespace BBCoop::Binding
