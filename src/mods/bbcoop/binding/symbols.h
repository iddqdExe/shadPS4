// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "bbcoop/binding/patch_table.h"
#include "bbcoop/binding/resolver.h"

namespace BBCoop::Binding {

/// One id per row of the generated EU 1.09 symbol table (binding/data/eu109_symbols.inc, written by
/// tools/re/sigmaker from docs/re/eu109-symbols.tsv); the value is the index into Eu109Symbols().
enum class SymbolId : std::uint16_t {
#define BBCOOP_SYMBOL(name, kind, required, target, match, offset, mode, pattern) name,
#include "bbcoop/binding/data/eu109_symbols.inc"
#undef BBCOOP_SYMBOL
    Count
};

/// The executable segment of the reference image (EU 1.09): XXH3-64 of its file bytes, its RVA
/// and its file size.
struct ImageInfo {
    std::uint64_t fingerprint;
    std::uint64_t text_rva;
    std::uint64_t text_size;
};

std::span<const SymbolSpec> Eu109Symbols();
ImageInfo Eu109Image();
std::span<const PatchSpec> Eu109Patches();
/// Empty for an id outside the table (for example SymbolId::Count).
std::string_view SymbolName(SymbolId id);
/// nullopt when no symbol has this name.
std::optional<SymbolId> FindSymbol(std::string_view name);

} // namespace BBCoop::Binding
