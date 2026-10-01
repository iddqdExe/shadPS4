// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "bbcoop/binding/symbols.h"

namespace BBCoop::Runtime {

/// Called by the module loader for each executable segment right after its bytes are loaded and
/// before the emulator or the user's XML patches change them. For eboot.bin of CUSA03173 version
/// 01.09 with the mod enabled it keeps a copy of the segment: the pristine text. Another version
/// is refused here ("BB Co-op disabled: unsupported game version"), before the copy is made.
void OnExecutableSegmentLoaded(std::string_view module_name, std::uint64_t segment_addr,
                               std::uint64_t size);

/// Called once eboot.bin is loaded and the XML patches are applied, before any guest code runs.
/// Fingerprints the pristine text, resolves the EU 1.09 symbols, plans the byte patches and
/// installs the hooks, all or nothing: on any problem nothing is written, the reason is logged
/// and the game continues without the mod. The pristine copy is released afterwards.
void OnGameLoaded(std::uint64_t base, std::uint64_t size);

/// True once OnGameLoaded has installed everything.
bool IsActive();

/// The address of a resolved symbol in the loaded image. Asserts when the mod is inactive or the
/// symbol is unresolved (while the mod is active only optional symbols can be unresolved, which
/// happens on an image other than the reference EU 1.09 one). Use it for required symbols; for an
/// optional one use TrySymbolAddress and degrade when it is nullopt.
std::uint64_t SymbolAddress(Binding::SymbolId id);

/// The address of a symbol in the loaded image, or nullopt when the mod is inactive, the symbol
/// is unresolved or `id` is out of range. Never asserts: feature code that uses an optional
/// symbol checks it with this and turns itself off instead of crashing.
std::optional<std::uint64_t> TrySymbolAddress(Binding::SymbolId id);

} // namespace BBCoop::Runtime
