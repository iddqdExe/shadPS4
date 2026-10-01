// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

namespace BBCoop::Runtime {

/// True when every byte of [address, address + size) is committed, readable host memory right
/// now (guest addresses are host addresses in shadPS4). False for size 0, for addresses below
/// 0x10000, for a range that wraps around, and for pages that are reserved, free, guard or
/// no-access pages (including pages the GPU page tracker has made no-access for the moment).
/// Thread-safe. The answer can go stale if another thread unmaps the memory afterwards.
bool IsReadable(std::uint64_t address, std::uint64_t size);

template <typename T>
std::optional<T> ReadGuest(std::uint64_t address) {
    if (!IsReadable(address, sizeof(T))) {
        return std::nullopt;
    }
    T value;
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
    return value;
}

/// Reads a pointer; a null pointer (any value below 0x10000) is reported as nullopt.
std::optional<std::uint64_t> ReadPointer(std::uint64_t address);

/// [[[base + o0] + o1] + ...]: dereferences after adding each offset. nullopt when any step is
/// unreadable, yields a null pointer or would wrap around the address space.
std::optional<std::uint64_t> FollowPointerChain(std::uint64_t base,
                                                std::span<const std::uint32_t> offsets);

} // namespace BBCoop::Runtime
