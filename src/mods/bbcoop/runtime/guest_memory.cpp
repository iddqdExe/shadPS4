// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/guest_memory.h"

#include <limits>

#include <windows.h>

namespace BBCoop::Runtime {

namespace {
/// Nothing is ever mapped below this address; small integers read as pointers end up here.
constexpr std::uint64_t kMinAddress = 0x10000;
constexpr DWORD kReadableProtection = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                      PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                      PAGE_EXECUTE_WRITECOPY;
} // namespace

// shadPS4 maps every guest page at the host address equal to its guest address (see
// core/address_space.cpp: the Windows backend maps with MapViewOfFile3/VirtualAlloc2 at
// reinterpret_cast<PVOID>(virtual_addr)), so a guest address is queried and read directly.
// VirtualQuery sees the real page state, unlike the emulator's VMA bookkeeping, and needs no lock.
bool IsReadable(std::uint64_t address, std::uint64_t size) {
    if (size == 0 || address < kMinAddress ||
        address > std::numeric_limits<std::uint64_t>::max() - size) {
        return false;
    }
    const std::uint64_t end = address + size;
    std::uint64_t cursor = address;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) != sizeof(info)) {
            return false;
        }
        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
            (info.Protect & kReadableProtection) == 0) {
            return false;
        }
        const auto region_end = reinterpret_cast<std::uint64_t>(info.BaseAddress) + info.RegionSize;
        if (region_end <= cursor) {
            return false;
        }
        cursor = region_end;
    }
    return true;
}

std::optional<std::uint64_t> ReadPointer(std::uint64_t address) {
    const auto value = ReadGuest<std::uint64_t>(address);
    if (!value || *value < kMinAddress) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::uint64_t> FollowPointerChain(std::uint64_t base,
                                                std::span<const std::uint32_t> offsets) {
    std::uint64_t current = base;
    for (const auto offset : offsets) {
        if (current > std::numeric_limits<std::uint64_t>::max() - offset) {
            return std::nullopt;
        }
        const auto next = ReadPointer(current + offset);
        if (!next) {
            return std::nullopt;
        }
        current = *next;
    }
    return current;
}

} // namespace BBCoop::Runtime
