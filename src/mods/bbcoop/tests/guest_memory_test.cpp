// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

// runtime/guest_memory.cpp has no emulator dependencies (it asks the host with VirtualQuery), so
// the tests compile it directly. Guest addresses are host addresses, so host pages stand in for
// guest pages here.

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>

#include <gtest/gtest.h>
#include <windows.h>

#include "bbcoop/runtime/guest_memory.h"

using namespace BBCoop::Runtime;

namespace {
/// Six pages with different states, in this order: read-write, read-only, no-access,
/// read-only + guard, execute-only, reserved (not committed).
class Pages {
public:
    enum Page { ReadWrite, ReadOnly, NoAccess, Guard, ExecuteOnly, Reserved, kCount };

    Pages() {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        page_ = info.dwPageSize;
        base_ = static_cast<std::uint8_t*>(
            VirtualAlloc(nullptr, page_ * kCount, MEM_RESERVE, PAGE_NOACCESS));
        if (base_ == nullptr) {
            return;
        }
        Commit(ReadWrite, PAGE_READWRITE);
        Commit(ReadOnly, PAGE_READWRITE); // filled below, then made read-only
        if (ok_) {
            std::memset(At(ReadOnly), 0x5A, page_);
        }
        Protect(ReadOnly, PAGE_READONLY);
        Commit(NoAccess, PAGE_NOACCESS);
        Commit(Guard, PAGE_READONLY | PAGE_GUARD);
        Commit(ExecuteOnly, PAGE_EXECUTE);
    }
    ~Pages() {
        if (base_ != nullptr) {
            VirtualFree(base_, 0, MEM_RELEASE);
        }
    }
    Pages(const Pages&) = delete;
    Pages& operator=(const Pages&) = delete;

    bool Ok() const {
        return base_ != nullptr && ok_;
    }
    std::uint8_t* At(Page page) const {
        return base_ + page * page_;
    }
    std::uint64_t Address(Page page, std::uint64_t offset = 0) const {
        return reinterpret_cast<std::uint64_t>(At(page)) + offset;
    }
    std::uint64_t PageSize() const {
        return page_;
    }

private:
    void Commit(Page page, DWORD protect) {
        ok_ = ok_ && VirtualAlloc(At(page), page_, MEM_COMMIT, protect) != nullptr;
    }
    void Protect(Page page, DWORD protect) {
        DWORD old = 0;
        ok_ = ok_ && VirtualProtect(At(page), page_, protect, &old) != 0;
    }

    std::uint8_t* base_ = nullptr;
    std::uint64_t page_ = 0;
    bool ok_ = true;
};

class GuestMemoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pages.Ok()) << "VirtualAlloc/VirtualProtect failed: " << GetLastError();
    }
    Pages pages;
};
} // namespace

TEST_F(GuestMemoryTest, CommittedReadablePagesAreReadable) {
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadWrite), 8));
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadWrite), pages.PageSize()));
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadOnly, 100), 8));
}

TEST_F(GuestMemoryTest, OtherPagesAreNotReadable) {
    EXPECT_FALSE(IsReadable(pages.Address(Pages::NoAccess), 8));
    EXPECT_FALSE(IsReadable(pages.Address(Pages::Guard), 8));
    EXPECT_FALSE(IsReadable(pages.Address(Pages::ExecuteOnly), 8));
    EXPECT_FALSE(IsReadable(pages.Address(Pages::Reserved), 8));
}

TEST_F(GuestMemoryTest, ChecksEveryPageOfARange) {
    const std::uint64_t page = pages.PageSize();
    // Read-write into read-only: two regions, both readable.
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadWrite, page - 4), 8));
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadWrite), 2 * page));
    // Read-only into no-access: the last 4 bytes are not readable.
    EXPECT_FALSE(IsReadable(pages.Address(Pages::ReadOnly, page - 4), 8));
    EXPECT_TRUE(IsReadable(pages.Address(Pages::ReadOnly, page - 8), 8)); // ends at the boundary
    EXPECT_FALSE(IsReadable(pages.Address(Pages::ReadWrite), 3 * page));
}

TEST_F(GuestMemoryTest, RefusesNullSmallEmptyAndWrappingRanges) {
    EXPECT_FALSE(IsReadable(0, 8));
    EXPECT_FALSE(IsReadable(0xFFFF, 1));
    EXPECT_FALSE(IsReadable(pages.Address(Pages::ReadWrite), 0));
    EXPECT_FALSE(IsReadable(std::numeric_limits<std::uint64_t>::max() - 3, 8));
    EXPECT_FALSE(IsReadable(0x7FFF'FFFF'FFFF'0000ull, 8)); // above the user address space
}

TEST_F(GuestMemoryTest, ReadGuestReadsReadableMemoryOnly) {
    const std::uint32_t value = 0xDEADBEEF;
    std::memcpy(pages.At(Pages::ReadWrite) + 16, &value, sizeof(value));
    EXPECT_EQ(ReadGuest<std::uint32_t>(pages.Address(Pages::ReadWrite, 16)), value);
    EXPECT_EQ(ReadGuest<std::uint8_t>(pages.Address(Pages::ReadOnly)), 0x5A);
    EXPECT_FALSE(ReadGuest<std::uint32_t>(pages.Address(Pages::NoAccess)).has_value());
    EXPECT_FALSE(
        ReadGuest<std::uint64_t>(pages.Address(Pages::ReadOnly, pages.PageSize() - 4)).has_value());
    struct Pair {
        float x, y;
    };
    const Pair pair{1.5f, -2.0f};
    std::memcpy(pages.At(Pages::ReadWrite) + 32, &pair, sizeof(pair));
    const auto read = ReadGuest<Pair>(pages.Address(Pages::ReadWrite, 32));
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->x, 1.5f);
    EXPECT_EQ(read->y, -2.0f);
}

TEST_F(GuestMemoryTest, ReadPointerTreatsSmallValuesAsNull) {
    auto* slots = reinterpret_cast<std::uint64_t*>(pages.At(Pages::ReadWrite));
    slots[0] = 0;
    slots[1] = 0xFFFF;
    slots[2] = 0x10000;
    EXPECT_FALSE(ReadPointer(pages.Address(Pages::ReadWrite, 0)).has_value());
    EXPECT_FALSE(ReadPointer(pages.Address(Pages::ReadWrite, 8)).has_value());
    EXPECT_EQ(ReadPointer(pages.Address(Pages::ReadWrite, 16)), 0x10000u);
    EXPECT_FALSE(ReadPointer(pages.Address(Pages::NoAccess)).has_value());
}

TEST_F(GuestMemoryTest, FollowsPointerChains) {
    // [base + 0x8] = node, [node + 0x10] = leaf.
    auto* memory = pages.At(Pages::ReadWrite);
    const std::uint64_t base = pages.Address(Pages::ReadWrite, 0x100);
    const std::uint64_t node = pages.Address(Pages::ReadWrite, 0x200);
    const std::uint64_t leaf = pages.Address(Pages::ReadOnly, 0x40);
    std::memcpy(memory + 0x108, &node, sizeof(node));
    std::memcpy(memory + 0x210, &leaf, sizeof(leaf));

    const std::array<std::uint32_t, 2> chain{0x8, 0x10};
    EXPECT_EQ(FollowPointerChain(base, chain), leaf);
    EXPECT_EQ(FollowPointerChain(base, std::span<const std::uint32_t>{}), base);
    // [leaf] holds 0x5A5A5A5A5A5A5A5A (the read-only page's filler), which is not mapped: it is
    // returned as a value, but dereferencing it fails.
    const std::array<std::uint32_t, 3> through_leaf{0x8, 0x10, 0x0};
    EXPECT_EQ(FollowPointerChain(base, through_leaf), 0x5A5A5A5A5A5A5A5Aull);
    const std::array<std::uint32_t, 4> past_leaf{0x8, 0x10, 0x0, 0x0};
    EXPECT_FALSE(FollowPointerChain(base, past_leaf).has_value());
    // A null link stops the chain: [base + 0] is 0.
    const std::array<std::uint32_t, 2> to_null{0x0, 0x10};
    EXPECT_FALSE(FollowPointerChain(base, to_null).has_value());
    // base + offset must not wrap around.
    const std::array<std::uint32_t, 1> wrap{0x100};
    EXPECT_FALSE(
        FollowPointerChain(std::numeric_limits<std::uint64_t>::max() - 0x10, wrap).has_value());
}

TEST(GuestMemoryWrapTest, FollowPointerChainDoesNotWrapOntoMappedMemory) {
    // base + offset can only wrap onto a mapped address below the offset, so map a page below
    // 4 GB and aim a 32-bit offset at it from just below 2^64.
    void* low = nullptr;
    for (std::uint64_t at = 0x10000000; low == nullptr && at < 0xF0000000; at += 0x10000000) {
        low = VirtualAlloc(reinterpret_cast<void*>(at), 0x1000, MEM_RESERVE | MEM_COMMIT,
                           PAGE_READWRITE);
    }
    if (low == nullptr) {
        GTEST_SKIP() << "no free page below 4 GB";
    }
    const std::uint64_t target = reinterpret_cast<std::uint64_t>(low);
    const std::uint64_t pointer = 0x20000;
    std::memcpy(low, &pointer, sizeof(pointer));
    const std::array<std::uint32_t, 1> offset{0xFFFFFFFF};
    const std::uint64_t base = target - offset[0]; // wraps: base + offset == target (mod 2^64)
    ASSERT_GT(base, target);
    EXPECT_EQ(ReadPointer(target), pointer) << "the page itself is readable";
    EXPECT_FALSE(FollowPointerChain(base, offset).has_value());
    VirtualFree(low, 0, MEM_RELEASE);
}
