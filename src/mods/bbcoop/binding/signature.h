// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace BBCoop::Binding {

/// Uppercase two-digit hex bytes separated by single spaces ("48 8B 05"); empty input gives "".
std::string FormatHexBytes(std::span<const std::uint8_t> bytes);

/// Byte pattern with wildcards, written as space-separated hex bytes ("48 8B ?? 05").
class Signature {
public:
    /// Tokens are separated by whitespace: "XX" (hex byte), "?" or "??" (any byte).
    /// Fails on an empty pattern, a bad token, or a pattern without a single literal byte.
    static std::expected<Signature, std::string> Parse(std::string_view text);

    std::size_t Size() const {
        return bytes_.size();
    }
    /// The pattern bytes; wildcard positions hold 0, so Bytes() alone cannot tell a literal 00
    /// from a wildcard. Callers that need literal bytes must check HasWildcards() first.
    std::span<const std::uint8_t> Bytes() const {
        return bytes_;
    }
    bool HasWildcards() const {
        return has_wildcards_;
    }
    bool MatchesAt(std::span<const std::uint8_t> haystack, std::size_t offset) const;
    /// Match offsets in ascending order; stops after max_matches.
    std::vector<std::size_t> FindAll(std::span<const std::uint8_t> haystack,
                                     std::size_t max_matches) const;
    /// Canonical text form, e.g. "48 8B ?? 05".
    std::string ToString() const;

private:
    Signature() = default; ///< Only Parse uses it: code outside cannot construct an empty pattern.

    std::vector<std::uint8_t> bytes_;
    std::vector<bool> literal_;
    bool has_wildcards_ = false;
    std::size_t anchor_offset_ = 0; ///< Start of the longest run of literal bytes.
    std::size_t anchor_size_ = 0;
};

} // namespace BBCoop::Binding
