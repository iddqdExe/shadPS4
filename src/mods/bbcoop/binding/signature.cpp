// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/binding/signature.h"

#include <cctype>
#include <format>
#include <functional>
#include <iterator>

namespace BBCoop::Binding {

namespace {
int HexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

// The single place that decides how one byte is written; FormatHexBytes and Signature::ToString
// both go through it.
void AppendHexByte(std::string& out, std::uint8_t byte) {
    std::format_to(std::back_inserter(out), "{:02X}", byte);
}
} // namespace

std::string FormatHexBytes(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 3);
    for (const std::uint8_t byte : bytes) {
        if (!out.empty()) {
            out += ' ';
        }
        AppendHexByte(out, byte);
    }
    return out;
}

std::expected<Signature, std::string> Signature::Parse(std::string_view text) {
    Signature sig;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
        if (pos >= text.size()) {
            break;
        }
        std::size_t end = pos;
        while (end < text.size() && !std::isspace(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
        const auto token = text.substr(pos, end - pos);
        if (token == "?" || token == "??") {
            sig.bytes_.push_back(0);
            sig.literal_.push_back(false);
            sig.has_wildcards_ = true;
        } else if (token.size() == 2 && HexValue(token[0]) >= 0 && HexValue(token[1]) >= 0) {
            sig.bytes_.push_back(
                static_cast<std::uint8_t>(HexValue(token[0]) * 16 + HexValue(token[1])));
            sig.literal_.push_back(true);
        } else {
            return std::unexpected(std::format("invalid token '{}' at offset {}", token, pos));
        }
        pos = end;
    }
    if (sig.bytes_.empty()) {
        return std::unexpected(std::string{"empty signature"});
    }
    for (std::size_t i = 0; i < sig.literal_.size();) {
        if (!sig.literal_[i]) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < sig.literal_.size() && sig.literal_[j]) {
            ++j;
        }
        if (j - i > sig.anchor_size_) {
            sig.anchor_offset_ = i;
            sig.anchor_size_ = j - i;
        }
        i = j;
    }
    if (sig.anchor_size_ == 0) {
        return std::unexpected(std::string{"signature has no literal bytes"});
    }
    return sig;
}

bool Signature::MatchesAt(std::span<const std::uint8_t> haystack, std::size_t offset) const {
    if (offset > haystack.size() || haystack.size() - offset < bytes_.size()) {
        return false;
    }
    for (std::size_t i = 0; i < bytes_.size(); ++i) {
        if (literal_[i] && haystack[offset + i] != bytes_[i]) {
            return false;
        }
    }
    return true;
}

std::vector<std::size_t> Signature::FindAll(std::span<const std::uint8_t> haystack,
                                            std::size_t max_matches) const {
    std::vector<std::size_t> out;
    if (haystack.size() < bytes_.size() || max_matches == 0) {
        return out;
    }
    // Search for the longest literal run, then verify the whole pattern around each hit.
    const auto anchor = bytes_.begin() + static_cast<std::ptrdiff_t>(anchor_offset_);
    const std::boyer_moore_horspool_searcher searcher(
        anchor, anchor + static_cast<std::ptrdiff_t>(anchor_size_));
    const std::size_t tail = bytes_.size() - anchor_offset_ - anchor_size_;
    auto it = haystack.begin() + static_cast<std::ptrdiff_t>(anchor_offset_);
    const auto last = haystack.end() - static_cast<std::ptrdiff_t>(tail);
    while (it < last) {
        const auto found = searcher(it, last).first;
        if (found == last) {
            break;
        }
        const auto start = static_cast<std::size_t>(found - haystack.begin()) - anchor_offset_;
        if (MatchesAt(haystack, start)) {
            out.push_back(start);
            if (out.size() >= max_matches) {
                break;
            }
        }
        it = found + 1;
    }
    return out;
}

std::string Signature::ToString() const {
    std::string out;
    out.reserve(bytes_.size() * 3);
    for (std::size_t i = 0; i < bytes_.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        if (literal_[i]) {
            AppendHexByte(out, bytes_[i]);
        } else {
            out += "??";
        }
    }
    return out;
}

} // namespace BBCoop::Binding
