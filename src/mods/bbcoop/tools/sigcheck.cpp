// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Offline check: resolves the compiled EU 1.09 table against a decrypted eboot ELF in both
// reference and scanning mode and verifies every patch's original bytes.
// Exit code: 0 all good, 1 a check failed, 2 bad command line or unusable input file.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bbcoop/binding/symbols.h"

using namespace BBCoop::Binding;

namespace {

struct Text {
    std::span<const std::uint8_t> bytes;
    std::uint64_t rva;
};

void Print(const std::string& line) {
    std::fputs(line.c_str(), stdout);
    std::fputc('\n', stdout);
}

int InputError(const std::string& message) {
    std::fputs(std::format("bbcoop_sigcheck: {}\n", message).c_str(), stderr);
    return 2;
}

// The caller has checked that [offset, offset + sizeof(T)) lies inside the file.
template <typename T>
T ReadAt(std::span<const std::uint8_t> file, std::uint64_t offset) {
    T value;
    std::memcpy(&value, file.data() + offset, sizeof(T));
    return value;
}

// The file bytes and vaddr of the first executable PT_LOAD of an ELF64 file. Only what the check
// needs is parsed, and every offset or size taken from the file is bounds-checked first.
std::expected<Text, std::string> FindText(std::span<const std::uint8_t> file) {
    constexpr std::uint64_t kHeaderSize = 0x40;
    constexpr std::uint64_t kPhdrSize = 0x38; // ELF64 program header
    constexpr std::uint32_t kPtLoad = 1;
    constexpr std::uint32_t kPfExec = 1;
    if (file.size() < kHeaderSize) {
        return std::unexpected(
            std::format("{} bytes is too small for an ELF64 header", file.size()));
    }
    if (std::memcmp(file.data(),
                    "\x7F"
                    "ELF",
                    4) != 0) {
        return std::unexpected("not an ELF file (bad magic)");
    }
    if (file[4] != 2) {
        return std::unexpected("not a 64-bit ELF file");
    }
    // Every field below is read with memcpy into a host integer, so the file must be little-endian.
    if (file[5] != 1) {
        return std::unexpected("not a little-endian ELF file");
    }
    if (const auto machine = ReadAt<std::uint16_t>(file, 0x12); machine != 0x3E) {
        return std::unexpected(std::format("e_machine is {:#x}, not x86-64 (0x3e)", machine));
    }
    const auto phoff = ReadAt<std::uint64_t>(file, 0x20);
    const auto phentsize = ReadAt<std::uint16_t>(file, 0x36);
    const auto phnum = ReadAt<std::uint16_t>(file, 0x38);
    if (phentsize < kPhdrSize) {
        return std::unexpected(std::format("program header entry size {} is too small", phentsize));
    }
    if (phoff > file.size() || std::uint64_t{phnum} * phentsize > file.size() - phoff) {
        return std::unexpected("the program header table lies outside the file");
    }
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const std::uint64_t ph = phoff + std::uint64_t{i} * phentsize;
        const auto type = ReadAt<std::uint32_t>(file, ph);
        const auto flags = ReadAt<std::uint32_t>(file, ph + 4);
        if (type != kPtLoad || (flags & kPfExec) == 0) {
            continue;
        }
        const auto offset = ReadAt<std::uint64_t>(file, ph + 8);
        const auto vaddr = ReadAt<std::uint64_t>(file, ph + 16);
        const auto filesz = ReadAt<std::uint64_t>(file, ph + 32);
        if (offset > file.size() || filesz > file.size() - offset) {
            return std::unexpected(
                std::format("the executable segment (program header {}) lies outside the file", i));
        }
        return Text{file.subspan(offset, filesz), vaddr};
    }
    return std::unexpected("no executable PT_LOAD segment");
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fputs("usage: bbcoop_sigcheck <eboot.elf>\n", stderr);
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        return InputError(std::format("cannot open {}", argv[1]));
    }
    const std::vector<std::uint8_t> file{std::istreambuf_iterator<char>(in),
                                         std::istreambuf_iterator<char>()};
    if (in.bad()) {
        return InputError(std::format("cannot read {}", argv[1]));
    }
    const auto text = FindText(file);
    if (!text) {
        return InputError(std::format("{}: {}", argv[1], text.error()));
    }

    const auto image = Eu109Image();
    const auto specs = Eu109Symbols();
    const bool reference = text->rva == image.text_rva && text->bytes.size() == image.text_size &&
                           Fingerprint(text->bytes) == image.fingerprint;
    Print(std::format("fingerprint {}", reference ? "matches the reference image"
                                                  : "DOES NOT match the reference image"));
    std::size_t bad = reference ? 0 : 1;
    for (const bool reference_mode : {true, false}) {
        if (reference_mode && !reference) {
            continue;
        }
        const auto start = std::chrono::steady_clock::now();
        const auto result = ResolveSymbols({text->bytes, text->rva, reference_mode}, specs);
        const std::chrono::duration<double, std::milli> elapsed =
            std::chrono::steady_clock::now() - start;
        Print(std::format("{} mode: resolved {}/{} in {:.1f} ms",
                          reference_mode ? "reference" : "scan", result.ResolvedCount(),
                          specs.size(), elapsed.count()));
        for (const auto& failure : result.failures) {
            Print("  FAIL " + FormatFailure(failure));
        }
        bad += result.failures.size();
        if (!reference_mode) {
            // A unique match somewhere else is still a wrong answer: the table holds the RVAs of
            // the reference image.
            for (std::size_t i = 0; i < specs.size(); ++i) {
                const auto rva = result.Rva(i);
                if (rva && *rva != specs[i].target_rva) {
                    Print(std::format("  FAIL {}: scan resolved {:#x}, table says {:#x}",
                                      specs[i].name, *rva, specs[i].target_rva));
                    ++bad;
                }
            }
            continue;
        }
        // Every patch group enabled: each patch's original bytes are checked against the image, and
        // an overlap between any two patches is reported.
        std::vector<std::string_view> groups;
        for (const auto& patch : Eu109Patches()) {
            if (std::find(groups.begin(), groups.end(), patch.group) == groups.end()) {
                groups.push_back(patch.group);
            }
        }
        const auto lookup = [&](std::string_view name) -> std::optional<std::uint64_t> {
            const auto id = FindSymbol(name);
            return id ? result.Rva(static_cast<std::size_t>(*id)) : std::nullopt;
        };
        const auto plan = PlanPatches(
            {Eu109Patches(), groups, lookup, text->bytes, text->bytes, text->rva, true});
        Print(std::format("patches: {} planned, {} errors", plan.ops.size(), plan.errors.size()));
        for (const auto& error : plan.errors) {
            Print(std::format("  FAIL patch {}: {}", error.name, error.detail));
        }
        bad += plan.errors.size();
    }
    return bad == 0 ? 0 : 1;
}
