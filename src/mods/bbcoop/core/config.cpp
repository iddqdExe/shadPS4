// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/core/config.h"

#include <algorithm>
#include <fstream>
#include <initializer_list>
#include <sstream>

#include <fmt/format.h>
#include <toml.hpp>

namespace BBCoop::Core {

namespace {

class Reader {
public:
    Reader(std::string_view source, std::vector<std::string>& warnings)
        : source_(source), warnings_(warnings) {}

    bool Failed() const {
        return !error_.empty();
    }
    const std::string& Error() const {
        return error_;
    }

    void Fail(const std::string& message) {
        if (error_.empty()) {
            error_ = fmt::format("{}: {}", source_, message);
        }
    }

    void Warn(const std::string& message) {
        warnings_.push_back(fmt::format("{}: {}", source_, message));
    }

    const toml::value* Find(const toml::value& table, std::string_view key) {
        const std::string k{key};
        return table.contains(k) ? &table.at(k) : nullptr;
    }

    void ReadBool(const toml::value& table, std::string_view section, std::string_view key,
                  bool& out) {
        if (const auto* v = Find(table, key)) {
            if (!v->is_boolean()) {
                return Fail(fmt::format("{}.{} must be a boolean", section, key));
            }
            out = v->as_boolean();
        }
    }

    template <typename T>
    void ReadInt(const toml::value& table, std::string_view section, std::string_view key,
                 std::int64_t min, std::int64_t max, T& out) {
        if (const auto* v = Find(table, key)) {
            if (!v->is_integer()) {
                return Fail(fmt::format("{}.{} must be an integer", section, key));
            }
            const auto value = v->as_integer();
            if (value < min || value > max) {
                return Fail(fmt::format("{}.{} must be in {}..{} (got {})", section, key, min,
                                        max, value));
            }
            out = static_cast<T>(value);
        }
    }

    void ReadString(const toml::value& table, std::string_view section, std::string_view key,
                    std::string& out) {
        if (const auto* v = Find(table, key)) {
            if (!v->is_string()) {
                return Fail(fmt::format("{}.{} must be a string", section, key));
            }
            out = v->as_string();
        }
    }

    template <typename E>
    void ReadEnum(const toml::value& table, std::string_view section, std::string_view key,
                  std::initializer_list<std::pair<std::string_view, E>> allowed, E& out) {
        std::string text;
        const bool present = Find(table, key) != nullptr;
        ReadString(table, section, key, text);
        if (!present || Failed()) {
            return;
        }
        for (const auto& [name, value] : allowed) {
            if (name == text) {
                out = value;
                return;
            }
        }
        std::string names;
        for (const auto& [name, value] : allowed) {
            names += names.empty() ? "" : ", ";
            names += name;
        }
        Fail(fmt::format("{}.{} must be one of: {} (got \"{}\")", section, key, names, text));
    }

    void WarnUnknown(const toml::value& table, std::string_view prefix,
                     std::initializer_list<std::string_view> known) {
        for (const auto& [key, value] : table.as_table()) {
            if (std::find(known.begin(), known.end(), key) == known.end()) {
                Warn(fmt::format("unknown key '{}{}'", prefix, key));
            }
        }
    }

private:
    std::string_view source_;
    std::vector<std::string>& warnings_;
    std::string error_;
};

} // namespace

std::expected<ConfigResult, std::string> ParseConfig(std::string_view text,
                                                     std::string_view source_name) {
    auto parsed = toml::try_parse_str(std::string{text});
    if (parsed.is_err()) {
        std::string message = fmt::format("{}: TOML syntax error", source_name);
        for (const auto& error : parsed.unwrap_err()) {
            message += "\n" + toml::format_error(error);
        }
        return std::unexpected(message);
    }
    const toml::value& root = parsed.unwrap();

    ConfigResult result;
    Config& c = result.config;
    Reader r{source_name, result.warnings};

    for (const auto& [key, value] : root.as_table()) {
        static constexpr std::string_view kTables[] = {"general", "net", "host", "timeouts",
                                                       "debug"};
        if (std::find(std::begin(kTables), std::end(kTables), key) == std::end(kTables)) {
            r.Warn(fmt::format("unknown key '{}'", key));
        } else if (!value.is_table()) {
            r.Fail(fmt::format("'{}' must be a table", key));
        }
    }
    if (r.Failed()) {
        return std::unexpected(r.Error());
    }

    if (const auto* general = r.Find(root, "general")) {
        r.WarnUnknown(*general, "general.", {"enabled"});
        r.ReadBool(*general, "general", "enabled", c.enabled);
    }
    if (const auto* net = r.Find(root, "net")) {
        r.WarnUnknown(*net, "net.", {"port", "upnp", "rendezvous"});
        r.ReadInt(*net, "net", "port", 1, 65535, c.net.port);
        r.ReadBool(*net, "net", "upnp", c.net.upnp);
        r.ReadString(*net, "net", "rendezvous", c.net.rendezvous);
    }
    if (const auto* host = r.Find(root, "host")) {
        r.WarnUnknown(*host, "host.", {"echo_loss", "auto_grant", "guest_hp_penalty", "max_players"});
        r.ReadEnum(*host, "host", "echo_loss",
                   {{"vanilla", EchoLossRule::Vanilla}, {"keep", EchoLossRule::Keep}},
                   c.host.echo_loss);
        r.ReadEnum(*host, "host", "auto_grant",
                   {{"all", AutoGrantMode::All}, {"unique_only", AutoGrantMode::UniqueOnly}},
                   c.host.auto_grant);
        r.ReadBool(*host, "host", "guest_hp_penalty", c.host.guest_hp_penalty);
        r.ReadInt(*host, "host", "max_players", 2, 3, c.host.max_players);
    }
    if (const auto* timeouts = r.Find(root, "timeouts")) {
        r.WarnUnknown(*timeouts, "timeouts.", {"suspect_ms", "reconnect_ms", "dead_ms"});
        r.ReadInt(*timeouts, "timeouts", "suspect_ms", 500, 600000, c.timeouts.suspect_ms);
        r.ReadInt(*timeouts, "timeouts", "reconnect_ms", 500, 600000, c.timeouts.reconnect_ms);
        r.ReadInt(*timeouts, "timeouts", "dead_ms", 1000, 600000, c.timeouts.dead_ms);
    }
    if (const auto* debug = r.Find(root, "debug")) {
        r.WarnUnknown(*debug, "debug.", {"log_player_state"});
        r.ReadBool(*debug, "debug", "log_player_state", c.debug.log_player_state);
    }
    if (!r.Failed() && !(c.timeouts.suspect_ms < c.timeouts.reconnect_ms &&
                         c.timeouts.reconnect_ms < c.timeouts.dead_ms)) {
        r.Fail("timeouts must satisfy suspect_ms < reconnect_ms < dead_ms");
    }
    if (r.Failed()) {
        return std::unexpected(r.Error());
    }
    return result;
}

std::expected<ConfigResult, std::string> LoadConfigFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ConfigResult result;
        result.warnings.push_back(fmt::format("{} not found; using defaults", path.string()));
        return result;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return ParseConfig(text.str(), path.string());
}

std::string_view ToString(EchoLossRule rule) {
    return rule == EchoLossRule::Vanilla ? "vanilla" : "keep";
}

std::string_view ToString(AutoGrantMode mode) {
    return mode == AutoGrantMode::All ? "all" : "unique_only";
}

} // namespace BBCoop::Core
