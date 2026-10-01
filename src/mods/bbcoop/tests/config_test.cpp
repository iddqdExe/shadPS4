// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string_view>

#include <gtest/gtest.h>

#include "bbcoop/core/config.h"

using namespace BBCoop::Core;

TEST(ConfigTest, EmptyInputGivesDefaults) {
    const auto result = ParseConfig("", "test.toml");
    ASSERT_TRUE(result.has_value()) << result.error();
    const Config& c = result->config;
    EXPECT_TRUE(c.enabled);
    EXPECT_EQ(c.net.port, 41800);
    EXPECT_FALSE(c.net.upnp);
    EXPECT_EQ(c.net.rendezvous, "");
    EXPECT_EQ(c.host.echo_loss, EchoLossRule::Vanilla);
    EXPECT_EQ(c.host.auto_grant, AutoGrantMode::All);
    EXPECT_FALSE(c.host.guest_hp_penalty);
    EXPECT_EQ(c.host.max_players, 3);
    EXPECT_EQ(c.timeouts.suspect_ms, 3000u);
    EXPECT_EQ(c.timeouts.reconnect_ms, 5000u);
    EXPECT_EQ(c.timeouts.dead_ms, 45000u);
    EXPECT_FALSE(c.debug.log_player_state);
    EXPECT_FALSE(c.debug.self_test_exceptions);
    EXPECT_TRUE(result->warnings.empty());
}

TEST(ConfigTest, ParsesAllSections) {
    const auto result = ParseConfig(R"(
[general]
enabled = false
[net]
port = 50000
upnp = true
rendezvous = "rv.example.org:7777"
[host]
echo_loss = "keep"
auto_grant = "unique_only"
guest_hp_penalty = true
max_players = 2
[timeouts]
suspect_ms = 2000
reconnect_ms = 4000
dead_ms = 60000
[debug]
log_player_state = true
self_test_exceptions = true
)",
                                    "test.toml");
    ASSERT_TRUE(result.has_value()) << result.error();
    const Config& c = result->config;
    EXPECT_FALSE(c.enabled);
    EXPECT_EQ(c.net.port, 50000);
    EXPECT_TRUE(c.net.upnp);
    EXPECT_EQ(c.net.rendezvous, "rv.example.org:7777");
    EXPECT_EQ(c.host.echo_loss, EchoLossRule::Keep);
    EXPECT_EQ(c.host.auto_grant, AutoGrantMode::UniqueOnly);
    EXPECT_TRUE(c.host.guest_hp_penalty);
    EXPECT_EQ(c.host.max_players, 2);
    EXPECT_EQ(c.timeouts.suspect_ms, 2000u);
    EXPECT_EQ(c.timeouts.reconnect_ms, 4000u);
    EXPECT_EQ(c.timeouts.dead_ms, 60000u);
    EXPECT_TRUE(c.debug.log_player_state);
    EXPECT_TRUE(c.debug.self_test_exceptions);
}

TEST(ConfigTest, ParsesSelfTestExceptionsAlone) {
    const auto result = ParseConfig("[debug]\nself_test_exceptions = true\n", "test.toml");
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result->config.debug.self_test_exceptions);
    EXPECT_FALSE(result->config.debug.log_player_state);
    EXPECT_TRUE(result->warnings.empty());
}

TEST(ConfigTest, RejectsNonBooleanSelfTestExceptions) {
    const auto result = ParseConfig("[debug]\nself_test_exceptions = 1\n", "test.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("debug.self_test_exceptions"), std::string::npos)
        << result.error();
}

TEST(ConfigTest, RejectsPortOutOfRange) {
    const auto result = ParseConfig("[net]\nport = 70000\n", "test.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("net.port"), std::string::npos) << result.error();
}

TEST(ConfigTest, RejectsWrongType) {
    const auto result = ParseConfig("[net]\nport = \"abc\"\n", "test.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("net.port"), std::string::npos) << result.error();
}

TEST(ConfigTest, RejectsUnknownEnumValue) {
    const auto result = ParseConfig("[host]\necho_loss = \"lose_all\"\n", "test.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("vanilla"), std::string::npos) << result.error();
    EXPECT_NE(result.error().find("keep"), std::string::npos) << result.error();
}

TEST(ConfigTest, RejectsMaxPlayersOutsideTwoToThree) {
    EXPECT_FALSE(ParseConfig("[host]\nmax_players = 1\n", "t").has_value());
    EXPECT_FALSE(ParseConfig("[host]\nmax_players = 4\n", "t").has_value());
}

TEST(ConfigTest, RejectsTimeoutsOutOfOrder) {
    const auto result =
        ParseConfig("[timeouts]\nsuspect_ms = 6000\nreconnect_ms = 5000\n", "test.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("timeouts"), std::string::npos) << result.error();
}

TEST(ConfigTest, RejectsSyntaxErrorWithSourceName) {
    const auto result = ParseConfig("[net\nport = 1\n", "broken.toml");
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().find("broken.toml"), std::string::npos) << result.error();
}

TEST(ConfigTest, WarnsOnUnknownKeysAndTables) {
    // toml11 tables are unordered maps, so the warning order is not specified.
    const auto result = ParseConfig("[net]\nprot = 1\n[foo]\nbar = 2\n", "test.toml");
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_EQ(result->warnings.size(), 2u);
    const auto has = [&](std::string_view needle) {
        return std::any_of(result->warnings.begin(), result->warnings.end(),
                           [&](const std::string& w) { return w.find(needle) != std::string::npos; });
    };
    EXPECT_TRUE(has("'net.prot'"));
    EXPECT_TRUE(has("'foo'"));
}

TEST(ConfigTest, MissingFileGivesDefaultsWithWarning) {
    const auto path = std::filesystem::temp_directory_path() / "bbcoop-missing-config.toml";
    std::filesystem::remove(path);
    const auto result = LoadConfigFile(path);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result->config.net.port, 41800);
    ASSERT_EQ(result->warnings.size(), 1u);
    EXPECT_NE(result->warnings[0].find("not found"), std::string::npos);
}

TEST(ConfigTest, LoadsExistingFile) {
    const auto path = std::filesystem::temp_directory_path() / "bbcoop-config-test.toml";
    {
        std::ofstream out(path);
        out << "[net]\nport = 41900\n";
    }
    const auto result = LoadConfigFile(path);
    std::filesystem::remove(path);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result->config.net.port, 41900);
}
