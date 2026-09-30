// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bbcoop/runtime/mod.h"

#include "common/logging/log.h"
#include "common/path_util.h"

namespace BBCoop {

namespace {
Core::Config g_config;
CliOverrides g_cli;
} // namespace

void SetCliOverrides(const CliOverrides& overrides) {
    g_cli = overrides;
}

void Initialize() {
    const auto path = Common::FS::GetUserPath(Common::FS::PathType::UserDir) / "bbcoop.toml";
    auto loaded = Core::LoadConfigFile(path);
    if (!loaded) {
        LOG_ERROR(BBCoop_Config, "{}", loaded.error());
        LOG_ERROR(BBCoop_Config, "BB Co-op is disabled for this run because of the config error");
        g_config = Core::Config{};
        g_config.enabled = false;
    } else {
        g_config = loaded->config;
        for (const auto& warning : loaded->warnings) {
            LOG_WARNING(BBCoop_Config, "{}", warning);
        }
    }
    if (g_cli.port) {
        g_config.net.port = *g_cli.port;
    }
    LOG_INFO(BBCoop_Config,
             "BB Co-op config: enabled={} port={}{} upnp={} echo_loss={} auto_grant={}",
             g_config.enabled, g_config.net.port, g_cli.port ? " (cli)" : "", g_config.net.upnp,
             Core::ToString(g_config.host.echo_loss), Core::ToString(g_config.host.auto_grant));
}

const Core::Config& GetConfig() {
    return g_config;
}

} // namespace BBCoop
