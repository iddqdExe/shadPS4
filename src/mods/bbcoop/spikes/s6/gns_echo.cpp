// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.

// GameNetworkingSockets echo probe with a mid-session client address change.
// Listen socket 127.0.0.1:47001 <- UdpRebindProxy 127.0.0.1:47002 <- client connection.
// GNS runs its own service thread; the server side (receive + echo) polls on a second app thread,
// the main thread runs RunCallbacks() and the client.
//   1. 1000 reliable 200-byte messages (k_nSteamNetworkingSend_Reliable, as in the brief), one at a
//      time: mean RTT. Repeated with ReliableNoNagle for a figure comparable to ENet (DETAIL only).
//   2. one 8000-byte reliable message (GNS fragments it): echo integrity.
//   3. proxy.Rebind(), 100 more reliable messages: does the server still get them?

#include <steam/isteamnetworkingutils.h>
#include <steam/steamnetworkingsockets.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "spike_common.h"
#include "udp_rebind_proxy.h"

namespace {

constexpr std::uint16_t kServerPort = 47001;
constexpr std::uint16_t kProxyPort = 47002;

S6::Clock::time_point g_t0;
ISteamNetworkingSockets* g_sockets = nullptr;
HSteamListenSocket g_listen = k_HSteamListenSocket_Invalid;
std::atomic<HSteamNetConnection> g_server_conn{k_HSteamNetConnection_Invalid};
HSteamNetConnection g_client_conn = k_HSteamNetConnection_Invalid;
std::atomic<bool> g_client_connected{false};
std::atomic<bool> g_stop{false};
std::atomic<std::uint32_t> g_server_echoed{0};
std::atomic<std::uint32_t> g_phase3_received{0};
std::atomic<std::int64_t> g_rebind_mark_us{-1};
double g_client_closed_s = -1.0;
double g_server_closed_s = -1.0;
std::string g_client_close_reason;
std::string g_server_close_reason;
std::mutex g_log_mutex;
int g_log_lines = 0;

double SinceRebindSeconds() {
    const std::int64_t mark = g_rebind_mark_us.load();
    return mark < 0 ? 0.0 : (S6::MicrosSince(g_t0) - mark) / 1e6;
}

void DebugOutput(ESteamNetworkingSocketsDebugOutputType type, const char* msg) {
    std::lock_guard lock(g_log_mutex);
    if (++g_log_lines > 200) {
        return; // keep the run log bounded
    }
    std::printf("GNSLOG t_ms=%.1f lvl=%d %s%s", S6::MicrosSince(g_t0) / 1000.0, static_cast<int>(type), msg,
                (msg[0] && msg[std::strlen(msg) - 1] == '\n') ? "" : "\n");
}

void OnStatusChanged(SteamNetConnectionStatusChangedCallback_t* info) {
    const auto state = info->m_info.m_eState;
    const bool is_server_side = info->m_info.m_hListenSocket != k_HSteamListenSocket_Invalid;
    std::printf("DETAIL gns status t_ms=%.1f side=%s state=%d old=%d end=%d %s\n",
                S6::MicrosSince(g_t0) / 1000.0, is_server_side ? "server" : "client", static_cast<int>(state),
                static_cast<int>(info->m_eOldState), info->m_info.m_eEndReason, info->m_info.m_szEndDebug);
    if (is_server_side) {
        if (state == k_ESteamNetworkingConnectionState_Connecting) {
            g_sockets->AcceptConnection(info->m_hConn);
        } else if (state == k_ESteamNetworkingConnectionState_Connected) {
            g_server_conn = info->m_hConn;
        } else if (state == k_ESteamNetworkingConnectionState_ClosedByPeer ||
                   state == k_ESteamNetworkingConnectionState_ProblemDetectedLocally) {
            if (g_server_closed_s < 0) {
                g_server_closed_s = SinceRebindSeconds();
                g_server_close_reason = std::to_string(info->m_info.m_eEndReason) + " " + info->m_info.m_szEndDebug;
            }
            g_server_conn = k_HSteamNetConnection_Invalid;
            g_sockets->CloseConnection(info->m_hConn, 0, nullptr, false);
        }
    } else {
        if (state == k_ESteamNetworkingConnectionState_Connected) {
            g_client_connected = true;
        } else if (state == k_ESteamNetworkingConnectionState_ClosedByPeer ||
                   state == k_ESteamNetworkingConnectionState_ProblemDetectedLocally) {
            if (g_client_closed_s < 0) {
                g_client_closed_s = SinceRebindSeconds();
                g_client_close_reason = std::to_string(info->m_info.m_eEndReason) + " " + info->m_info.m_szEndDebug;
            }
            g_client_connected = false;
        }
    }
}

// Server side: receive on the accepted connection and echo every message back, reliably.
void ServerThread() {
    SteamNetworkingMessage_t* msgs[32];
    while (!g_stop) {
        const HSteamNetConnection conn = g_server_conn.load();
        if (conn == k_HSteamNetConnection_Invalid) {
            std::this_thread::yield();
            continue;
        }
        const int n = g_sockets->ReceiveMessagesOnConnection(conn, msgs, 32);
        if (n <= 0) {
            std::this_thread::yield();
            continue;
        }
        for (int i = 0; i < n; ++i) {
            const auto* data = static_cast<const unsigned char*>(msgs[i]->GetData());
            if (msgs[i]->GetSize() > 0 && data[0] == 3) {
                ++g_phase3_received;
            }
            g_sockets->SendMessageToConnection(conn, data, msgs[i]->GetSize(),
                                               k_nSteamNetworkingSend_ReliableNoNagle, nullptr);
            msgs[i]->Release();
            ++g_server_echoed;
        }
    }
}

std::vector<unsigned char> MakePayload(std::uint8_t phase, std::uint32_t seq, std::size_t size) {
    std::vector<unsigned char> p(size);
    p[0] = phase;
    std::memcpy(&p[1], &seq, sizeof(seq));
    for (std::size_t i = 5; i < size; ++i) {
        p[i] = static_cast<unsigned char>((seq * 31u + i) & 0xFF);
    }
    return p;
}

// Runs callbacks and polls the client until one message arrives or the timeout passes.
bool WaitClientMessage(std::int64_t timeout_us, std::vector<unsigned char>* out) {
    const auto t0 = S6::Clock::now();
    while (S6::MicrosSince(t0) < timeout_us) {
        g_sockets->RunCallbacks();
        SteamNetworkingMessage_t* msg = nullptr;
        if (g_sockets->ReceiveMessagesOnConnection(g_client_conn, &msg, 1) == 1) {
            const auto* data = static_cast<const unsigned char*>(msg->GetData());
            out->assign(data, data + msg->GetSize());
            msg->Release();
            return true;
        }
        std::this_thread::yield();
    }
    return false;
}

struct RttStats {
    std::int64_t mean = 0, p50 = 0, p99 = 0, max = 0;
    std::size_t samples = 0;
    std::uint32_t bad = 0;
};

RttStats PingPong(std::uint8_t phase, int flags) {
    std::vector<std::int64_t> rtts;
    RttStats s;
    for (std::uint32_t i = 0; i < 1000; ++i) {
        const auto payload = MakePayload(phase, i, 200);
        const auto t = S6::Clock::now();
        g_sockets->SendMessageToConnection(g_client_conn, payload.data(),
                                           static_cast<std::uint32_t>(payload.size()), flags, nullptr);
        std::vector<unsigned char> echo;
        if (!WaitClientMessage(2'000'000, &echo) || echo != payload) {
            ++s.bad;
            continue;
        }
        rtts.push_back(S6::MicrosSince(t));
    }
    if (!rtts.empty()) {
        std::int64_t sum = 0;
        for (auto v : rtts) {
            sum += v;
        }
        s.mean = sum / static_cast<std::int64_t>(rtts.size());
        std::sort(rtts.begin(), rtts.end());
        s.p50 = rtts[rtts.size() / 2];
        s.p99 = rtts[static_cast<std::size_t>(0.99 * (rtts.size() - 1))];
        s.max = rtts.back();
    }
    s.samples = rtts.size();
    return s;
}

void PrintRealTimeStatus(const char* tag) {
    SteamNetConnectionRealTimeStatus_t st{};
    if (g_sockets->GetConnectionRealTimeStatus(g_client_conn, &st, 0, nullptr) == k_EResultOK) {
        std::printf("DETAIL gns %s ping_ms=%d quality_local=%.3f quality_remote=%.3f out_pps=%.1f "
                    "in_pps=%.1f send_rate_Bps=%d pending_reliable=%d\n",
                    tag, st.m_nPing, st.m_flConnectionQualityLocal, st.m_flConnectionQualityRemote,
                    st.m_flOutPacketsPerSec, st.m_flInPacketsPerSec, st.m_nSendRateBytesPerSecond,
                    st.m_cbPendingReliable);
    }
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0); // the MSVC CRT has no line buffering
    g_t0 = S6::Clock::now();
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa); // the proxy opens sockets before GNS initializes

    SteamNetworkingErrMsg err{};
    if (!GameNetworkingSockets_Init(nullptr, err)) {
        std::printf("RESULT gns rtt_us=0 frag=fail roaming=fail (init failed: %s)\n", err);
        return 1;
    }
    g_sockets = SteamNetworkingSockets();
    ISteamNetworkingUtils* utils = SteamNetworkingUtils();
    utils->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Msg, DebugOutput);
    utils->SetGlobalCallback_SteamNetConnectionStatusChanged(OnStatusChanged);
    std::printf("DETAIL gns init_ms=%.1f (GameNetworkingSockets v1.6.0, USE_CRYPTO=BCrypt)\n",
                S6::MicrosSince(g_t0) / 1000.0);

    SteamNetworkingIPAddr listen_addr;
    listen_addr.SetIPv4(0x7F000001, kServerPort);
    g_listen = g_sockets->CreateListenSocketIP(listen_addr, 0, nullptr);
    if (g_listen == k_HSteamListenSocket_Invalid) {
        std::printf("RESULT gns rtt_us=0 frag=fail roaming=fail (listen failed)\n");
        GameNetworkingSockets_Kill();
        return 1;
    }
    std::thread server_thread(ServerThread);
    UdpRebindProxy proxy(kProxyPort, kServerPort);

    SteamNetworkingIPAddr via_proxy;
    via_proxy.SetIPv4(0x7F000001, kProxyPort);
    const auto connect_t0 = S6::Clock::now();
    g_client_conn = g_sockets->ConnectByIPAddress(via_proxy, 0, nullptr);
    while (!g_client_connected && S6::MicrosSince(connect_t0) < 10'000'000) {
        g_sockets->RunCallbacks();
        std::this_thread::yield();
    }
    // Wait for the server side to be accepted and marked connected too.
    while (g_server_conn.load() == k_HSteamNetConnection_Invalid && S6::MicrosSince(connect_t0) < 10'000'000) {
        g_sockets->RunCallbacks();
        std::this_thread::yield();
    }
    std::printf("DETAIL gns connect=%s ms=%.1f proxy_upstream_port=%u\n", g_client_connected ? "yes" : "no",
                S6::MicrosSince(connect_t0) / 1000.0, proxy.UpstreamPort());
    S6::CheckOwnUdpEndpointsLoopback("gns");
    if (!g_client_connected) {
        std::printf("RESULT gns rtt_us=0 frag=fail roaming=fail (no connect)\n");
        g_stop = true;
        server_thread.join();
        GameNetworkingSockets_Kill();
        return 1;
    }

    // 1. Ping-pong, as briefed (Reliable: Nagle on), then NoNagle for comparison with ENet.
    const RttStats nagle = PingPong(1, k_nSteamNetworkingSend_Reliable);
    std::printf("DETAIL gns rtt flags=Reliable samples=%zu bad=%u mean_us=%lld p50_us=%lld p99_us=%lld "
                "max_us=%lld\n",
                nagle.samples, nagle.bad, static_cast<long long>(nagle.mean), static_cast<long long>(nagle.p50),
                static_cast<long long>(nagle.p99), static_cast<long long>(nagle.max));
    const RttStats nonagle = PingPong(1, k_nSteamNetworkingSend_ReliableNoNagle);
    std::printf("DETAIL gns rtt flags=ReliableNoNagle samples=%zu bad=%u mean_us=%lld p50_us=%lld "
                "p99_us=%lld max_us=%lld\n",
                nonagle.samples, nonagle.bad, static_cast<long long>(nonagle.mean),
                static_cast<long long>(nonagle.p50), static_cast<long long>(nonagle.p99),
                static_cast<long long>(nonagle.max));

    // 2. One 8000-byte message: GNS splits it into ~1200-byte segments (MTU_PacketSize 1300 default).
    bool frag_ok = false;
    {
        const auto payload = MakePayload(2, 0, 8000);
        const auto t = S6::Clock::now();
        g_sockets->SendMessageToConnection(g_client_conn, payload.data(),
                                           static_cast<std::uint32_t>(payload.size()),
                                           k_nSteamNetworkingSend_ReliableNoNagle, nullptr);
        std::vector<unsigned char> echo;
        frag_ok = WaitClientMessage(5'000'000, &echo) && echo == payload;
        std::printf("DETAIL gns frag bytes=8000 ok=%s rtt_us=%lld\n", frag_ok ? "yes" : "no",
                    static_cast<long long>(S6::MicrosSince(t)));
    }
    PrintRealTimeStatus("stats");
    {
        char detail[2048]{};
        if (g_sockets->GetDetailedConnectionStatus(g_client_conn, detail, sizeof(detail)) >= 0) {
            std::string text(detail);
            for (char& c : text) {
                if (c == '\n' || c == '\r') {
                    c = '|';
                }
            }
            std::printf("DETAIL gns detailed_status %s\n", text.c_str());
        }
    }

    // 3. Address change mid-session, then 100 more reliable messages.
    const std::uint16_t old_port = proxy.UpstreamPort();
    g_rebind_mark_us = S6::MicrosSince(g_t0);
    proxy.Rebind();
    while (proxy.UpstreamPort() == old_port && SinceRebindSeconds() < 1.0) {
        std::this_thread::yield();
    }
    for (std::uint32_t i = 0; i < 100; ++i) {
        const auto payload = MakePayload(3, i, 200);
        g_sockets->SendMessageToConnection(g_client_conn, payload.data(),
                                           static_cast<std::uint32_t>(payload.size()),
                                           k_nSteamNetworkingSend_Reliable, nullptr);
    }
    g_sockets->FlushMessagesOnConnection(g_client_conn);
    std::uint32_t echoes = 0;
    const auto phase3_t0 = S6::Clock::now();
    while (echoes < 100 && S6::MicrosSince(phase3_t0) < 60'000'000) {
        if (g_client_closed_s >= 0 && g_server_closed_s >= 0) {
            break;
        }
        std::vector<unsigned char> echo;
        if (WaitClientMessage(100'000, &echo) && echo.size() == 200 && echo[0] == 3) {
            ++echoes;
        }
    }
    if (echoes == 100) {
        PrintRealTimeStatus("stats_after_rebind");
    }
    std::printf("DETAIL gns roaming upstream_port %u->%u forwarded_after_rebind=%llu server_received=%u/100 "
                "client_echoes=%u/100 replies_new=%llu replies_old=%llu client_closed_s=%.2f (%s) "
                "server_closed_s=%.2f (%s) phase_s=%.2f\n",
                old_port, proxy.UpstreamPort(), static_cast<unsigned long long>(proxy.ForwardedAfterRebind()),
                g_phase3_received.load(), echoes, static_cast<unsigned long long>(proxy.RepliesViaNew()),
                static_cast<unsigned long long>(proxy.RepliesViaOld()), g_client_closed_s,
                g_client_close_reason.c_str(), g_server_closed_s, g_server_close_reason.c_str(),
                S6::MicrosSince(phase3_t0) / 1e6);

    std::string roaming;
    if (echoes == 100) {
        roaming = "ok";
    } else if (g_client_closed_s >= 0) {
        char text[64];
        std::snprintf(text, sizeof(text), "disconnect after %.1fs", g_client_closed_s);
        roaming = text;
    } else {
        roaming = "fail";
    }
    std::printf("RESULT gns rtt_us=%lld frag=%s roaming=%s\n", static_cast<long long>(nagle.mean),
                frag_ok ? "ok" : "fail", roaming.c_str());

    g_stop = true;
    server_thread.join();
    g_sockets->CloseConnection(g_client_conn, 0, nullptr, false);
    g_sockets->CloseListenSocket(g_listen);
    GameNetworkingSockets_Kill();
    return 0;
}
