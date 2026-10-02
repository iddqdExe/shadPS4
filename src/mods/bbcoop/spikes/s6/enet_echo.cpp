// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.

// ENet + libsodium echo probe with a mid-session client address change.
// Server 127.0.0.1:47001 (own thread) <- UdpRebindProxy 127.0.0.1:47002 <- client (main thread).
// Every application payload is sealed with XChaCha20-Poly1305 (shared session key) by the sender
// and opened by the receiver, to prove the ENet + libsodium pair builds and works together.
//   1. 1000 reliable 200-byte messages, one at a time, echoed back: mean RTT.
//   2. one 8000-byte reliable message (ENet fragments it): echo integrity.
//   3. proxy.Rebind(), 100 more reliable messages: does the server still get them?
// Usage: bbcoop_s6_enet_echo [--roam-intercept]
//   --roam-intercept installs an ENetHost::intercept callback on the server that accepts a packet
//   from a new address for an existing peer when it carries an application payload that opens with
//   the session key, and then moves the peer to that address (roaming without patching ENet).

#include <enet/enet.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "spike_common.h"
#include "udp_rebind_proxy.h"

namespace {

constexpr std::uint16_t kServerPort = 47001;
constexpr std::uint16_t kProxyPort = 47002;
constexpr std::size_t kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
constexpr std::size_t kTag = crypto_aead_xchacha20poly1305_ietf_ABYTES;      // 16

std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> g_key;

// Plaintext layout: [0] phase, [1..4] sequence (LE), then a deterministic pattern.
std::vector<unsigned char> MakePlain(std::uint8_t phase, std::uint32_t seq, std::size_t size) {
    std::vector<unsigned char> p(size);
    p[0] = phase;
    std::memcpy(&p[1], &seq, sizeof(seq));
    for (std::size_t i = 5; i < size; ++i) {
        p[i] = static_cast<unsigned char>((seq * 31u + i) & 0xFF);
    }
    return p;
}

std::vector<unsigned char> Seal(const std::vector<unsigned char>& plain) {
    std::vector<unsigned char> wire(kNonce + plain.size() + kTag);
    randombytes_buf(wire.data(), kNonce);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(wire.data() + kNonce, &clen, plain.data(), plain.size(),
                                               nullptr, 0, nullptr, wire.data(), g_key.data());
    wire.resize(kNonce + static_cast<std::size_t>(clen));
    return wire;
}

std::optional<std::vector<unsigned char>> Open(const unsigned char* data, std::size_t size) {
    if (size < kNonce + kTag) {
        return std::nullopt;
    }
    std::vector<unsigned char> plain(size - kNonce - kTag);
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plen, nullptr, data + kNonce,
                                                   size - kNonce, nullptr, 0, data,
                                                   g_key.data()) != 0) {
        return std::nullopt;
    }
    plain.resize(static_cast<std::size_t>(plen));
    return plain;
}

ENetAddress Loopback(std::uint16_t port) {
    ENetAddress a{};
    enet_address_set_host_ip(&a, "127.0.0.1");
    a.port = port;
    return a;
}

void SendSealed(ENetPeer* peer, const std::vector<unsigned char>& plain) {
    const auto wire = Seal(plain);
    ENetPacket* packet = enet_packet_create(wire.data(), wire.size(), ENET_PACKET_FLAG_RELIABLE);
    enet_peer_send(peer, 0, packet);
}

// ---- server ---------------------------------------------------------------------------------

struct ServerState {
    std::atomic<bool> stop{false};
    std::atomic<bool> ready{false};
    std::atomic<std::uint32_t> opened{0};
    std::atomic<std::uint32_t> open_failed{0};
    std::atomic<std::uint32_t> phase3_received{0};
    std::atomic<std::uint32_t> roams{0};
    std::atomic<std::int64_t> disconnect_us{-1}; // since the rebind mark
    std::atomic<std::int64_t> rebind_mark_us{-1};
};

ServerState g_server;
S6::Clock::time_point g_t0;

// Roaming by authenticated packet, done in the intercept hook so ENet itself stays unpatched.
// ENet drops a datagram whose source differs from peer->address (protocol.c:1043-1050 at v1.3.18).
// Before that check runs, this callback walks the datagram's commands; if one carries a full
// application payload that opens with the session key, the peer is moved to the new address.
// A real transport would authenticate the whole datagram and reject replays; see the S6 report.
int RoamIntercept(ENetHost* host, ENetEvent*) {
    const std::size_t len = host->receivedDataLength;
    const enet_uint8* data = host->receivedData;
    if (len < sizeof(enet_uint16)) {
        return 0;
    }
    enet_uint16 peer_id;
    std::memcpy(&peer_id, data, sizeof(peer_id));
    peer_id = ENET_NET_TO_HOST_16(peer_id);
    const enet_uint16 flags = peer_id & ENET_PROTOCOL_HEADER_FLAG_MASK;
    peer_id &= ~(ENET_PROTOCOL_HEADER_FLAG_MASK | ENET_PROTOCOL_HEADER_SESSION_MASK);
    if (peer_id >= host->peerCount || (flags & ENET_PROTOCOL_HEADER_FLAG_COMPRESSED)) {
        return 0;
    }
    ENetPeer* peer = &host->peers[peer_id];
    if (peer->state != ENET_PEER_STATE_CONNECTED) {
        return 0;
    }
    if (peer->address.host == host->receivedAddress.host &&
        peer->address.port == host->receivedAddress.port) {
        return 0;
    }
    std::size_t off = (flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME) ? sizeof(ENetProtocolHeader)
                                                                     : sizeof(enet_uint16);
    bool authenticated = false;
    while (off + sizeof(ENetProtocolCommandHeader) <= len && !authenticated) {
        const auto* cmd = reinterpret_cast<const ENetProtocol*>(data + off);
        const enet_uint8 number = cmd->header.command & ENET_PROTOCOL_COMMAND_MASK;
        const std::size_t size = enet_protocol_command_size(number);
        if (size == 0 || off + size > len) {
            break;
        }
        off += size;
        std::size_t payload = 0;
        bool whole_message = false;
        switch (number) {
        case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
            payload = ENET_NET_TO_HOST_16(cmd->sendReliable.dataLength);
            whole_message = true;
            break;
        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
            payload = ENET_NET_TO_HOST_16(cmd->sendUnreliable.dataLength);
            whole_message = true;
            break;
        case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
            payload = ENET_NET_TO_HOST_16(cmd->sendUnsequenced.dataLength);
            whole_message = true;
            break;
        case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
            payload = ENET_NET_TO_HOST_16(cmd->sendFragment.dataLength);
            break;
        default:
            break;
        }
        if (off + payload > len) {
            break;
        }
        if (whole_message && Open(data + off, payload)) {
            authenticated = true;
        }
        off += payload;
    }
    if (authenticated) {
        char old_text[32]{};
        char new_text[32]{};
        enet_address_get_host_ip(&peer->address, old_text, sizeof(old_text));
        enet_address_get_host_ip(&host->receivedAddress, new_text, sizeof(new_text));
        std::printf("DETAIL enet roam_intercept peer=%u %s:%u -> %s:%u at_ms=%.1f\n", peer_id,
                    old_text, peer->address.port, new_text, host->receivedAddress.port,
                    S6::MicrosSince(g_t0) / 1000.0);
        peer->address = host->receivedAddress;
        ++g_server.roams;
    }
    return 0; // let ENet process the datagram normally (it now matches peer->address)
}

void ServerThread(bool roam_intercept) {
    const ENetAddress addr = Loopback(kServerPort);
    ENetHost* server = enet_host_create(&addr, 4, 3, 0, 0);
    if (!server) {
        std::printf("ERROR enet server host create failed\n");
        g_server.ready = true;
        return;
    }
    if (roam_intercept) {
        server->intercept = RoamIntercept;
    }
    g_server.ready = true;
    ENetEvent ev{};
    while (!g_server.stop) {
        const int r = enet_host_service(server, &ev, 1);
        if (r <= 0) {
            continue;
        }
        switch (ev.type) {
        case ENET_EVENT_TYPE_CONNECT:
            break;
        case ENET_EVENT_TYPE_RECEIVE: {
            auto plain = Open(ev.packet->data, ev.packet->dataLength);
            enet_packet_destroy(ev.packet);
            if (!plain) {
                ++g_server.open_failed;
                break;
            }
            ++g_server.opened;
            if ((*plain)[0] == 3) {
                ++g_server.phase3_received;
            }
            SendSealed(ev.peer, *plain);
            enet_host_flush(server);
            break;
        }
        case ENET_EVENT_TYPE_DISCONNECT: {
            const std::int64_t mark = g_server.rebind_mark_us.load();
            g_server.disconnect_us = mark >= 0 ? S6::MicrosSince(g_t0) - mark : 0;
            break;
        }
        default:
            break;
        }
    }
    enet_host_destroy(server);
}

// ---- client ---------------------------------------------------------------------------------

struct Echo {
    std::vector<unsigned char> plain;
};

// Services the client host until an echo arrives, the peer disconnects, or the timeout passes.
enum class Wait { Echo, Disconnect, Timeout };

Wait ServiceOnce(ENetHost* client, std::uint32_t timeout_ms, Echo* out) {
    ENetEvent ev{};
    const auto t0 = S6::Clock::now();
    for (;;) {
        const auto elapsed_ms = static_cast<std::uint32_t>(S6::MicrosSince(t0) / 1000);
        if (elapsed_ms >= timeout_ms) {
            return Wait::Timeout;
        }
        const int r = enet_host_service(client, &ev, 1);
        if (r <= 0) {
            continue;
        }
        if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
            auto plain = Open(ev.packet->data, ev.packet->dataLength);
            enet_packet_destroy(ev.packet);
            if (plain && out) {
                out->plain = std::move(*plain);
                return Wait::Echo;
            }
        } else if (ev.type == ENET_EVENT_TYPE_DISCONNECT) {
            return Wait::Disconnect;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    const bool roam_intercept = argc > 1 && std::strcmp(argv[1], "--roam-intercept") == 0;
    const char* lib = roam_intercept ? "enet+roam_intercept" : "enet";
    std::setvbuf(stdout, nullptr, _IONBF, 0); // the MSVC CRT has no line buffering
    g_t0 = S6::Clock::now();

    if (sodium_init() < 0 || enet_initialize() != 0) {
        std::printf("RESULT %s rtt_us=0 frag=fail roaming=fail (init failed)\n", lib);
        return 1;
    }
    std::printf("DETAIL %s enet=%u.%u.%u libsodium=%s\n", lib, ENET_VERSION_MAJOR, ENET_VERSION_MINOR,
                ENET_VERSION_PATCH, sodium_version_string());
    crypto_aead_xchacha20poly1305_ietf_keygen(g_key.data());

    std::thread server_thread(ServerThread, roam_intercept);
    while (!g_server.ready) {
        std::this_thread::yield();
    }
    UdpRebindProxy proxy(kProxyPort, kServerPort);
    if (!proxy.Ok()) {
        std::printf("RESULT %s rtt_us=0 frag=fail roaming=fail (proxy bind failed)\n", lib);
        g_server.stop = true;
        server_thread.join();
        return 1;
    }

    const ENetAddress local = Loopback(0); // bind the client to loopback too (0C-R8)
    ENetHost* client = enet_host_create(&local, 1, 3, 0, 0);
    const ENetAddress via_proxy = Loopback(kProxyPort);
    ENetPeer* peer = enet_host_connect(client, &via_proxy, 3, 0);
    ENetEvent ev{};
    bool connected = false;
    const auto connect_t0 = S6::Clock::now();
    while (S6::MicrosSince(connect_t0) < 5'000'000) {
        if (enet_host_service(client, &ev, 1) > 0 && ev.type == ENET_EVENT_TYPE_CONNECT) {
            connected = true;
            break;
        }
    }
    std::printf("DETAIL %s connect=%s ms=%.1f proxy_upstream_port=%u\n", lib, connected ? "yes" : "no",
                S6::MicrosSince(connect_t0) / 1000.0, proxy.UpstreamPort());
    S6::CheckOwnUdpEndpointsLoopback(lib);
    if (!connected) {
        std::printf("RESULT %s rtt_us=0 frag=fail roaming=fail (no connect)\n", lib);
        g_server.stop = true;
        server_thread.join();
        return 1;
    }

    // 1. 1000 reliable 200-byte messages, ping-pong.
    std::vector<std::int64_t> rtts;
    rtts.reserve(1000);
    std::uint32_t phase1_bad = 0;
    for (std::uint32_t i = 0; i < 1000; ++i) {
        const auto plain = MakePlain(1, i, 200);
        const auto t = S6::Clock::now();
        SendSealed(peer, plain);
        enet_host_flush(client);
        Echo echo;
        if (ServiceOnce(client, 2000, &echo) != Wait::Echo || echo.plain != plain) {
            ++phase1_bad;
            continue;
        }
        rtts.push_back(S6::MicrosSince(t));
    }
    std::int64_t sum = 0;
    for (auto v : rtts) {
        sum += v;
    }
    const std::int64_t mean_us = rtts.empty() ? 0 : sum / static_cast<std::int64_t>(rtts.size());
    std::sort(rtts.begin(), rtts.end());
    auto pct = [&](double p) {
        return rtts.empty() ? 0 : rtts[static_cast<std::size_t>(p * (rtts.size() - 1))];
    };
    std::printf("DETAIL %s rtt samples=%zu bad=%u mean_us=%lld p50_us=%lld p99_us=%lld max_us=%lld "
                "wire_bytes=%zu\n",
                lib, rtts.size(), phase1_bad, static_cast<long long>(mean_us),
                static_cast<long long>(pct(0.5)), static_cast<long long>(pct(0.99)),
                static_cast<long long>(rtts.empty() ? 0 : rtts.back()), 200 + kNonce + kTag);

    // 2. One 8000-byte message: ENet splits it into SEND_FRAGMENT commands below the peer MTU.
    bool frag_ok = false;
    {
        const auto plain = MakePlain(2, 0, 8000);
        const auto t = S6::Clock::now();
        SendSealed(peer, plain);
        enet_host_flush(client);
        Echo echo;
        frag_ok = ServiceOnce(client, 5000, &echo) == Wait::Echo && echo.plain == plain;
        std::printf("DETAIL %s frag bytes=8000 wire_bytes=%zu peer_mtu=%u ok=%s rtt_us=%lld\n", lib,
                    8000 + kNonce + kTag, peer->mtu, frag_ok ? "yes" : "no",
                    static_cast<long long>(S6::MicrosSince(t)));
    }
    std::printf("DETAIL %s stats enet_rtt_ms=%u rtt_var_ms=%u packet_loss=%.4f packets_sent=%u "
                "packets_lost=%u server_opened=%u server_open_failed=%u\n",
                lib, peer->roundTripTime, peer->roundTripTimeVariance,
                peer->packetLoss / static_cast<double>(ENET_PEER_PACKET_LOSS_SCALE), peer->packetsSent,
                peer->packetsLost, g_server.opened.load(), g_server.open_failed.load());

    // 3. Address change mid-session, then 100 more reliable messages.
    const std::uint16_t old_port = proxy.UpstreamPort();
    const std::int64_t mark = S6::MicrosSince(g_t0);
    g_server.rebind_mark_us = mark;
    proxy.Rebind();
    while (proxy.UpstreamPort() == old_port && S6::MicrosSince(g_t0) - mark < 1'000'000) {
        std::this_thread::yield();
    }
    for (std::uint32_t i = 0; i < 100; ++i) {
        SendSealed(peer, MakePlain(3, i, 200));
    }
    enet_host_flush(client);
    std::uint32_t echoes = 0;
    double disconnect_s = -1.0;
    const auto phase3_t0 = S6::Clock::now();
    // Keep servicing until all echoes arrived, or both sides have dropped the connection (the
    // server's own timeout is reported too), or 60 s passed.
    while (echoes < 100 && S6::MicrosSince(phase3_t0) < 60'000'000) {
        if (disconnect_s >= 0 && g_server.disconnect_us.load() >= 0) {
            break;
        }
        Echo echo;
        const Wait w = ServiceOnce(client, 100, &echo);
        if (w == Wait::Echo && echo.plain.size() == 200 && echo.plain[0] == 3) {
            ++echoes;
        } else if (w == Wait::Disconnect && disconnect_s < 0) {
            disconnect_s = (S6::MicrosSince(g_t0) - mark) / 1e6;
        }
    }
    const double phase3_s = S6::MicrosSince(phase3_t0) / 1e6;
    std::printf("DETAIL %s roaming upstream_port %u->%u forwarded_after_rebind=%llu "
                "server_received=%u/100 client_echoes=%u/100 server_roams=%u replies_new=%llu "
                "replies_old=%llu client_disconnect_s=%.2f server_disconnect_s=%.2f phase_s=%.2f\n",
                lib, old_port, proxy.UpstreamPort(),
                static_cast<unsigned long long>(proxy.ForwardedAfterRebind()),
                g_server.phase3_received.load(), echoes, g_server.roams.load(),
                static_cast<unsigned long long>(proxy.RepliesViaNew()),
                static_cast<unsigned long long>(proxy.RepliesViaOld()), disconnect_s,
                g_server.disconnect_us.load() >= 0 ? g_server.disconnect_us.load() / 1e6 : -1.0,
                phase3_s);
    if (echoes == 100) {
        std::printf("DETAIL %s stats_after_roam enet_rtt_ms=%u packet_loss=%.4f packets_sent=%u "
                    "packets_lost=%u\n",
                    lib, peer->roundTripTime,
                    peer->packetLoss / static_cast<double>(ENET_PEER_PACKET_LOSS_SCALE),
                    peer->packetsSent, peer->packetsLost);
    }

    std::string roaming;
    if (echoes == 100) {
        roaming = "ok";
    } else if (disconnect_s >= 0) {
        char text[64];
        std::snprintf(text, sizeof(text), "disconnect after %.1fs", disconnect_s);
        roaming = text;
    } else {
        roaming = "fail";
    }
    std::printf("RESULT %s rtt_us=%lld frag=%s roaming=%s\n", lib, static_cast<long long>(mean_us),
                frag_ok ? "ok" : "fail", roaming.c_str());

    if (disconnect_s < 0) {
        enet_peer_disconnect_now(peer, 0);
    }
    enet_host_destroy(client);
    g_server.stop = true;
    server_thread.join();
    enet_deinitialize();
    return 0;
}
