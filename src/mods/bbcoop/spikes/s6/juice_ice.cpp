// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.

// libjuice ICE probe: two agents in one process exchange descriptions and trickled candidates
// directly (no signaling server), connect over loopback and send 100 datagrams 1 -> 2.
// Both agents bind 127.0.0.1 (0C-R8) and use no STUN/TURN server, so the only candidates are
// loopback host candidates and nothing leaves the machine. Callbacks run on libjuice's own thread.

#include <juice/juice.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "spike_common.h"

namespace {

juice_agent_t* g_agent1 = nullptr;
juice_agent_t* g_agent2 = nullptr;
std::atomic<int> g_state1{JUICE_STATE_DISCONNECTED};
std::atomic<int> g_state2{JUICE_STATE_DISCONNECTED};
std::atomic<int> g_candidates1{0};
std::atomic<int> g_candidates2{0};
std::atomic<int> g_received2{0};
std::atomic<std::uint64_t> g_bytes2{0};
S6::Clock::time_point g_t0;

bool Up(int state) {
    return state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
}

void OnState1(juice_agent_t*, juice_state_t state, void*) {
    g_state1 = state;
    std::printf("DETAIL juice agent1 state=%s t_ms=%.1f\n", juice_state_to_string(state),
                S6::MicrosSince(g_t0) / 1000.0);
}
void OnState2(juice_agent_t*, juice_state_t state, void*) {
    g_state2 = state;
    std::printf("DETAIL juice agent2 state=%s t_ms=%.1f\n", juice_state_to_string(state),
                S6::MicrosSince(g_t0) / 1000.0);
}
void OnCandidate1(juice_agent_t*, const char* sdp, void*) {
    ++g_candidates1;
    std::printf("DETAIL juice agent1 candidate %s\n", sdp);
    juice_add_remote_candidate(g_agent2, sdp);
}
void OnCandidate2(juice_agent_t*, const char* sdp, void*) {
    ++g_candidates2;
    std::printf("DETAIL juice agent2 candidate %s\n", sdp);
    juice_add_remote_candidate(g_agent1, sdp);
}
void OnGatheringDone1(juice_agent_t*, void*) {
    juice_set_remote_gathering_done(g_agent2);
}
void OnGatheringDone2(juice_agent_t*, void*) {
    juice_set_remote_gathering_done(g_agent1);
}
void OnRecv1(juice_agent_t*, const char*, size_t, void*) {}
void OnRecv2(juice_agent_t*, const char*, size_t size, void*) {
    ++g_received2;
    g_bytes2 += size;
}

void LogHandler(juice_log_level_t level, const char* message) {
    std::printf("JUICELOG lvl=%d %s\n", static_cast<int>(level), message);
}

juice_agent_t* Create(juice_cb_state_changed_t on_state, juice_cb_candidate_t on_candidate,
                      juice_cb_gathering_done_t on_done, juice_cb_recv_t on_recv) {
    juice_config_t config;
    std::memset(&config, 0, sizeof(config));
    config.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL; // one shared libjuice thread
    config.stun_server_host = nullptr;                     // no STUN: nothing leaves loopback
    config.bind_address = "127.0.0.1";                     // 0C-R8
    config.cb_state_changed = on_state;
    config.cb_candidate = on_candidate;
    config.cb_gathering_done = on_done;
    config.cb_recv = on_recv;
    return juice_create(&config);
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0); // the MSVC CRT has no line buffering
    g_t0 = S6::Clock::now();
    juice_set_log_handler(LogHandler);
    juice_set_log_level(JUICE_LOG_LEVEL_INFO);

    g_agent1 = Create(OnState1, OnCandidate1, OnGatheringDone1, OnRecv1);
    g_agent2 = Create(OnState2, OnCandidate2, OnGatheringDone2, OnRecv2);
    if (!g_agent1 || !g_agent2) {
        std::printf("RESULT juice connected=no time_ms=0 (juice_create failed)\n");
        return 1;
    }

    char sdp1[JUICE_MAX_SDP_STRING_LEN];
    char sdp2[JUICE_MAX_SDP_STRING_LEN];
    juice_get_local_description(g_agent1, sdp1, sizeof(sdp1));
    juice_set_remote_description(g_agent2, sdp1);
    juice_get_local_description(g_agent2, sdp2, sizeof(sdp2));
    juice_set_remote_description(g_agent1, sdp2);

    const auto ice_t0 = S6::Clock::now();
    juice_gather_candidates(g_agent1);
    juice_gather_candidates(g_agent2);
    while (!(Up(g_state1) && Up(g_state2)) && S6::MicrosSince(ice_t0) < 10'000'000) {
        if (g_state1 == JUICE_STATE_FAILED || g_state2 == JUICE_STATE_FAILED) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool connected = Up(g_state1) && Up(g_state2);
    const double connect_ms = S6::MicrosSince(ice_t0) / 1000.0;
    S6::CheckOwnUdpEndpointsLoopback("juice");

    if (connected) {
        char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
        char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
        if (juice_get_selected_candidates(g_agent1, local, sizeof(local), remote, sizeof(remote)) == 0) {
            std::printf("DETAIL juice agent1 selected local=\"%s\" remote=\"%s\"\n", local, remote);
        }
        char local_addr[JUICE_MAX_ADDRESS_STRING_LEN];
        char remote_addr[JUICE_MAX_ADDRESS_STRING_LEN];
        if (juice_get_selected_addresses(g_agent1, local_addr, sizeof(local_addr), remote_addr,
                                         sizeof(remote_addr)) == 0) {
            std::printf("DETAIL juice agent1 selected_addresses local=%s remote=%s\n", local_addr, remote_addr);
        }
        char payload[200];
        for (int i = 0; i < 100; ++i) {
            std::memset(payload, i, sizeof(payload));
            juice_send(g_agent1, payload, sizeof(payload));
        }
        const auto t = S6::Clock::now();
        while (g_received2 < 100 && S6::MicrosSince(t) < 2'000'000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    std::printf("DETAIL juice candidates agent1=%d agent2=%d datagrams_received=%d/100 bytes=%llu\n",
                g_candidates1.load(), g_candidates2.load(), g_received2.load(),
                static_cast<unsigned long long>(g_bytes2.load()));
    std::printf("RESULT juice connected=%s time_ms=%.0f\n", connected ? "yes" : "no", connect_ms);

    juice_destroy(g_agent1);
    juice_destroy(g_agent2);
    return connected && g_received2 == 100 ? 0 : 1;
}
