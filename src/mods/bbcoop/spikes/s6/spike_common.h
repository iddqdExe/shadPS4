// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.
#pragma once
// Shared helpers for the S6 probes: monotonic time and a self-check that every UDP endpoint the
// process owns is bound to loopback (0C-R8: nothing may listen on 0.0.0.0 / ::).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace S6 {

using Clock = std::chrono::steady_clock;

inline std::int64_t MicrosSince(Clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t0).count();
}

// Lists the UDP endpoints owned by this process (IPv4 and IPv6) and reports whether all of them
// are loopback. Printed as one "SOCKETS" line so the run log shows the actual binds.
inline bool CheckOwnUdpEndpointsLoopback(const char* tag) {
    const DWORD pid = GetCurrentProcessId();
    std::string list;
    bool all_loopback = true;
    int count = 0;

    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<unsigned char> buf4(size + 4096);
    size = static_cast<ULONG>(buf4.size());
    if (GetExtendedUdpTable(buf4.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf4.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) {
                continue;
            }
            in_addr a{};
            a.s_addr = row.dwLocalAddr;
            char text[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &a, text, sizeof(text));
            const bool loopback = (ntohl(row.dwLocalAddr) >> 24) == 127;
            all_loopback = all_loopback && loopback;
            list += std::string(count++ ? "," : "") + text + ":" +
                    std::to_string(ntohs(static_cast<u_short>(row.dwLocalPort)));
        }
    }

    size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    std::vector<unsigned char> buf6(size + 4096);
    size = static_cast<ULONG>(buf6.size());
    if (GetExtendedUdpTable(buf6.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf6.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) {
                continue;
            }
            in6_addr a{};
            std::memcpy(&a, row.ucLocalAddr, sizeof(a));
            char text[INET6_ADDRSTRLEN]{};
            inet_ntop(AF_INET6, &a, text, sizeof(text));
            static const unsigned char kLoop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            const bool mapped_loop = a.s6_addr[10] == 0xff && a.s6_addr[11] == 0xff &&
                                     a.s6_addr[12] == 127 &&
                                     std::memcmp(a.s6_addr, kLoop6, 10) == 0;
            const bool loopback = std::memcmp(a.s6_addr, kLoop6, 16) == 0 || mapped_loop;
            all_loopback = all_loopback && loopback;
            list += std::string(count++ ? "," : "") + "[" + text + "]:" +
                    std::to_string(ntohs(static_cast<u_short>(row.dwLocalPort)));
        }
    }

    std::printf("SOCKETS %s count=%d all_loopback=%s list=%s\n", tag, count,
                all_loopback ? "yes" : "NO", list.c_str());
    std::fflush(stdout);
    return all_loopback;
}

} // namespace S6
