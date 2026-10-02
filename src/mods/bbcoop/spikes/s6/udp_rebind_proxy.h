// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.
#pragma once
// Loopback UDP proxy that simulates a NAT rebinding of the client in the middle of a session.
// It listens on 127.0.0.1:listen_port, forwards client->server through an "external" socket S1 and,
// after Rebind(), through a fresh socket S2 (another local port). Server replies arriving on any of
// its sockets go back to the client. Differences from the brief's sketch: <chrono> is included
// (0C-R10), a second Rebind() closes the oldest socket instead of leaking it, SIO_UDP_CONNRESET is
// off (spec 8.1), and the worker blocks in select() instead of sleep-polling, so the proxy adds no
// timer-resolution latency to the RTT measurements.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h> // SIO_UDP_CONNRESET
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

class UdpRebindProxy {
public:
    UdpRebindProxy(std::uint16_t listen_port, std::uint16_t server_port) : server_port_(server_port) {
        listen_ = Open(listen_port);
        upstream_ = Open(0);
        worker_ = std::thread([this] { Run(); });
    }
    ~UdpRebindProxy() {
        stop_ = true;
        worker_.join();
        closesocket(listen_);
        closesocket(upstream_);
        if (old_ != INVALID_SOCKET) {
            closesocket(old_);
        }
    }
    UdpRebindProxy(const UdpRebindProxy&) = delete;
    UdpRebindProxy& operator=(const UdpRebindProxy&) = delete;

    void Rebind() { rebind_ = true; }
    bool Ok() const { return listen_ != INVALID_SOCKET && upstream_ != INVALID_SOCKET; }
    std::uint16_t UpstreamPort() const { return upstream_port_.load(); }

    // After the first Rebind(): datagrams client->server, and server->client replies that arrived
    // on the new socket (server learned the new address) or on an old one (it still uses the old).
    std::uint64_t ForwardedAfterRebind() const { return forwarded_after_rebind_.load(); }
    std::uint64_t RepliesViaNew() const { return replies_new_.load(); }
    std::uint64_t RepliesViaOld() const { return replies_old_.load(); }

private:
    static SOCKET Open(std::uint16_t port) {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            return s;
        }
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        BOOL off = FALSE;
        DWORD ret = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &ret, nullptr, nullptr);
        return s;
    }

    static std::uint16_t LocalPort(SOCKET s) {
        sockaddr_in a{};
        int len = sizeof(a);
        getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
        return ntohs(a.sin_port);
    }

    void Run() {
        char buf[65536];
        sockaddr_in client{};
        int client_len = 0;
        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port_);
        server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        upstream_port_ = LocalPort(upstream_);
        bool rebound = false;

        while (!stop_) {
            if (rebind_.exchange(false)) {
                if (old_ != INVALID_SOCKET) {
                    closesocket(old_);
                }
                old_ = upstream_;
                upstream_ = Open(0);
                upstream_port_ = LocalPort(upstream_);
                rebound = true;
            }
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(listen_, &readable);
            FD_SET(upstream_, &readable);
            if (old_ != INVALID_SOCKET) {
                FD_SET(old_, &readable);
            }
            timeval tv{0, 20000}; // 20 ms: bounds the latency of stop_/rebind_ only
            if (select(0, &readable, nullptr, nullptr, &tv) <= 0) {
                continue;
            }
            if (FD_ISSET(listen_, &readable)) {
                for (;;) {
                    sockaddr_in from{};
                    int from_len = sizeof(from);
                    const int n = recvfrom(listen_, buf, sizeof(buf), 0,
                                           reinterpret_cast<sockaddr*>(&from), &from_len);
                    if (n <= 0) {
                        break;
                    }
                    client = from;
                    client_len = from_len;
                    sendto(upstream_, buf, n, 0, reinterpret_cast<sockaddr*>(&server), sizeof(server));
                    if (rebound) {
                        ++forwarded_after_rebind_;
                    }
                }
            }
            for (SOCKET s : {upstream_, old_}) {
                if (s == INVALID_SOCKET || !FD_ISSET(s, &readable)) {
                    continue;
                }
                for (;;) {
                    const int n = recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr);
                    if (n <= 0) {
                        break;
                    }
                    if (client_len > 0) {
                        sendto(listen_, buf, n, 0, reinterpret_cast<sockaddr*>(&client), client_len);
                    }
                    if (rebound && s == upstream_) {
                        ++replies_new_;
                    } else if (rebound) {
                        ++replies_old_;
                    }
                }
            }
        }
    }

    std::uint16_t server_port_;
    SOCKET listen_{INVALID_SOCKET};
    SOCKET upstream_{INVALID_SOCKET};
    SOCKET old_{INVALID_SOCKET};
    std::atomic<bool> stop_{false};
    std::atomic<bool> rebind_{false};
    std::atomic<std::uint16_t> upstream_port_{0};
    std::atomic<std::uint64_t> forwarded_after_rebind_{0};
    std::atomic<std::uint64_t> replies_new_{0};
    std::atomic<std::uint64_t> replies_old_{0};
    std::thread worker_;
};
