# SPDX-FileCopyrightText: 2026 BB Co-op contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# SPIKE CODE (S6) - throwaway, see docs/spikes/S6-network-libraries.md. Do not build on this.

# FetchContent PATCH_COMMAND for GameNetworkingSockets v1.6.0 (run with the GNS source dir as cwd).
# OpenUDPSocketBoundToHost() opens the client socket of a direct-IP connection with no local address,
# i.e. bound to the wildcard address; GNS has no option for it. Bind it to 127.0.0.1 when the remote
# host is IPv4 loopback. A text replace (not git apply) so CRLF checkouts and re-runs are harmless.
set(_file "src/steamnetworkingsockets/clientlib/steamnetworkingsockets_socketthread.cpp")
file(READ "${_file}" _text)
if (_text MATCHES "BBCOOP SPIKE S6")
    return()
endif()
set(_old "errMsg, nullptr, &nAddressFamilies );")
string(FIND "${_text}" "${_old}" _at)
if (_at EQUAL -1)
    message(FATAL_ERROR "S6 GNS patch: anchor not found in ${_file}")
endif()
set(_new "errMsg, ( adrRemote.GetType() == k_EIPTypeV4 && adrRemote.IsLoopback() ) ? &s_bbcoopSpikeS6Loopback : nullptr, &nAddressFamilies ); /* BBCOOP SPIKE S6 */")
string(REPLACE "${_old}" "${_new}" _text "${_text}")
set(_fn "IBoundUDPSocket *OpenUDPSocketBoundToHost( const netadr_t &adrRemote, CRecvPacketCallback callback, SteamNetworkingErrMsg &errMsg )")
string(REPLACE "${_fn}"
    "static const SteamNetworkingIPAddr s_bbcoopSpikeS6Loopback = [] { SteamNetworkingIPAddr a; a.SetIPv4( 0x7f000001, 0 ); return a; }(); // BBCOOP SPIKE S6\n${_fn}"
    _text "${_text}")
file(WRITE "${_file}" "${_text}")
message(STATUS "S6 GNS patch: client sockets to a loopback remote bind 127.0.0.1")
