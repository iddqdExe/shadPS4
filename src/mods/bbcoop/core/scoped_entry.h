// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

namespace BBCoop::Core {

/// Re-entrancy guard for code that only one thread runs (no atomics): the first scope takes the
/// flag, a scope entered while it is taken is refused (false) and leaves the flag alone, and the
/// scope that took it releases it on every path, exceptions included.
///
///     ScopedEntry entry(g_in_tick);
///     if (!entry) {
///         return; // nested call
///     }
class ScopedEntry {
public:
    explicit ScopedEntry(bool& flag) : flag_(flag), entered_(!flag) {
        if (entered_) {
            flag_ = true;
        }
    }
    ~ScopedEntry() {
        if (entered_) {
            flag_ = false;
        }
    }

    ScopedEntry(const ScopedEntry&) = delete;
    ScopedEntry& operator=(const ScopedEntry&) = delete;

    /// True when this scope took the flag.
    explicit operator bool() const {
        return entered_;
    }

private:
    bool& flag_;
    bool entered_;
};

} // namespace BBCoop::Core
