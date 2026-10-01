// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <mutex>
#include <utility>
#include <vector>

namespace BBCoop::Core {

/// Multi-producer queue drained by a single consumer (the game thread). Never blocks the
/// consumer for longer than a swap; producers get `false` when the queue is full.
template <typename T>
class BoundedTaskQueue {
public:
    explicit BoundedTaskQueue(std::size_t capacity) : capacity_(capacity) {}

    bool Push(T item) {
        std::scoped_lock lock(mutex_);
        if (items_.size() >= capacity_) {
            return false;
        }
        items_.push_back(std::move(item));
        return true;
    }

    std::size_t Drain(std::vector<T>& out) {
        std::vector<T> taken;
        {
            std::scoped_lock lock(mutex_);
            taken.swap(items_);
        }
        const auto count = taken.size();
        for (auto& item : taken) out.push_back(std::move(item));
        return count;
    }

    std::size_t Size() const {
        std::scoped_lock lock(mutex_);
        return items_.size();
    }

private:
    mutable std::mutex mutex_;
    std::vector<T> items_;
    std::size_t capacity_;
};

} // namespace BBCoop::Core
