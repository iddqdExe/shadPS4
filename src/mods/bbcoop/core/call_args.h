// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <type_traits>

namespace BBCoop::Core {

/// What CallGame accepts as an argument: a type the System V calling convention passes in a
/// register as it is (integer, enum, pointer, floating point). A struct, a string or a
/// std::nullptr_t (pass a typed pointer) is refused at compile time.
template <typename T>
inline constexpr bool IsGameCallArg = std::is_integral_v<T> || std::is_enum_v<T> ||
                                      std::is_pointer_v<T> || std::is_floating_point_v<T>;

} // namespace BBCoop::Core
