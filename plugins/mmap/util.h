/*******************************************************
 Copyright (C) 2023-2023 Georges Da Costa <georges.da-costa@irit.fr>

    This file is part of Mojitos.

    Mojitos is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Mojitos is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MojitO/S.  If not, see <https://www.gnu.org/licenses/>.

*******************************************************/

#ifndef _UTIL_H
#define _UTIL_H

#include <stdint.h>

#define CASSERT(predicate, file) _impl_CASSERT_LINE(predicate,__LINE__,file)

#define _impl_PASTE(a,b) a##b
#define _impl_CASSERT_LINE(predicate, line, file) \
    typedef char _impl_PASTE(assertion_failed_##file##_,line)[2*!!(predicate)-1];

#define UNUSED(expr) do { (void)(expr); } while (0)
#define PANIC(code, fmt, ...)                \
    do {                                     \
        fprintf(stderr, "Exit on error: ");  \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
        fprintf(stderr, "\n");               \
        exit(code);                          \
    } while (0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * @brief Substracts lhs by rhs, assuming that lhs is a cyclic increment from rhs,
 * meaning that if rhs is greater, lhs's value overflowed.
 * @param lhs
 * @param rhs
 * @return uint64_t
 */
uint64_t modulo_substraction(const uint64_t lhs, const uint64_t rhs);

#endif
