// Copyright (c) 2022 Viper Science LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef VIPER25519_UTILS_HPP_
#define VIPER25519_UTILS_HPP_

// Standard library headers
#include <cstdint>
#include <span>
#include <stdexcept>

// Third-party headers
#include "sodium.h"

namespace ed25519
{

/// Zero the contents of a span.
template <typename T>
auto secure_zero(std::span<T> input) -> void
{
    sodium_memzero(input.data(), input.size() * sizeof(T));
}

/// Copy and zero the contents of a span to an array.
template <typename T, std::size_t N>
auto copy_and_zero(std::span<T> input, std::array<T, N>& output) -> void
{
    static_assert(
        N >= input.size(),
        "Output array must be at least as large as the input span"
    );

    // Copy the contents from the input span to the output array
    std::memcpy(output.data(), input.data(), input.size() * sizeof(T));

    // Write zeros back to the input span
    sodium_memzero(input.data(), input.size() * sizeof(T));
}

/// Convert unsigned integer to Big Endian byte array.
constexpr auto to_be_bytes(uint64_t x) -> std::array<uint8_t, 8>
{
    std::array<uint8_t, 8> bytes;
    for (size_t i = 0; i < 8; ++i)
    {
        bytes[i] = (x >> (8 * i)) & 0xFF;
    }
    return bytes;
}  // to_be_bytes

/// Convert unsigned integer to Little Endian byte array.

/// Timing safe memory compare.
constexpr auto mem_verify(
    std::span<const uint8_t> x, std::span<const uint8_t> y
) -> bool
{
    if (x.size() != y.size())
        throw std::length_error("Input lengths must match.");
    size_t len = x.size();
    size_t differentbits = 0;
    auto xx = x.begin();
    auto yy = y.begin();
    while (len--) differentbits |= (*xx++ ^ *yy++);
    return (bool)(1 & ((differentbits - 1) >> 8));
}  // mem_verify

}  // namespace ed25519

#endif  // VIPER25519_UTILS_HPP_