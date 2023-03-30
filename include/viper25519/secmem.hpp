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

#ifndef VIPER25519_SECMEM_HPP_
#define VIPER25519_SECMEM_HPP_

#include <sys/mman.h>

#include <algorithm>
#include <array>

namespace ed25519
{

template <class T, std::size_t Size>
struct SecureByteArray : public std::array<T, Size>
{
    static_assert(
        std::is_standard_layout<T>::value && std::is_trivial<T>::value,
        "Only POD types allowed"
    );
    static_assert(sizeof(T) == 1, "Only 1-byte types allowed");

    SecureByteArray()
    {
        mlock(std::array<T, Size>::data(), sizeof(T) * Size);
    }

    ~SecureByteArray()
    {
        char *bytes = reinterpret_cast<char *>(std::array<T, Size>::data());
        std::fill_n<volatile char *>(bytes, sizeof(T) * Size, 0);
        munlock(bytes, sizeof(T) * Size);
    }
}; // SecureByteArray

}  // namespace ed25519

#endif  // VIPER25519_SECMEM_HPP_