// Copyright (c) 2024 Viper Science LLC
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

// Public Viper25519 Headers
#include <viper25519/kes25519.hpp>

// Third-Party Libraries
#include <botan/hash.h>

// Private Viper25519 code
#include "utils.hpp"

using namespace ed25519;

auto KesSeed::split(std::span<uint8_t, KesSeed::size> bytes)
    -> std::pair<SeedByteArray, SeedByteArray>
{
    auto left_seed = SecureByteArray<uint8_t, 32>{};
    auto right_seed = SecureByteArray<uint8_t, 32>{};

    static constexpr auto one = std::array<uint8_t, 1>{1};
    static constexpr auto two = std::array<uint8_t, 1>{2};

    const auto hasher = Botan::HashFunction::create("Blake2b(256)");
    hasher->update(one.data(), one.size());
    hasher->update(bytes.data(), bytes.size());
    hasher->final(left_seed.data());  // Hasher is reset here
    hasher->update(two.data(), two.size());
    hasher->update(bytes.data(), bytes.size());
    hasher->final(right_seed.data());

    Botan::secure_scrub_memory(bytes.data(), bytes.size());

    return std::make_pair(left_seed, right_seed);
}  // KesSeed::split

auto KesPublicKey::hash_pair(const KesPublicKey& other) const -> KesPublicKey
{
    const auto self_bytes = this->bytes();
    const auto other_bytes = other.bytes();
    const auto hasher = Botan::HashFunction::create("Blake2b(256)");
    hasher->update(self_bytes.data(), ED25519_KEY_SIZE);
    hasher->update(other_bytes.data(), ED25519_KEY_SIZE);
    auto out = hasher->final();
    return KesPublicKey(std::span(out).first<ED25519_KEY_SIZE>());
}  // KesPublicKey::hash_pair