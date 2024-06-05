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

#ifndef VIPER25519_KES25519_HPP_
#define VIPER25519_KES25519_HPP_

// Standard Library Headers
#include <array>
#include <cmath>
#include <concepts>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

// Third-Party Headers
#include <botan/hash.h>
#include <botan/mem_ops.h>

// Viper25519 Headers
#include <viper25519/ed25519.hpp>
#include <viper25519/secmem.hpp>

namespace ed25519
{

// Function to convert a 32 bit integer to 4 bytes using Big Endian.
inline auto u32_to_be(uint32_t value) -> std::array<uint8_t, 4>
{
    std::array<uint8_t, 4> bytes;
    bytes[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    bytes[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    bytes[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(value & 0xFF);
    return bytes;
}

// Function to convert four Big Endian bytes to a 32 bit integer.
inline auto be_to_u32(std::span<const uint8_t> bytes) -> uint32_t
{
    if (bytes.size() != 4)
    {
        throw std::invalid_argument("bytes must be of length 4");
    }
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

// Function to convert a 64 bit integer to 8 bytes using Big Endian.

// Function to convert a 4 byte array to a 32 bit integer using Big Endian.

// A key evolving signatures implementation based on
// "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
// by Tal Malkin, Daniele Micciancio and Sara Miner
// <https://eprint.iacr.org/2001/034>
//
// Specfically we do the binary sum composition directly as in the paper, and
// then use that in a nested\/recursive fashion to construct up to a 7-level
// deep binary tree version.
//
// We provide two different implementations in this crate, to provide
// compatibility with Cardano's different eras. The first, `SumKes`, is a
// trivial construction, while the second, `SumCompactKes`, is a version with a
// more compact signature.
//
// Consider the following Merkle tree:
//
// ```ascii
//        (A)
//      /    |
//   (B)     (C)
//   / \     / |
// (D) (E) (F) (G)
//      ^
//  0   1   2   3
// ```
//
// The caret points at leaf node E, indicating that the current period is 1.
// The signatures for leaf nodes D through G all contain their respective
// DSIGN keys.
//
// In the naive `SumKes` signatures the signature for branch node B holds
// the signature for node E, and the VerKeys for nodes D and E. The signature
// for branch node A (the root node), the signature for node B and the
// VerKeys for nodes B and C. In other words, the number of individual hashes
// to be stored equals the depth of the Merkle tree.
//
// Instead, the more efficient `SumCompactKes` gets rid of some redundant data
// of the signature. In particular, the signature for branch node B only holds
// the signature for node E, and the VerKey for node D. It can reconstruct its
// own VerKey from these two. The signature for branch node A (the root node),
// then, only contains the VerKey for node C, and the signature for node B. In
// other words, the number of individual hashes to be stored equals the depth
// of the Merkle tree.

/// Maxium supported KES depth.
inline constexpr size_t MAX_KES_DEPTH = 7;

/// Define a concept for non-type unsigned integer values up to MAX_KES_DEPTH.
template <auto Value>
concept KesValidDepth = Value >= 0 && Value <= MAX_KES_DEPTH;

/// Restrain depth to zero.
template <auto Value>
concept KesDepth0 = KesValidDepth<Value> && Value == 0;

/// Restrain depth to non-zero.
template <auto Value>
concept KesDepthN0 = KesValidDepth<Value> && Value != 0;

/// Structure that represents the depth of the binary tree.
struct KesDepth
{
    const uint32_t value;

    constexpr KesDepth(uint32_t v) : value(v) {}
    constexpr operator uint32_t() const { return value; }
    constexpr auto operator==(const KesDepth& d) -> bool
    {
        return value == d.value;
    }

    constexpr auto get_value() const -> uint32_t { return value; }

    /// Compute the total number of signatures one can generate with the given
    /// `KesDepth`
    constexpr auto total() const -> uint32_t
    {
        return static_cast<uint32_t>(::lround(::pow(2, this->value)));
    }

    /// Compute half of the total number of signatures one can generate with the
    /// given `KesDepth`
    constexpr auto half() const -> uint32_t
    {
        if (this->value <= 0) throw std::runtime_error("KES depth 0");
        return static_cast<uint32_t>(::lround(::pow(2, this->value - 1)));
    }

    /// Returns a new `KesDepth` value with one less depth as `self`.
    auto decr() const -> KesDepth
    {
        if (this->value <= 0) throw std::runtime_error("KES depth 0");
        return KesDepth(this->value - 1);
    }

    /// Returns a new `Depth` value with one more depth as `self`.
    auto incr() const -> KesDepth { return KesDepth(this->value + 1); }
};

/// Utilities for the Seed of a KES scheme.
struct KesSeed
{
    /// Byte representation size of a `KesSeed`.
    static constexpr size_t size = KEY_SIZE;

    /// Function that takes as input a mutable span, splits it into two, and
    /// overwrites the input with zeros.
    /// @param seed 32 byte seed (size enforced at compile time).
    /// @param left_split Span of 32 bytes to be filled with the first split.
    /// @param right_split Span of 32 bytes to be filled with the second split.
    /// @return A pair of 32 byte secure arrays.
    static auto split(
        std::span<uint8_t, KesSeed::size> seed,
        std::span<uint8_t, KesSeed::size> left_split,
        std::span<uint8_t, KesSeed::size> right_split
    ) -> void;

};  // KesSeed

/// KES public key, which is represented as an array of bytes.
/// @note A `PublicKey` is the output of a Blake2b hash.
class KesPublicKey
{
  public:
    static constexpr size_t size = PUBLIC_KEY_SIZE;

    explicit KesPublicKey(std::span<const uint8_t, PUBLIC_KEY_SIZE> pub)
    {
        std::copy_n(pub.begin(), pub.size(), this->pub_.begin());
    }

    /// @brief Return a constant reference to the public key bytes.
    [[nodiscard]] constexpr auto bytes() const
        -> const std::array<uint8_t, size>&
    {
        return this->pub_;
    }

    /// @brief Hash two public keys using Blake2b.
    auto hash_pair(const KesPublicKey& other) const -> KesPublicKey;

  private:
    std::array<uint8_t, size> pub_;
};

template <size_t Depth>
    requires KesValidDepth<Depth>
class SumKesSignature
{
  public:
    /// Size of the signature in bytes.
    static constexpr size_t size =
        SIGNATURE_SIZE + Depth * (PUBLIC_KEY_SIZE * 2);

    explicit SumKesSignature(std::span<const uint8_t> bytes)
    {
        if (bytes.size() != SumKesSignature<Depth>::size)
        {
            throw std::runtime_error(
                "Invalid byte string size: " + std::to_string(bytes.size())
            );
        }
        std::copy_n(bytes.begin(), size, this->data_.begin());
    }  // SumKesSignature

    [[nodiscard]] constexpr auto bytes() const
        -> const std::array<uint8_t, SumKesSignature<Depth>::size>&
    {
        return this->data_;
    }

    /// Verify the signature
    auto verify(
        uint32_t period, const KesPublicKey& pk, std::span<const uint8_t> msg
    ) const -> bool
        requires KesDepth0<Depth>
    {
        auto pub = PublicKey(pk.bytes());
        return pub.verifySignature(msg, this->data_);
    }  // verify

    auto verify(
        uint32_t period, const KesPublicKey& pk, std::span<const uint8_t> msg
    ) const -> bool
        requires KesDepthN0<Depth>
    {
        const auto offset0 = SumKesSignature<Depth>::size - 2 * PUBLIC_KEY_SIZE;
        const auto lhs_pk = KesPublicKey(std::span<const uint8_t>(this->data_)
                                             .subspan(offset0, PUBLIC_KEY_SIZE)
                                             .first<PUBLIC_KEY_SIZE>());
        const auto offset1 = SumKesSignature<Depth>::size - PUBLIC_KEY_SIZE;
        const auto rhs_pk = KesPublicKey(std::span<const uint8_t>(this->data_)
                                             .subspan(offset1, PUBLIC_KEY_SIZE)
                                             .first<PUBLIC_KEY_SIZE>());

        if (lhs_pk.hash_pair(rhs_pk).bytes() != pk.bytes())
        {
            throw std::invalid_argument("Invalid hash comparison.");
        }

        const auto sigma = SumKesSignature<Depth - 1>(
            std::span<const uint8_t>(this->data_)
                .first<SumKesSignature<Depth - 1>::size>()
        );

        const auto depth = KesDepth(Depth);
        if (period < depth.half())
        {
            return sigma.verify(period, lhs_pk, msg);
        }

        return sigma.verify(period - depth.half(), rhs_pk, msg);
    }  // verify

    auto verify(uint32_t period, const KesPublicKey& pk, std::string_view msg)
        const -> bool
    {
        const auto msg_bytes =
            std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size());
        return this->verify(period, pk, msg_bytes);
    }  // sign

  private:
    std::array<uint8_t, size> data_;
};

template <size_t Depth>
    requires KesValidDepth<Depth>
class SumKesPrivateKey
{
  public:
    /// Size of the secret key in bytes.
    static constexpr size_t size =
        KEY_SIZE + Depth * (32 + (PUBLIC_KEY_SIZE * 2));

    SumKesPrivateKey() = delete;

    /// @brief Construct a KES key object from a span of key bytes.
    /// @param bytes A span of bytes that will be moved into the object.
    /// @note The calling code is responsible for the lifetime of the input.
    /// Furthermore, the input may still contain a valid key after the move
    /// and must be wiped by the calling code.
    explicit SumKesPrivateKey(std::span<uint8_t> bytes)
    {
        if ((bytes.size() != SumKesPrivateKey<Depth>::size) &&
            (bytes.size() != SumKesPrivateKey<Depth>::size + 4))
        {
            throw std::runtime_error(
                "Invalid byte string size: " + std::to_string(bytes.size())
            );
        }
        std::move(bytes.begin(), bytes.end(), this->prv_.begin());
    }  // SumKesPrivateKey<Depth>::SumKesPrivateKey<Depth>
    // need to make one that takes size only bytes and a period int

    /// @brief Key generation.
    /// @param key_buffer A buffer of size `SumKesPrivateKey<Depth>::size`
    /// plus four bytes to store period as a 32 bit integer .
    /// @param seed A buffer of size `KesSeed::size` containing the seed.
    /// @return A pair of `SumKesPrivateKey<Depth>` and `KesPublicKey`.
    /// @note The calling code is responsible for the lifetime of the input
    /// buffer. Furthermore, the input may still contain a valid key after
    /// the move and must be wiped by the calling code. Using a
    /// SecureByteArray should take care of this.
    [[nodiscard]] static auto keygen(
        std::span<uint8_t, SumKesPrivateKey<Depth>::size + 4> key_buffer,
        std::span<uint8_t, KesSeed::size> seed
    ) -> std::pair<SumKesPrivateKey<Depth>, KesPublicKey>
        requires KesDepth0<Depth>
    {
        if (key_buffer.size() != SumKesPrivateKey<Depth>::size + 4)
        {
            throw std::runtime_error("Invalid buffer size.");
        }
        if (seed.size() != KesSeed::size)
        {
            throw std::runtime_error("Invalid input seed size.");
        }

        const auto secret_key = ed25519::PrivateKey(seed);
        const auto public_key = secret_key.publicKey();
        std::copy_n(secret_key.bytes().begin(), 32, key_buffer.data());
        Botan::secure_scrub_memory(seed.data(), seed.size());

        // We write the period to the main data.
        std::copy_n(
            u32_to_be(0).data(), 4,
            key_buffer.data() + SumKesPrivateKey<Depth>::size
        );

        return {
            SumKesPrivateKey<Depth>(key_buffer),
            KesPublicKey(public_key.bytes())
        };
    }

    [[nodiscard]] static auto keygen(
        std::span<uint8_t, SumKesPrivateKey<Depth>::size + 4> key_buffer,
        std::span<uint8_t, KesSeed::size> seed
    ) -> std::pair<SumKesPrivateKey<Depth>, KesPublicKey>
        requires KesDepthN0<Depth>
    {
        if (key_buffer.size() != SumKesPrivateKey<Depth>::size + 4)
        {
            throw std::runtime_error("Invalid buffer size.");
        }
        if (seed.size() != KesSeed::size)
        {
            throw std::runtime_error("Invalid input seed size.");
        }

        auto pk = SumKesPrivateKey<Depth>::keygen_buffer(
            {key_buffer.data(), SumKesPrivateKey<Depth>::size}, seed
        );

        // We write the period to the main data.
        std::copy_n(
            u32_to_be(0).data(), 4,
            key_buffer.data() + SumKesPrivateKey<Depth>::size
        );

        return {SumKesPrivateKey<Depth>(key_buffer), pk};
    }

    static auto keygen_buffer(
        std::span<uint8_t> in_buffer,
        std::optional<std::span<uint8_t, KesSeed::size>> op_seed
    ) -> KesPublicKey
        requires KesDepth0<Depth>
    {
        const auto secret = [&]() -> PrivateKey
        {
            if (op_seed.has_value())
            {
                if ((*op_seed).size() != SumKesPrivateKey<0>::size)
                {
                    throw std::runtime_error("Invalid input seed size.");
                }
                auto sk = PrivateKey(*op_seed);
                Botan::secure_scrub_memory(
                    (*op_seed).data(), (*op_seed).size()
                );
                return sk;
            }
            if (in_buffer.size() != SumKesPrivateKey<0>::size + KesSeed::size)
            {
                throw std::runtime_error("Input size is incorrect.");
            }
            const auto seed = std::span<uint8_t>(
                in_buffer.data() + SumKesPrivateKey<0>::size, KesSeed::size
            );
            auto sk = PrivateKey(seed.first<KesSeed::size>());
            Botan::secure_scrub_memory(seed.data(), seed.size());
            return sk;
        }();

        std::copy_n(
            secret.bytes().begin(), SumKesPrivateKey<0>::size, in_buffer.begin()
        );

        auto public_key = secret.publicKey();
        return KesPublicKey(public_key.bytes());
    }  // keygen_buffer

    static auto keygen_buffer(
        std::span<uint8_t> in_buffer,
        std::optional<std::span<uint8_t, KesSeed::size>> op_seed
    ) -> KesPublicKey
        requires KesDepthN0<Depth>
    {
        // Split the seed
        auto r0 = KeyByteArray();
        auto seed = KeyByteArray();

        if (op_seed.has_value())
        {
            if (in_buffer.size() != SumKesPrivateKey<Depth>::size)
            {
                throw std::runtime_error("Invalid buffer size.");
            }
            if ((*op_seed).size() != KesSeed::size)
            {
                throw std::runtime_error("Invalid input seed size.");
            }

            KesSeed::split(*op_seed, r0, seed);
        }
        else
        {
            if (in_buffer.size() !=
                (SumKesPrivateKey<Depth>::size + KesSeed::size))
            {
                throw std::runtime_error("Invalid buffer size.");
            }

            const auto buf_seed = std::span<uint8_t>(
                in_buffer.data() + SumKesPrivateKey<Depth>::size, KesSeed::size
            );
            KesSeed::split(buf_seed.first<KesSeed::size>(), r0, seed);
        }

        // We copy the seed before overwriting with zeros (in the `keygen`
        // call).
        std::copy(
            seed.begin(), seed.end(),
            in_buffer.begin() + SumKesPrivateKey<Depth - 1>::size
        );

        // Buffer for temp key
        auto temp_buffer =
            SecureByteArray<uint8_t, SumKesPrivateKey<Depth - 1>::size + 4>{};

        const auto pk_0 = SumKesPrivateKey<Depth - 1>::keygen_buffer(
            in_buffer.first<SumKesPrivateKey<Depth - 1>::size>(), r0
        );
        const auto keys =
            SumKesPrivateKey<Depth - 1>::keygen(temp_buffer, seed);
        const auto pk_1 = keys.second;

        // Write the public keys to the main data.
        std::copy_n(
            pk_0.bytes().begin(), PUBLIC_KEY_SIZE,
            in_buffer.begin() + SumKesPrivateKey<Depth - 1>::size +
                KesSeed::size
        );
        std::copy_n(
            pk_1.bytes().begin(), PUBLIC_KEY_SIZE,
            in_buffer.begin() + SumKesPrivateKey<Depth - 1>::size +
                KesSeed::size + KesPublicKey::size
        );

        return pk_0.hash_pair(pk_1);
    }  // keygen_buffer

    /// Factory method to create a new set of KES keys from a
    /// cryptographically secure random number generator.
    /// @return A pair of the private key and the public key.
    [[nodiscard]] static auto generate()
        -> std::pair<SumKesPrivateKey<Depth>, KesPublicKey>
    {
        // Create a seed from an Ed25519 private key.
        // The private key will securely clean up when it is deallocated. We
        // need to make a mutable copy to pass to the key generation
        // function. Use a secure array so that the seed cannot be leaked.
        const auto key = PrivateKey::generate();
        const auto seed = key.bytes();
        auto mut_seed = KeyByteArray();
        std::copy_n(seed.begin(), seed.size(), mut_seed.begin());

        // Provide a mutable buffer that will be filled with the KES key
        // components. Use a secure array so that it is securely wiped after
        // key generation.
        auto mut_buffer =
            SecureByteArray<uint8_t, SumKesPrivateKey<Depth>::size + 4>();

        return SumKesPrivateKey<Depth>::keygen(mut_buffer, mut_seed);
    }  // generate

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> KesPublicKey
        requires KesDepthN0<Depth>
    {
        const auto offset0 =
            SumKesPrivateKey<Depth>::size - 2 * PUBLIC_KEY_SIZE;
        const auto pk0 = KesPublicKey(std::span<const uint8_t>(this->prv_)
                                          .subspan(offset0, PUBLIC_KEY_SIZE)
                                          .first<PUBLIC_KEY_SIZE>());
        const auto offset1 = SumKesPrivateKey<Depth>::size - PUBLIC_KEY_SIZE;
        const auto pk1 = KesPublicKey(std::span<const uint8_t>(this->prv_)
                                          .subspan(offset1, PUBLIC_KEY_SIZE)
                                          .first<PUBLIC_KEY_SIZE>());
        return pk0.hash_pair(pk1);
    }  // publicKey

    /// @brief Zero out the private key.
    auto drop() -> void
    {
        Botan::secure_scrub_memory(this->prv_.data(), this->prv_.size());
    }  // drop

    /// @brief Return a constant reference to the private key bytes.
    /// The encoding returns the following array of size `Self::SIZE + 4`:
    /// ( sk_{-1} || seed || self.lhs_pk || self.rhs_pk || period )
    /// where `sk_{-1}` is the secret secret key of lower depth.
    /// Note that the period is only included in the last layer.
    [[nodiscard]] constexpr auto bytes() const
        -> const SecureByteArray<uint8_t, SumKesPrivateKey<Depth>::size + 4>&
    {
        return this->prv_;
    }

    static auto update_buffer(std::span<uint8_t> in_buffer, uint32_t period)
        -> void
        requires KesDepth0<Depth>
    {
        throw std::runtime_error(
            "The key cannot be furhter updated (the period has reached the "
            "maximum allowed)"
        );
    }

    static auto update_buffer(std::span<uint8_t> in_buffer, uint32_t period)
        -> void
        requires KesDepthN0<Depth>
    {
        const auto depth = KesDepth(Depth);
        const auto next_period = period + 1;

        if (next_period == depth.total())
        {
            throw std::runtime_error(
                "The key cannot be furhter updated (the period has reached "
                "the "
                "maximum allowed)"
            );
        }

        if (next_period < depth.half())
        {
            SumKesPrivateKey<Depth - 1>::update_buffer(
                in_buffer.first<SumKesPrivateKey<Depth - 1>::size>(), period
            );
        }
        else if (next_period == depth.half())
        {
            // Wipe the seed for the current period
            SumKesPrivateKey<Depth - 1>::keygen_buffer(
                in_buffer.first<SumKesPrivateKey<Depth - 1>::size + KEY_SIZE>(),
                std::nullopt
            );
        }
        else if (next_period > depth.half())
        {
            SumKesPrivateKey<Depth - 1>::update_buffer(
                in_buffer.first<SumKesPrivateKey<Depth - 1>::size>(),
                period - depth.half()
            );
        }
    }  // update_buffer

    auto update() -> void
        requires KesDepth0<Depth>
    {
        throw std::runtime_error(
            "The key cannot be furhter updated (the period has reached the "
            "maximum allowed)"
        );
    }  // update

    /// @brief Update the key to the next period.
    /// @note This function mutates the key object.
    auto update() -> void
        requires KesDepthN0<Depth>
    {
        const auto current_period = this->period();
        SumKesPrivateKey<Depth>::update_buffer(this->prv_, current_period);
        this->period_ = current_period + 1;  // use only this in the future
        std::copy_n(                         // get rid of this eventually
            u32_to_be(current_period + 1).data(), 4,
            this->prv_.data() + SumKesPrivateKey<Depth>::size
        );
    }  // update

    /// @brief Return the current period of the secret key.
    [[nodiscard]] auto period() -> size_t
        requires KesDepth0<Depth>
    {
        return 0;
    }

    [[nodiscard]] auto period() -> size_t
        requires KesDepthN0<Depth>
    {
        return be_to_u32(std::span<const uint8_t>{
            this->prv_.data() + SumKesPrivateKey<Depth>::size, 4
        });
    }

    static auto sign_from_buffer(
        std::span<const uint8_t> in_buffer, std::span<const uint8_t> msg
    ) -> SumKesSignature<Depth>
        requires KesDepth0<Depth>
    {
        if (in_buffer.size() != KEY_SIZE)
        {
            throw std::invalid_argument("Invalid key size.");
        }
        const auto skey = PrivateKey(in_buffer.first<KEY_SIZE>());
        return SumKesSignature<Depth>(skey.sign(msg));
    }  // sign_from_buffer

    // sig(depth-1) || pk0 || pk1
    static auto sign_from_buffer(
        std::span<const uint8_t> in_buffer, std::span<const uint8_t> msg
    ) -> SumKesSignature<Depth>
        requires KesDepthN0<Depth>
    {
        auto sig_bytes = std::array<uint8_t, SumKesSignature<Depth>::size>();

        // Recursively get the signature from the next lowest key depth.
        auto sigma = SumKesPrivateKey<Depth - 1>::sign_from_buffer(
            in_buffer.first<SumKesPrivateKey<Depth - 1>::size>(), msg
        );
        std::copy(
            sigma.bytes().begin(), sigma.bytes().end(), sig_bytes.begin()
        );

        // Copy the first public key
        const auto offset0 = SumKesPrivateKey<Depth - 1>::size + KEY_SIZE;
        std::copy_n(
            in_buffer.subspan(offset0, PUBLIC_KEY_SIZE).begin(),
            PUBLIC_KEY_SIZE,
            sig_bytes.begin() + SumKesSignature<Depth - 1>::size
        );

        // Copy the second public key
        const auto offset1 = offset0 + PUBLIC_KEY_SIZE;
        std::copy_n(
            in_buffer.subspan(offset1, PUBLIC_KEY_SIZE).begin(),
            PUBLIC_KEY_SIZE,
            sig_bytes.begin() + SumKesSignature<Depth - 1>::size +
                PUBLIC_KEY_SIZE
        );

        return SumKesSignature<Depth>(sig_bytes);
    }  // sign_from_buffer

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to
    /// sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg
    ) const -> SumKesSignature<Depth>
        requires KesDepth0<Depth>
    {
        const auto skey = [&]() -> PrivateKey
        {
            auto key_bytes = KeyByteArray{};
            std::copy_n(
                this->prv_.data(), SumKesPrivateKey<Depth>::size,
                key_bytes.begin()
            );
            return PrivateKey(key_bytes);
        }();

        return SumKesSignature<Depth>(skey.sign(msg));
    }  // sign

    [[nodiscard]] auto sign(std::span<const uint8_t> msg
    ) const -> SumKesSignature<Depth>
        requires KesDepthN0<Depth>
    {
        return SumKesPrivateKey<Depth>::sign_from_buffer(this->bytes(), msg);
    }  // sign

    [[nodiscard]] auto sign(std::string_view msg
    ) const -> SumKesSignature<Depth>
    {
        const auto msg_bytes =
            std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size());
        return this->sign(msg_bytes);
    }  // sign

  private:
    SecureByteArray<uint8_t, size + 4> prv_;
    uint32_t period_ = 0;

};  // SumKesPrivateKey

}  // namespace ed25519

#endif  // VIPER25519_KES25519_HPP_