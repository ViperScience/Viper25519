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

#ifndef _VIPER_ED25519_HPP_
#define _VIPER_ED25519_HPP_

#include <array>
#include <cstdint>
#include <span>
#include <sys/mman.h>

namespace ed25519
{

static constexpr size_t ED25519_KEY_SIZE = 32;
static constexpr size_t ED25519_EXTENDED_KEY_SIZE = 64;

// To-Do: rewrite this...
template<class T, std::size_t Size>
struct KeyArray : public std::array<T, Size>
{
    static_assert(std::is_pod<T>::value, "Only POD types allowed");
    static_assert(sizeof(T) == 1, "Only 1-byte types allowed");

    KeyArray(void) {
        mlock(std::array<T, Size>::data(), sizeof(T) * Size);
    }

    ~KeyArray(void) {
        char *bytes = reinterpret_cast<char *>(std::array<T, Size>::data());
        for (std::size_t i = 0; i < sizeof(T) * Size; i++)
            bytes[i] = 0;
        munlock(bytes, sizeof(T) * Size);
    }
};

using KeyBytes = KeyArray<uint8_t, ED25519_KEY_SIZE>;
using ExtKeyBytes = KeyArray<uint8_t, ED25519_EXTENDED_KEY_SIZE>;

// Forward Declarations
class PrivateKey;
class PublicKey;
class ExtendedPrivateKey;

class PrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    KeyBytes prv_;

    /// Make the default constructor private so that it can only be used
    /// internally.
    PrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 32 bytes that will be moved into the object. 
    PrivateKey(std::span<const uint8_t> prv);

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> PrivateKey;

    /// Check key validity.
    [[nodiscard]] auto isValid() const -> bool;

    /// Extend the Ed25519 key for inclusion in a BIP32-Ed25519 wallet.
    [[nodiscard]] auto extend() const -> ExtendedPrivateKey;

    /// Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// Generate a message signature from the private key.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const -> std::vector<uint8_t>;

}; // PrivateKey

class PublicKey
{
  private:
    /// Public key byte array (unencrypted).
    std::array<uint8_t, ED25519_KEY_SIZE> pub_{};

  public:
    constexpr PublicKey(std::array<uint8_t, ED25519_KEY_SIZE> pub)
        : pub_{pub}
    {
    }

    PublicKey(std::span<const uint8_t> pub);

    // verify signature

}; // PublicKey

class ExtendedPrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    ExtKeyBytes prv_;

  public:
    ExtendedPrivateKey(std::span<const uint8_t> prv);

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> ExtendedPrivateKey;

    /// Check key validity.
    [[nodiscard]] auto isValid() const -> bool;

    /// Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// Generate a message signature from the private key.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const -> std::vector<uint8_t>;

}; // ExtendedPrivateKey


}  // namespace ed25519

#endif  // _VIPER_ED25519_HPP_