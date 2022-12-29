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

#include <sys/mman.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace ed25519
{

static constexpr size_t ED25519_KEY_SIZE = 32;
static constexpr size_t ED25519_EXTENDED_KEY_SIZE = 64;
static constexpr size_t ED25519_SIGNATURE_SIZE = 64;

// To-Do: rewrite this...
template <class T, std::size_t Size>
struct SecureByteArray : public std::array<T, Size>
{
    static_assert(
        std::is_standard_layout<T>::value && std::is_trivial<T>::value,
        "Only POD types allowed"
    );
    static_assert(sizeof(T) == 1, "Only 1-byte types allowed");

    SecureByteArray(void)
    {
        mlock(std::array<T, Size>::data(), sizeof(T) * Size);
    }

    ~SecureByteArray(void)
    {
        char *bytes = reinterpret_cast<char *>(std::array<T, Size>::data());
        std::fill_n<volatile char *>(bytes, sizeof(T) * Size, 0);
        munlock(bytes, sizeof(T) * Size);
    }
};

using KeyByteArray = SecureByteArray<uint8_t, ED25519_KEY_SIZE>;
using ExtKeyByteArray = SecureByteArray<uint8_t, ED25519_EXTENDED_KEY_SIZE>;

// Forward Declarations
class PrivateKey;
class PublicKey;
class ExtendedPrivateKey;

class PrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    KeyByteArray prv_;

    /// Make the default constructor private so that it can only be used
    /// internally.
    PrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 32 bytes that will be moved into the object.
    PrivateKey(std::span<const uint8_t> prv);

    /// @brief Return the private key as a secure byte vector.
    [[nodiscard]] auto bytes() const -> KeyByteArray;

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> PrivateKey;

    /// @brief Check key validity.
    [[nodiscard]] auto isValid() const -> bool;

    /// @brief Extend the Ed25519 key for inclusion in a BIP32-Ed25519 wallet.
    [[nodiscard]] auto extend() const -> ExtendedPrivateKey;

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const
        -> std::array<uint8_t, ED25519_SIGNATURE_SIZE>;

};  // PrivateKey

class PublicKey
{
  private:
    /// Public key byte array (unencrypted).
    std::array<uint8_t, ED25519_KEY_SIZE> pub_{};

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param pub An array of 32 bytes that will be moved into the object.
    constexpr PublicKey(std::array<uint8_t, ED25519_KEY_SIZE> pub) : pub_{pub}
    {
    }

    /// @brief Construct a key object from a span of key bytes.
    /// @param pub A span of 32 bytes that will be moved into the object.
    PublicKey(std::span<const uint8_t> pub);

    /// @brief Return the public key as a byte vector.
    [[nodiscard]] auto bytes() const -> std::array<uint8_t, ED25519_KEY_SIZE>;

    /// @brief Verify a signature using the public key.
    /// @param msg A span of bytes (uint8_t) representing the original message.
    /// @param sig A span of 64 bytes (uint8_t) representing the signature.
    [[nodiscard]] auto verifySignature(
        std::span<const uint8_t> msg, std::span<const uint8_t> sig
    ) const -> bool;

};  // PublicKey

class ExtendedPrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    ExtKeyByteArray prv_;

  public:
    ExtendedPrivateKey(std::span<const uint8_t> prv);

    /// @brief Return the private key as a secure byte vector.
    [[nodiscard]] auto bytes() const -> ExtKeyByteArray;

    /// Factory method to create a new Ed25519 private key from a
    /// cryptographically secure random number generator.
    [[nodiscard]] static auto generate() -> ExtendedPrivateKey;

    /// @brief Check key validity.
    [[nodiscard]] auto isValid() const -> bool;

    /// @brief Derive the public key paired with this private key.
    [[nodiscard]] auto publicKey() const -> PublicKey;

    /// @brief Generate a message signature from the private key.
    /// @param msg A span of bytes (uint8_t) representing the message to sign.
    [[nodiscard]] auto sign(std::span<const uint8_t> msg) const
        -> std::array<uint8_t, ED25519_SIGNATURE_SIZE>;

};  // ExtendedPrivateKey

}  // namespace ed25519

#endif  // _VIPER_ED25519_HPP_