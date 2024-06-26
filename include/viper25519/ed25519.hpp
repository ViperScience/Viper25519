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

#ifndef VIPER25519_ED25519_HPP_
#define VIPER25519_ED25519_HPP_

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>
#include <viper25519/secmem.hpp>

/// @brief Root namespace for the Ed25519 classes.
namespace ed25519
{

static constexpr size_t ED25519_KEY_SIZE = 32;
static constexpr size_t ED25519_EXTENDED_KEY_SIZE = 64;
static constexpr size_t ED25519_SIGNATURE_SIZE = 64;

using KeyByteArray = SecureByteArray<uint8_t, ED25519_KEY_SIZE>;
using PubKeyByteArray = std::array<uint8_t, ED25519_KEY_SIZE>;
using ExtKeyByteArray = SecureByteArray<uint8_t, ED25519_EXTENDED_KEY_SIZE>;

// Forward Declarations
class PrivateKey;
class PublicKey;
class ExtendedPrivateKey;

/// @brief Represent an Ed25519 private key.
class PrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    KeyByteArray prv_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    PrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 32 bytes that will be moved into the object.
    /// @note The input may still contain a valid key after the move and must
    /// be wiped by the calling code.
    explicit PrivateKey(std::span<const uint8_t, ED25519_KEY_SIZE> prv);

    /// @brief Return a constant reference to the private key secure byte
    /// array.
    [[nodiscard]] constexpr auto bytes() const -> const KeyByteArray&
    {
        return this->prv_;
    }

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

/// @brief Represent an Ed25519 prublic key.
class PublicKey
{
  private:
    /// Public key byte array (unencrypted).
    PubKeyByteArray pub_{};

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param pub An array of 32 bytes that will be copied into the object.
    explicit PublicKey(std::span<const uint8_t, ED25519_KEY_SIZE> pub);

    /// @brief Return a constant reference to the public key byte array.
    [[nodiscard]] constexpr auto bytes() const -> const PubKeyByteArray&
    {
        return this->pub_;
    }

    /// @brief Verify a signature using the public key.
    /// @param msg A span of bytes (uint8_t) representing the original message.
    /// @param sig A span of 64 bytes (uint8_t) representing the signature.
    [[nodiscard]] auto verifySignature(
        std::span<const uint8_t> msg,
        std::span<const uint8_t, ED25519_SIGNATURE_SIZE> sig
    ) const -> bool;

    /// @brief Add two public keys as curve25519 points.
    /// Add two public keys as two points on the elliptic curve 25519. This is
    /// useful during child key derivation when the keys are part of BIP32 style
    /// wallets.
    /// @param rhs The public key that will be added to the object.
    /// @returns A public key that is the result of the summation.
    [[nodiscard]] auto pointAdd(const PublicKey& rhs) const -> PublicKey;

};  // PublicKey

/// @brief Represent an extended Ed25519 private key.
class ExtendedPrivateKey
{
  private:
    /// Private key byte array (unencrypted)
    ExtKeyByteArray prv_{};

    /// Make the default constructor private so that it can only be used
    /// internally.
    ExtendedPrivateKey() = default;

  public:
    /// @brief Construct a key object from a span of key bytes.
    /// @param prv A span of 64 bytes that will be moved into the object.
    /// @note The input may still contain a valid key after the move and must
    /// be wiped by the calling code.
    explicit ExtendedPrivateKey(
        std::span<const uint8_t, ED25519_EXTENDED_KEY_SIZE> prv
    );

    /// @brief Return a constant reference to the private key secure byte
    /// array.
    [[nodiscard]] constexpr auto bytes() const -> const ExtKeyByteArray&
    {
        return this->prv_;
    }

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

    /// @brief Add the lower bytes of two secret keys as scalar values.
    /// Add the lower 32 bytes of two extended secret keys as two large scalars.
    /// The result is a 32 byte array. This may be used during child key
    /// derivation when the keys are part of BIP32 style wallets.
    /// @param rhs The secret key that will be added to the key within the
    /// object.
    /// @returns A 32-byte array containing the result of the summation.
    [[nodiscard]] auto scalerAddLowerBytes(const ExtendedPrivateKey& rhs) const
        -> std::array<uint8_t, 32>;

};  // ExtendedPrivateKey

}  // namespace ed25519

#endif  // VIPER25519_ED25519_HPP_