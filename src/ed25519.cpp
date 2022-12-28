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

// Standard Library Headers
#include <memory>
#include <stdexcept>

// Third-Party Library Headers
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/system_rng.h>

// Public Viper Ed25519 Headers
#include <ed25519-viper/curve25519.hpp>
#include <ed25519-viper/ed25519.hpp>

// Private Viper Ed25519 code
#include "utils.hpp"

using namespace ed25519;

PrivateKey::PrivateKey(std::span<const uint8_t> prv)
{
    if (prv.size() != ED25519_KEY_SIZE)
        throw std::invalid_argument("Not a valid Ed25519 key.");
    std::move(prv.begin(), prv.begin() + ED25519_KEY_SIZE, this->prv_.begin());
}  // PrivateKey::PrivateKey

auto PrivateKey::generate() -> PrivateKey
{
    // Use the Botan random number generator for generating the entropy.
    std::unique_ptr<Botan::RandomNumberGenerator> rng;
#if defined(BOTAN_HAS_SYSTEM_RNG)
    rng.reset(new Botan::System_RNG);
#else
    rng.reset(new Botan::AutoSeeded_RNG);
#endif

    // The randomly generated key should meet validity requirements within a
    // couple attempts, but we set a maximum number of tries here in order to
    // prevent an infinite loop. If the maximum retries are exceeded, this
    // probably indicates an issue with the random number generator anyway and
    // should not be used.
    auto max_retries = 10000UL;
    auto n_retries = 0UL;

    // Create the secret key
    auto skey_valid = false;
    auto skey = Botan::SecureVector<uint8_t>(ED25519_KEY_SIZE);
    do
    {
        if (n_retries > max_retries) throw std::runtime_error("RNG error");

        // Create a random 32-byte secret key.
        rng->randomize(skey.data(), ED25519_KEY_SIZE);

        // SHA-512 hash of the secret key
        const auto sha512 = Botan::HashFunction::create("SHA-512");
        sha512->update(skey.data(), ED25519_KEY_SIZE);
        auto keyhash = sha512->final();

        skey_valid = (keyhash[31] & 0b00100000) == 0;
        n_retries++;
    } while (!skey_valid);

    return PrivateKey(skey);
}  // PrivateKey::generate

auto PrivateKey::isValid() const -> bool
{
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(this->prv_.data(), ED25519_KEY_SIZE);
    auto keyhash = sha512->final();
    return (keyhash[31] & 0b00100000) == 0;
}  // PrivateKey::isValid

auto PrivateKey::extend() const -> ExtendedPrivateKey
{
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(this->prv_.data(), ED25519_KEY_SIZE);
    auto keyhash = sha512->final();

    // On the ed25519 scalar leftmost 32 bytes:
    //  * clear the lowest 3 bits
    //  * clear the highest bit
    //  * clear the 3rd highest bit
    //  * set the highest 2nd bit
    keyhash[0] &= 0b11111000;
    keyhash[31] &= 0b00011111;
    keyhash[31] |= 0b01000000;
    // Some implementations do not clear the third highest bit of the leftmost
    // 32 bytes but assume this is the case for a valid Ed25519 key. The
    // generate method enforces this but we do not enforce this check here.

    return ExtendedPrivateKey(keyhash);
}  // PrivateKey::extend

auto PrivateKey::publicKey() const -> PublicKey
{
    auto ext_key = this->extend();
    return ext_key.publicKey();
}  // PrivateKey::publicKey

auto PrivateKey::sign(std::span<const uint8_t> msg) const
    -> std::array<uint8_t, ED25519_SIGNATURE_SIZE>
{
    auto ext_key = this->extend();
    return ext_key.sign(msg);
}  // PrivateKey::sign

PublicKey::PublicKey(std::span<const uint8_t> pub)
{
    if (pub.size() != ED25519_KEY_SIZE)
        throw std::invalid_argument("Not a valid Ed25519 key.");
    std::move(pub.begin(), pub.begin() + ED25519_KEY_SIZE, this->pub_.begin());
}  // PublicKey::PublicKey

auto PublicKey::bytes() const -> std::array<uint8_t, ED25519_KEY_SIZE>
{
    auto copy = this->pub_;
    return copy;
}  // PublicKey::bytes

auto PublicKey::verifySignature(
    std::span<const uint8_t> msg, std::span<const uint8_t> sig
) const -> bool
{
    if (sig.size() != ED25519_SIGNATURE_SIZE)
        throw std::invalid_argument("Invalid signature size.");

    if (sig[63] & 224) throw std::invalid_argument("Invalid signature.");

    // This may also throw an exception
    const auto a = curve25519::ExtendedPoint::unpack(this->pub_);

    // hram = H(R,A,m)
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(sig.data(), 32);
    sha512->update(this->pub_.data(), this->pub_.size());
    sha512->update(msg.data(), msg.size());
    auto hash = sha512->final();
    auto hram = curve25519::bignum25519::expand256_modm(hash);

    // S
    auto s = curve25519::bignum25519::expand256_modm({sig.data() + 32, 32});

    // SB - H(R,A,m)A
    auto r = a.doubleScalarMultiple(hram, s);
    auto check_r = r.pack();  // 32 bytes

    // check that R = SB - H(R,A,m)A
    return mem_verify({sig.data(), 32}, check_r);
}  // PublicKey::verify

ExtendedPrivateKey::ExtendedPrivateKey(std::span<const uint8_t> prv)
{
    if (prv.size() != ED25519_EXTENDED_KEY_SIZE)
        throw std::invalid_argument("Not a valid extended Ed25519 key.");
    if ((prv[31] & 0b00100000) != 0)
        throw std::invalid_argument("Not a valid extended Ed25519 key.");
    std::move(
        prv.begin(), prv.begin() + ED25519_EXTENDED_KEY_SIZE, this->prv_.begin()
    );
}  // ExtendedPrivateKey::ExtendedPrivateKey

auto ExtendedPrivateKey::generate() -> ExtendedPrivateKey
{
    auto base_key = PrivateKey::generate();
    return base_key.extend();
}  // PrivateKey::generate

auto ExtendedPrivateKey::isValid() const -> bool
{
    return (
        ((this->prv_[0] & 0b00000111) == 0) &&
        ((this->prv_[31] & 0b00100000) == 0) &&
        ((this->prv_[31] & 0b10000000) == 0) &&
        ((this->prv_[31] & 0b01000000) == 0b01000000)
    );
}  // ExtendedPrivateKey::isValid

auto ExtendedPrivateKey::bytes() const -> ExtKeyByteArray
{
    auto copy = this->prv_;
    return copy;
}  // ExtendedPrivateKey::bytes

auto ExtendedPrivateKey::publicKey() const -> PublicKey
{
    // Expand the lower 32 bytes of the private key to large scalar
    auto kl = std::span<const uint8_t>{this->prv_.data(), 32};
    auto a = curve25519::bignum25519::expand256_modm(kl);

    // Perform a scalar multiplication of the curve basepoint B by the secret
    // key lower half.
    auto ab = curve25519::ExtendedPoint::multiplyBasepointByScalar(a);

    // Pack the public key result into a byte array
    return PublicKey(ab.pack());
}  // ExtendedPrivateKey::publicKey

auto ExtendedPrivateKey::sign(std::span<const uint8_t> msg) const
    -> std::array<uint8_t, ED25519_SIGNATURE_SIZE>
{
    // Derive the public key
    auto pk = this->publicKey().bytes();

    // r = H(aExt[32..64], m)
    const auto sha512 = Botan::HashFunction::create("SHA-512");
    sha512->update(this->prv_.data() + 32, 32);
    sha512->update(msg.data(), msg.size());
    auto hashr = sha512->final();
    auto r = curve25519::bignum25519::expand256_modm(hashr);

    // R = rB
    auto rb = curve25519::ExtendedPoint::multiplyBasepointByScalar(r);
    auto rs = rb.pack();

    // S = H(R,A,m)..
    sha512->update(rs.data(), rs.size());
    sha512->update(pk.data(), pk.size());
    sha512->update(msg.data(), msg.size());
    auto hram = sha512->final();
    auto s = curve25519::bignum25519::expand256_modm(hram);

    // S = H(R,A,m)a
    auto kl = std::span<const uint8_t>{this->prv_.data(), 32};
    auto a = curve25519::bignum25519::expand256_modm(kl);
    s = curve25519::bignum25519::mul256_modm(s, a);

    // S = (r + H(R,A,m)a)
    s = curve25519::bignum25519::add256_modm(s, r);

    // S = (r + H(R,A,m)a) mod L
    auto sbytes = curve25519::bignum25519::contract256_modm(s);

    // Return the complete signature
    auto sig = std::array<uint8_t, ED25519_SIGNATURE_SIZE>{};
    std::copy_n(rs.begin(), 32, sig.begin());
    std::copy_n(sbytes.begin(), 32, sig.begin() + 32);
    return sig;
}  // ExtendedPrivateKey::sign