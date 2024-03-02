# Viper25519
[![build](https://gitlab.com/viper-staking/viper25519/badges/main/pipeline.svg)](https://gitlab.com/viper-staking/viper25519/-/commits/main)
[![codecov](https://codecov.io/gl/viperscience/viper25519/branch/main/graph/badge.svg?token=B7F7UR16TG)](https://codecov.io/gl/viper-staking/viper25519)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/Language-C++-blue.svg)](https://gitlab.com/viper-staking/viper25519/-/graphs/main/charts)
[![C++ Standard](https://img.shields.io/badge/std-C++20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fviperscience.gitlab.io%2Fviper25519%2Findex.html)](https://viperscience.gitlab.io/viper25519/index.html)
[![Catalyst](https://img.shields.io/badge/catalyst-fund10-violet)](https://cardano.ideascale.com/c/idea/106219)

An implementation of the Ed25519 elliptic curve digital signature standard in
modern C++. The library is largley based on the popular 
[Ed25519-donna](https://github.com/floodyberry/ed25519-donna) constant 
time implementation with support for
[extended private keys](https://raw.githubusercontent.com/input-output-hk/adrestia/master/docs/static/Ed25519_BIP.pdf).

## Basic Usage
The Viper25519 library wraps the Ed25519 capability in three classes: 
`Ed25519PrivateKey`, `Ed25519PublicKey`, and `Ed25519ExtendedPrivateKey`. 
Examples of how to use these classes are demonstrated below. The examples assume
the following to be at the top of the source file.

    #include <viper25519/ed25519.hpp>
    using namespace ed25519; // key objects exist within this namespace

### Generating Keys

    // Create a standard Ed25519 private key.
    auto key = Ed25519PrivateKey::generate();

    // Extend to an Extended Ed25519 private key
    auto ext_key = key.extend();
    // Or create an extended key from scratch
    auto ext_key = Ed25519ExtendedPrivateKey::generate();

    // Derive the public key
    auto pub_key = key.publicKey();
    // Or from an extended key
    auto pub_key = ext_key.publicKey();

### Generating Signatures

    // Create a message of bytes to sign
    auto msg = std::vector<uint8_t>();
    // fill msg...

    // Create a signature of the message with the key
    auto sig = key.sign(msg);
    // Or
    auto sig = ext_key.sign(msg);

### Verifying Signatures

    auto check = pub.verifySignature(msg, sig);

### Loading Keys

Existing keys may also be loaded into the constructors of each object as a span of bytes.

    // Private key bytes may be loaded from any container type.
    auto pkey_bytes = std::array<uint8_t, 32>{...}; // <- load key bytes here
    auto ext_pkey_bytes = std::vector<uint8_t>(64);
    // fill ext_pkey_bytes ...

    auto key = Ed25519PrivateKey(pkey_bytes);
    auto ext_key = Ed25519ExtendedPrivateKey(ext_pkey_bytes);

### Verifiable Randome Functions (VRF)

VRF keys are Ed25519 keys and thus inherit functionality such as `sign` and `verifySignature`;
however, they have been extended with the following VRF capabilities (via the Cardano fork of the libsodium library):

* constructProof
* verifyProof
* proofToHash
* hashInput

An example usecase is demonstrated below:

    // Create an input of bytes to hash
    auto msg = std::vector<uint8_t>();
    // fill msg...

    // Generate a VRF key pair
    auto vrf_skey = VRFSecretKey::generate();
    auto vrf_pkey = vrf_skey.publicKey();

    // Generate the VRF proof
    auto proof = vrf_skey.constructProof(msg);
    
    // Generate the VRF hash of the input
    auto hash = vrf_skey.hashInput(msg);
    // or
    auto hash = vrf_skey.proofToHash(proof);

    // Verify the proof given the input and public key
    auto result vrf_pkey.verifyProof(msg, proof);
    // result == true if proof is valid.

## Building from source
While the primary intent of the Viper25519 library is to provide source files 
that may be included in modern C++ projects, the code may also be complied as a 
stand-alone library and linked separately to your project.

The following demonstrates how to build the Viper25519 library from source 
using CMake, including running unit tests and installation.

    git clone https://gitlab.com/viper-staking/viper25519.git
    cd viper25519
    mkdir build && cd build \
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make -j 8
    make test
    make install

A Docker build option is also provided for a complete example that includes 
dependency installation.

    git clone https://gitlab.com/viper-staking/viper25519.git
    cd viper25519
    docker build -t com.viperscience.viper25519:latest .

## Dependencies
The Viper25519 library links with Botan (2 or 3) for SHA-512 hasing capability. Botan 
uses functionality provided by OpenSSL. VRF capability is provided by the Cardano
fork of libsodium.

* [Botan](https://botan.randombit.net/)
* [OpenSSL](https://www.openssl.org/)
* [libsodium](https://github.com/IntersectMBO/libsodium)

The provided Docker file demonstrates how to install the required 
dependencies prior to building the Viper25519 library in a Debian 
environment. Additionally, a Cmake find scripts for Botan and libsodium are provided in the 
[cmake folder](https://gitlab.com/viper-staking/viper25519/-/blob/main/cmake/FindBotan.cmake).

## Platform Support

This library currently supports 64-bit Unix platforms only.

## Related Projects

The Viper25519 library was originally started as part of the 
[libcardano](https://gitlab.com/viper-staking/libcardano) project.
